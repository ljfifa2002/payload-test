#include "ssl_hooks.h"
#include <shadowhook.h>
#include <android/log.h>
#include <dlfcn.h>
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <strings.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <time.h>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

struct ssl_st;
using SSL = ssl_st;

using ssl_write_t        = int (*)(SSL*, const void*, int);
using ssl_read_t         = int (*)(SSL*, void*, int);
using ssl_get_servname_t = const char* (*)(const SSL*, int);
using ssl_get0_alpn_t    = void (*)(const SSL*, const unsigned char**, unsigned int*);

static ssl_write_t        orig_ssl_write  = nullptr;
static ssl_read_t         orig_ssl_read   = nullptr;
static ssl_get_servname_t fn_get_servname = nullptr;
static ssl_get0_alpn_t    fn_get0_alpn    = nullptr;

// JNI globals — set once by init_ssl_hooks_jni, then read-only.
static JavaVM*    g_vm        = nullptr;
static jclass     g_cls       = nullptr; // GlobalRef to HookerBridge class
static jmethodID  g_mid       = nullptr; // HookerBridge.jniLogNetwork

// Per-connection pending request info (SSL* → request state).
struct ReqInfo {
    std::string method;
    std::string url;
    std::string reqBody;
};
static std::unordered_map<SSL*, ReqInfo> g_pending;
static std::mutex g_pending_mu;

static const int BODY_MAX = 2048;

// ── helpers ─────────────────────────────────────────────────────────────────

static JNIEnv* get_env() {
    if (!g_vm) return nullptr;
    JNIEnv* env = nullptr;
    jint ret = g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (ret == JNI_OK) return env;
    if (ret == JNI_EDETACHED) {
        if (g_vm->AttachCurrentThreadAsDaemon(&env, nullptr) == JNI_OK) return env;
    }
    return nullptr;
}

static bool is_http2(SSL* ssl) {
    if (!fn_get0_alpn) return false;
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    fn_get0_alpn(ssl, &proto, &len);
    return proto && len == 2 && proto[0] == 'h' && proto[1] == '2';
}

static std::string get_host(SSL* ssl) {
    if (fn_get_servname) {
        const char* h = fn_get_servname(ssl, 0);
        if (h && h[0]) return h;
    }
    return "";
}

// Returns true if the first 16 bytes look like printable text.
static bool is_text(const void* buf, int len) {
    const auto* p = static_cast<const unsigned char*>(buf);
    int check = len < 16 ? len : 16;
    for (int i = 0; i < check; i++) {
        unsigned char c = p[i];
        if (c == 0x09 || c == 0x0a || c == 0x0d) continue; // tab, LF, CR
        if (c < 0x20 || c > 0x7e) return false;
    }
    return true;
}

// Extract up to BODY_MAX bytes of text body (after \r\n\r\n).
static std::string extract_body(const char* data, int len) {
    const char* sep = static_cast<const char*>(memmem(data, len, "\r\n\r\n", 4));
    if (!sep) return {};
    sep += 4;
    int bodyLen = (int)(data + len - sep);
    if (bodyLen <= 0) return {};
    if (bodyLen > BODY_MAX) bodyLen = BODY_MAX;
    return std::string(sep, bodyLen);
}

// Parse "METHOD /path HTTP/1.x\r\n...Host: host\r\n..."
// Returns true and fills out method/path/host on success.
static bool parse_request(const char* data, int len,
                           std::string& method, std::string& path, std::string& host) {
    // Need at least "GET / HTTP/1.0\r\n"
    if (len < 16) return false;
    // Check it starts with a known HTTP verb
    static const char* verbs[] = {"GET ","POST ","PUT ","DELETE ","PATCH ","HEAD ","OPTIONS ","CONNECT ",nullptr};
    bool found = false;
    for (int i = 0; verbs[i]; i++) {
        size_t vlen = strlen(verbs[i]);
        if (len >= (int)vlen && memcmp(data, verbs[i], vlen) == 0) { found = true; break; }
    }
    if (!found) return false;

    // Parse request line: METHOD SP path SP HTTP/...
    const char* eol = static_cast<const char*>(memmem(data, len, "\r\n", 2));
    if (!eol) return false;
    std::string line(data, eol - data);
    size_t s1 = line.find(' ');
    if (s1 == std::string::npos) return false;
    size_t s2 = line.rfind(' ');
    if (s2 == s1) return false;
    method = line.substr(0, s1);
    path   = line.substr(s1 + 1, s2 - s1 - 1);

    // Scan headers for Host:
    const char* hdr = eol + 2;
    const char* end = data + len;
    while (hdr < end) {
        const char* nl = static_cast<const char*>(memmem(hdr, end - hdr, "\r\n", 2));
        if (!nl) break;
        if (nl == hdr) break; // empty line = end of headers
        std::string hline(hdr, nl - hdr);
        if (hline.size() > 5 && (hline[0]=='H'||hline[0]=='h') &&
            strncasecmp(hline.c_str(), "host:", 5) == 0) {
            size_t vs = 5;
            while (vs < hline.size() && hline[vs] == ' ') vs++;
            host = hline.substr(vs);
        }
        hdr = nl + 2;
    }
    return true;
}

// Parse "HTTP/1.x NNN ..." → status code.
static int parse_status(const char* data, int len) {
    if (len < 12) return 0;
    if (memcmp(data, "HTTP/", 5) != 0) return 0;
    const char* sp = static_cast<const char*>(memchr(data, ' ', len < 20 ? len : 20));
    if (!sp) return 0;
    sp++;
    char buf[4] = {};
    int n = 0;
    while (n < 3 && sp + n < data + len && sp[n] >= '0' && sp[n] <= '9') { buf[n] = sp[n]; n++; }
    if (n != 3) return 0;
    return atoi(buf);
}

static void send_network(const std::string& method, const std::string& url,
                          int status, const std::string& reqBody, const std::string& respBody) {
    if (!g_vm) return;
    JNIEnv* env = get_env();
    if (!env) return;

    // Lazy JNI init: FindClass deferred until first SSL callback so that
    // HookerBridge is guaranteed to be loaded (constructor-time FindClass
    // would leave a pending exception and break System.loadLibrary).
    if (!g_cls || !g_mid) {
        static std::mutex init_mu;
        std::lock_guard<std::mutex> lk(init_mu);
        if (!g_cls) {
            jclass local = env->FindClass("com/pecker/payload/HookerBridge");
            if (!local || env->ExceptionCheck()) {
                env->ExceptionClear();
                return;
            }
            g_cls = reinterpret_cast<jclass>(env->NewGlobalRef(local));
            env->DeleteLocalRef(local);
        }
        if (g_cls && !g_mid) {
            g_mid = env->GetStaticMethodID(g_cls, "jniLogNetwork",
                "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V");
            if (!g_mid) {
                env->ExceptionClear();
                env->DeleteGlobalRef(g_cls);
                g_cls = nullptr;
                return;
            }
            LOGI("ssl_hooks: JNI bridge ready (lazy)");
        }
        if (!g_cls || !g_mid) return;
    }

    auto toJStr = [&](const std::string& s) -> jstring {
        return env->NewStringUTF(s.c_str());
    };

    jstring jmethod   = toJStr(method);
    jstring jurl      = toJStr(url);
    jstring jreqBody  = reqBody.empty()  ? nullptr : toJStr(reqBody);
    jstring jrespBody = respBody.empty() ? nullptr : toJStr(respBody);

    env->CallStaticVoidMethod(g_cls, g_mid, jmethod, jurl, (jint)status, jreqBody, jrespBody);
    if (env->ExceptionCheck()) env->ExceptionClear();

    env->DeleteLocalRef(jmethod);
    env->DeleteLocalRef(jurl);
    if (jreqBody)  env->DeleteLocalRef(jreqBody);
    if (jrespBody) env->DeleteLocalRef(jrespBody);
}

// ── hook implementations ─────────────────────────────────────────────────────

static int hook_ssl_write(SSL* ssl, const void* buf, int num) {
    int ret = orig_ssl_write(ssl, buf, num);
    if (ret > 0 && is_text(buf, ret) && !is_http2(ssl)) {
        const char* data = static_cast<const char*>(buf);
        std::string method, path, host;
        if (parse_request(data, ret, method, path, host)) {
            if (host.empty()) host = get_host(ssl);
            std::string url = host.empty() ? path : ("https://" + host + path);
            std::string body = extract_body(data, ret);
            std::lock_guard<std::mutex> lk(g_pending_mu);
            g_pending[ssl] = { method, url, body };
        }
    }
    return ret;
}

static int hook_ssl_read(SSL* ssl, void* buf, int num) {
    int ret = orig_ssl_read(ssl, buf, num);
    if (ret > 0 && is_text(buf, ret) && !is_http2(ssl)) {
        const char* data = static_cast<const char*>(buf);
        int code = parse_status(data, ret);
        if (code > 0) {
            std::string respBody = extract_body(data, ret);
            std::unique_lock<std::mutex> lk(g_pending_mu);
            auto it = g_pending.find(ssl);
            if (it != g_pending.end()) {
                ReqInfo req = std::move(it->second);
                g_pending.erase(it);
                lk.unlock();
                send_network(req.method, req.url, code, req.reqBody, respBody);
            }
        }
    }
    return ret;
}

// ── background thread: install hooks once libssl.so is loaded ────────────────

static void* ssl_hook_thread(void*) {
    LOGI("ssl_hooks: waiting for libssl.so to load...");

    void* real_orig_w = nullptr;
    void* stub_w = shadowhook_hook_sym_name(
        "libssl.so", "SSL_write", (void*)hook_ssl_write, &real_orig_w);
    if (!stub_w) {
        LOGE("ssl_hooks: SSL_write hook failed: %s",
             shadowhook_to_errmsg(shadowhook_get_errno()));
        return nullptr;
    }
    orig_ssl_write = reinterpret_cast<ssl_write_t>(real_orig_w);
    LOGI("ssl_hooks: SSL_write hooked");

    // libssl.so is now loaded — resolve helper functions and hook SSL_read.
    void* libssl = dlopen("libssl.so", RTLD_NOLOAD | RTLD_NOW);
    if (libssl) {
        fn_get_servname = reinterpret_cast<ssl_get_servname_t>(
            shadowhook_dlsym_symtab(libssl, "SSL_get_servername"));
        if (!fn_get_servname)
            fn_get_servname = reinterpret_cast<ssl_get_servname_t>(
                dlsym(libssl, "SSL_get_servername"));

        fn_get0_alpn = reinterpret_cast<ssl_get0_alpn_t>(
            shadowhook_dlsym_symtab(libssl, "SSL_get0_alpn_selected"));
        if (!fn_get0_alpn)
            fn_get0_alpn = reinterpret_cast<ssl_get0_alpn_t>(
                dlsym(libssl, "SSL_get0_alpn_selected"));

        LOGI("ssl_hooks: servname=%p alpn=%p",
             (void*)fn_get_servname, (void*)fn_get0_alpn);
    }

    void* real_orig_r = nullptr;
    void* stub_r = shadowhook_hook_sym_name(
        "libssl.so", "SSL_read", (void*)hook_ssl_read, &real_orig_r);
    if (stub_r) {
        orig_ssl_read = reinterpret_cast<ssl_read_t>(real_orig_r);
        LOGI("ssl_hooks: SSL_read hooked");
    } else {
        LOGE("ssl_hooks: SSL_read hook failed: %s",
             shadowhook_to_errmsg(shadowhook_get_errno()));
    }

    return nullptr;
}

void install_ssl_hooks() {
    pthread_t tid;
    if (pthread_create(&tid, nullptr, ssl_hook_thread, nullptr) == 0) {
        pthread_detach(tid);
        LOGI("ssl_hooks: deferred hook thread started");
    } else {
        LOGE("ssl_hooks: pthread_create failed");
    }
}

void init_ssl_hooks_jni(JavaVM* vm, JNIEnv* /*env*/) {
    // Only store the JavaVM pointer. FindClass is deferred to send_network()
    // (lazy, on first SSL callback) so that the constructor does not leave a
    // pending Java exception that would break System.loadLibrary().
    g_vm = vm;
    LOGI("ssl_hooks: JavaVM stored, JNI class lookup deferred");
}
