#include "ssl_hooks.h"
#include <shadowhook.h>
#include <android/log.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <time.h>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Opaque BoringSSL SSL type — only the pointer is needed.
struct ssl_st;
using SSL = ssl_st;

using ssl_write_t       = int (*)(SSL*, const void*, int);
using ssl_read_t        = int (*)(SSL*, void*, int);
using ssl_get_servname_t = const char* (*)(const SSL*, int);

static ssl_write_t        orig_ssl_write    = nullptr;
static ssl_read_t         orig_ssl_read     = nullptr;
static ssl_get_servname_t fn_get_servname   = nullptr;

static const int PREVIEW_MAX = 128;

static std::string get_host(SSL* ssl) {
    if (fn_get_servname) {
        const char* h = fn_get_servname(ssl, 0); // TLSEXT_NAMETYPE_host_name = 0
        if (h && h[0]) return h;
    }
    return "?";
}

static void log_ssl(const char* dir, SSL* ssl, const void* buf, int len) {
    std::string host = get_host(ssl);
    const auto* p = static_cast<const unsigned char*>(buf);

    // Detect printable ASCII (HTTP/1.1 text): check first 16 bytes.
    int check = len < 16 ? len : 16;
    bool is_text = true;
    for (int i = 0; i < check; i++) {
        if (p[i] < 0x09 || (p[i] > 0x0d && p[i] < 0x20) || p[i] > 0x7e) {
            is_text = false;
            break;
        }
    }

    int preview_len = len < PREVIEW_MAX ? len : PREVIEW_MAX;
    // Worst case hex: each byte → 2 chars, plus null terminator and margin.
    char preview[PREVIEW_MAX * 2 + 4];
    int out = 0;

    if (is_text) {
        for (int i = 0; i < preview_len && out < (int)sizeof(preview) - 4; i++) {
            char c = (char)p[i];
            if (c == '\r' || c == '\n' || c == '\t') {
                preview[out++] = ' ';
            } else if (c == '"') {
                preview[out++] = '\\'; preview[out++] = '"';
            } else if (c == '\\') {
                preview[out++] = '\\'; preview[out++] = '\\';
            } else {
                preview[out++] = c;
            }
        }
        preview[out] = '\0';
    } else {
        for (int i = 0; i < preview_len && out < (int)sizeof(preview) - 3; i++) {
            out += snprintf(preview + out, sizeof(preview) - out, "%02x", p[i]);
        }
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000LL;

    LOGI("{\"type\":\"ssl\",\"method\":\"%s\",\"host\":\"%s\",\"len\":%d,\"data\":\"%s\",\"timestamp\":%lld}",
         dir, host.c_str(), len, preview, ms);
}

static int hook_ssl_write(SSL* ssl, const void* buf, int num) {
    log_ssl("SSL_write", ssl, buf, num);
    return orig_ssl_write(ssl, buf, num);
}

static int hook_ssl_read(SSL* ssl, void* buf, int num) {
    int ret = orig_ssl_read(ssl, buf, num);
    if (ret > 0) log_ssl("SSL_read", ssl, buf, ret);
    return ret;
}

void install_ssl_hooks() {
    // Resolve SSL_get_servername for SNI hostname extraction.
    void* libssl = shadowhook_dlopen("libssl.so");
    if (libssl) {
        fn_get_servname = reinterpret_cast<ssl_get_servname_t>(
            shadowhook_dlsym_symtab(libssl, "SSL_get_servername"));
        if (!fn_get_servname)
            fn_get_servname = reinterpret_cast<ssl_get_servname_t>(
                dlsym(libssl, "SSL_get_servername"));
        if (fn_get_servname) LOGI("ssl_hooks: SSL_get_servername resolved");
        else                 LOGI("ssl_hooks: SSL_get_servername not found, host='?'");
    } else {
        LOGE("ssl_hooks: shadowhook_dlopen(libssl.so) failed");
    }

    void* stub_w = shadowhook_hook_sym_name(
        "libssl.so", "SSL_write",
        (void*)hook_ssl_write, (void**)&orig_ssl_write);
    if (stub_w) LOGI("ssl_hooks: SSL_write hooked");
    else        LOGE("ssl_hooks: SSL_write hook failed: %s",
                     shadowhook_to_errmsg(shadowhook_get_errno()));

    void* stub_r = shadowhook_hook_sym_name(
        "libssl.so", "SSL_read",
        (void*)hook_ssl_read, (void**)&orig_ssl_read);
    if (stub_r) LOGI("ssl_hooks: SSL_read hooked");
    else        LOGE("ssl_hooks: SSL_read hook failed: %s",
                     shadowhook_to_errmsg(shadowhook_get_errno()));
}
