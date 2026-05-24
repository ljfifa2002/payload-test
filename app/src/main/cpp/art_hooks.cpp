#include "art_hooks.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <shadowhook.h>
#include <string>
#include <cstdint>
#include <cstdio>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// ArtMethod* / entry_point helpers
// ---------------------------------------------------------------------------

// On arm64 Android 5-15, ArtMethod begins with:
//   [0]  declaring_class_ (uint32_t, compressed ref)
//   [4]  access_flags_    (uint32_t)
//   [8]  dex_code_item_offset_ / dex_method_index / ...
//   [32] entry_point_from_quick_compiled_code_  (uintptr_t)  ← standard
//
// Oplus may have shifted this. We calibrate by finding where a known JNI
// trampoline lives inside a reference method's ArtMethod bytes.

static int g_ep_offset = 32;   // default; updated by calibrate_ep_offset()

// Calibrate the entry_point offset using System.currentTimeMillis(), a
// well-known native method whose entry should be art_quick_generic_jni_trampoline.
static void calibrate_ep_offset(JNIEnv* env) {
    void* libart = dlopen("libart.so", RTLD_NOLOAD | RTLD_NOW);
    if (!libart) return;

    // Try both the exported symbol and the symtab name.
    void* trampoline = dlsym(libart, "art_quick_generic_jni_trampoline");
    if (!trampoline) {
        // shadowhook can search the full symbol table
        trampoline = shadowhook_dlsym_symtab(libart, "art_quick_generic_jni_trampoline");
    }
    dlclose(libart);

    if (!trampoline) {
        LOGI("art_hooks: calibration skipped (trampoline not found), using offset=%d", g_ep_offset);
        return;
    }
    LOGI("art_hooks: jni_trampoline @ %p", trampoline);

    // Get ArtMethod* for System.currentTimeMillis — a JNI native method.
    jclass sys = env->FindClass("java/lang/System");
    if (!sys) { env->ExceptionClear(); return; }
    jmethodID mid = env->GetStaticMethodID(sys, "currentTimeMillis", "()J");
    if (!mid) { env->ExceptionClear(); return; }

    // jmethodID IS ArtMethod* on ART.
    auto* am = reinterpret_cast<uintptr_t*>(mid);

    // Scan the first 128 bytes in pointer-sized steps for the trampoline address.
    for (int off = 0; off <= 120; off += 4) {
        uintptr_t candidate = *reinterpret_cast<uintptr_t*>(
            reinterpret_cast<uint8_t*>(am) + off);
        if (candidate == reinterpret_cast<uintptr_t>(trampoline)) {
            g_ep_offset = off;
            LOGI("art_hooks: calibrated ep_offset=%d", g_ep_offset);
            return;
        }
    }
    LOGI("art_hooks: calibration scan found nothing, keeping offset=%d", g_ep_offset);
}

// Read the compiled-code entry point from an ArtMethod.
static void* get_entry_point(jmethodID mid) {
    auto* am = reinterpret_cast<uint8_t*>(mid);
    return *reinterpret_cast<void**>(am + g_ep_offset);
}

// ---------------------------------------------------------------------------
// Per-method hook stubs
// Oplus watchdog restores the ArtMethod field but never touches the code at
// the address the field points to. Patching that code is invisible to the dog.
//
// ART arm64 quick calling convention for instance methods:
//   x0  = compressed 'this' reference
//   x1..= further arguments
//   x19 = ART Thread*   (callee-saved, ShadowHook preserves it)
//   return in x0
//
// ShadowHook UNIQUE mode patches the prologue and provides a trampoline to
// the original code.  The hook function is called with the same register
// layout as a normal C function, which happens to match ART quick convention
// for the argument registers — so cast is safe for logging purposes.
// ---------------------------------------------------------------------------

static JavaVM* g_vm = nullptr;

// Safely attach to JNI for the current thread (if needed) and return env.
// Returns JNI_OK or an error code; sets *env_out.
static int get_env(JNIEnv** env_out) {
    if (!g_vm) return JNI_ERR;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(env_out), JNI_VERSION_1_6);
    if (r == JNI_EDETACHED) {
        r = g_vm->AttachCurrentThread(env_out, nullptr);
    }
    return r;
}

// Emit a log line in the standard hook output format.
static void emit(const char* method, const char* data) {
    LOGI("{\"type\":\"behavior\",\"method\":\"%s\",\"data\":\"%s\"}", method, data);
}

// Try to read a jstring value returned from the trampoline (x0 after call).
// ART returns object references in x0 as uncompressed pointer on arm64.
// We wrap it in a local JNI reference so GC is aware.
static std::string jstring_val(JNIEnv* env, void* raw_ref) {
    if (!raw_ref || !env) return "(null)";
    // On arm64 ART, the raw pointer IS the object address — NewLocalRef is safe.
    auto jstr = reinterpret_cast<jstring>(raw_ref);
    jstring local = static_cast<jstring>(env->NewLocalRef(jstr));
    if (!local) return "(null)";
    const char* cstr = env->GetStringUTFChars(local, nullptr);
    std::string result = cstr ? cstr : "(null)";
    if (cstr) env->ReleaseStringUTFChars(local, cstr);
    env->DeleteLocalRef(local);
    return result;
}

// ---------------------------------------------------------------------------
// HOOK_METHOD macro:
//   Declares orig_<tag> + stub_<tag> statics and a hook function.
//   The hook logs the call, invokes the original, logs the return value.
//   RESULT_FN extracts a display string from the raw return value; for void
//   methods pass a lambda returning empty string.
// ---------------------------------------------------------------------------

#define HOOK_METHOD(tag, method_label, RetT, ...)                              \
    using Fn_##tag = RetT (*)(__VA_ARGS__);                                    \
    static void*     stub_##tag = nullptr;                                     \
    static Fn_##tag  orig_##tag = nullptr;                                     \
    static RetT hook_##tag(__VA_ARGS__);                                       \
    static RetT hook_##tag(__VA_ARGS__)

// ---------------------------------------------------------------------------
// TelephonyManager.getDeviceId() -> String   [instance, no-arg]
// ---------------------------------------------------------------------------
HOOK_METHOD(getDeviceId, "TelephonyManager.getDeviceId", void*, void* thiz) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_getDeviceId, thiz);
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getDeviceId", jstring_val(env, ret).c_str());
    return ret;
}

// ---------------------------------------------------------------------------
// TelephonyManager.getSubscriberId() -> String
// ---------------------------------------------------------------------------
HOOK_METHOD(getSubscriberId, "TelephonyManager.getSubscriberId", void*, void* thiz) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_getSubscriberId, thiz);
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getSubscriberId", jstring_val(env, ret).c_str());
    return ret;
}

// ---------------------------------------------------------------------------
// TelephonyManager.getSimSerialNumber() -> String
// ---------------------------------------------------------------------------
HOOK_METHOD(getSimSerialNumber, "TelephonyManager.getSimSerialNumber", void*, void* thiz) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_getSimSerialNumber, thiz);
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getSimSerialNumber", jstring_val(env, ret).c_str());
    return ret;
}

// ---------------------------------------------------------------------------
// TelephonyManager.getLine1Number() -> String
// ---------------------------------------------------------------------------
HOOK_METHOD(getLine1Number, "TelephonyManager.getLine1Number", void*, void* thiz) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_getLine1Number, thiz);
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getLine1Number", jstring_val(env, ret).c_str());
    return ret;
}

// ---------------------------------------------------------------------------
// Settings.Secure.getString(ContentResolver, String) -> String  [static]
// ARM64 ART: x0=cr, x1=key  (no 'this' for static)
// ---------------------------------------------------------------------------
HOOK_METHOD(settingsGetString, "Settings.Secure.getString", void*, void* cr, void* key) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_settingsGetString, cr, key);
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK) {
        std::string key_str = jstring_val(env, key);
        std::string val_str = jstring_val(env, ret);
        std::string data = key_str + "=" + val_str;
        emit("Settings.Secure.getString", data.c_str());
    }
    return ret;
}

// ---------------------------------------------------------------------------
// WifiInfo.getMacAddress() -> String
// ---------------------------------------------------------------------------
HOOK_METHOD(getMacAddress, "WifiInfo.getMacAddress", void*, void* thiz) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_getMacAddress, thiz);
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("WifiInfo.getMacAddress", jstring_val(env, ret).c_str());
    return ret;
}

// ---------------------------------------------------------------------------
// NetworkInterface.getHardwareAddress() -> byte[]
// Returns a raw compressed array reference; just log that it was called.
// ---------------------------------------------------------------------------
HOOK_METHOD(getHardwareAddress, "NetworkInterface.getHardwareAddress", void*, void* thiz) {
    SHADOWHOOK_STACK_SCOPE();
    void* ret = SHADOWHOOK_CALL_PREV(hook_getHardwareAddress, thiz);
    emit("NetworkInterface.getHardwareAddress", "called");
    return ret;
}

// ---------------------------------------------------------------------------
// Hook installer helper
// ---------------------------------------------------------------------------
struct HookTarget {
    const char* class_name;   // JNI form
    const char* method_name;
    const char* sig;
    bool        is_static;
    void*       hook_fn;
    void**      orig_out;
    void**      stub_out;
};

static void install_one(JNIEnv* env, const HookTarget& t) {
    jclass cls = env->FindClass(t.class_name);
    if (!cls) {
        env->ExceptionClear();
        LOGE("art_hooks: FindClass failed: %s", t.class_name);
        return;
    }
    jmethodID mid = t.is_static
        ? env->GetStaticMethodID(cls, t.method_name, t.sig)
        : env->GetMethodID(cls,        t.method_name, t.sig);
    if (!mid) {
        env->ExceptionClear();
        LOGE("art_hooks: GetMethodID failed: %s.%s %s", t.class_name, t.method_name, t.sig);
        return;
    }

    void* ep = get_entry_point(mid);
    if (!ep) {
        LOGE("art_hooks: entry_point is null for %s.%s", t.class_name, t.method_name);
        return;
    }
    LOGI("art_hooks: entry_point %s.%s @ %p (ep_offset=%d)",
         t.class_name, t.method_name, ep, g_ep_offset);

    void* orig = nullptr;
    void* stub = shadowhook_hook_func_addr(ep, t.hook_fn, &orig);
    if (!stub) {
        LOGE("art_hooks: shadowhook_hook_func_addr failed for %s.%s: %s",
             t.class_name, t.method_name,
             shadowhook_to_errmsg(shadowhook_get_errno()));
        return;
    }
    *t.orig_out = orig;
    *t.stub_out = stub;
    LOGI("art_hooks: hooked %s.%s -> orig=%p", t.class_name, t.method_name, orig);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
void install_art_inline_hooks(JNIEnv* env, JavaVM* vm) {
    g_vm = vm;
    calibrate_ep_offset(env);

    const HookTarget targets[] = {
        {
            "android/telephony/TelephonyManager", "getDeviceId", "()Ljava/lang/String;",
            false, (void*)hook_getDeviceId,
            (void**)&orig_getDeviceId, &stub_getDeviceId
        },
        {
            "android/telephony/TelephonyManager", "getSubscriberId", "()Ljava/lang/String;",
            false, (void*)hook_getSubscriberId,
            (void**)&orig_getSubscriberId, &stub_getSubscriberId
        },
        {
            "android/telephony/TelephonyManager", "getSimSerialNumber", "()Ljava/lang/String;",
            false, (void*)hook_getSimSerialNumber,
            (void**)&orig_getSimSerialNumber, &stub_getSimSerialNumber
        },
        {
            "android/telephony/TelephonyManager", "getLine1Number", "()Ljava/lang/String;",
            false, (void*)hook_getLine1Number,
            (void**)&orig_getLine1Number, &stub_getLine1Number
        },
        {
            "android/provider/Settings$Secure", "getString",
            "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
            true,  (void*)hook_settingsGetString,
            (void**)&orig_settingsGetString, &stub_settingsGetString
        },
        {
            "android/net/wifi/WifiInfo", "getMacAddress", "()Ljava/lang/String;",
            false, (void*)hook_getMacAddress,
            (void**)&orig_getMacAddress, &stub_getMacAddress
        },
        {
            "java/net/NetworkInterface", "getHardwareAddress", "()[B",
            false, (void*)hook_getHardwareAddress,
            (void**)&orig_getHardwareAddress, &stub_getHardwareAddress
        },
    };

    for (const auto& t : targets) {
        install_one(env, t);
    }
    LOGI("art_hooks: inline hooks installed (ep_offset=%d)", g_ep_offset);
}
