#include <jni.h>
#include <android/log.h>
#include <string_view>
#include <shadowhook.h>
#include <lsplant.hpp>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void* proxy_hook(void* target, void* hooker) {
    void* orig = nullptr;
    void* stub = shadowhook_hook_func_addr(target, hooker, &orig);
    (void)stub;
    if (orig == nullptr) {
        LOGE("shadowhook_hook_func_addr failed: %s",
             shadowhook_to_errmsg(shadowhook_get_errno()));
    }
    return orig;
}

static bool proxy_unhook(void* func) {
    (void)func;
    return true;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    int sh_ret = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    if (sh_ret != 0) {
        LOGE("shadowhook_init failed errno=%d", shadowhook_get_init_errno());
        return JNI_ERR;
    }
    LOGI("shadowhook_init ok");

    void* libart = shadowhook_dlopen("libart.so");
    lsplant::InitInfo info{
        .inline_hooker = proxy_hook,
        .inline_unhooker = proxy_unhook,
        .art_symbol_resolver = [libart](std::string_view symbol) -> void* {
            return shadowhook_dlsym_symtab(libart, std::string(symbol).c_str());
        },
    };
    bool lsp_ok = lsplant::Init(env, info);
    if (!lsp_ok) {
        LOGE("lsplant::Init failed");
        return JNI_ERR;
    }
    LOGI("lsplant::Init ok");

    LOGI("JNI_OnLoad ok");
    return JNI_VERSION_1_6;
}
