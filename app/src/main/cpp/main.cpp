#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <functional>
#include <string>
#include <string_view>
#include <shadowhook.h>
#include <lsplant.hpp>
#include "hooks.h"

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

__attribute__((constructor))
static void payload_init() {
    int sh_ret = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    if (sh_ret != 0) {
        LOGE("shadowhook_init failed ret=%d", sh_ret);
        return;
    }
    LOGI("shadowhook_init ok");

    // JNI_GetCreatedJavaVMs 不在默认链接库，用 dlsym 动态查找
    using GetCreatedJavaVMs_t = jint (*)(JavaVM**, jsize, jsize*);
    auto get_vms = reinterpret_cast<GetCreatedJavaVMs_t>(
        dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    if (get_vms == nullptr) {
        LOGE("dlsym JNI_GetCreatedJavaVMs failed");
        return;
    }

    JavaVM* vm = nullptr;
    jsize count = 0;
    if (get_vms(&vm, 1, &count) != JNI_OK || count == 0 || vm == nullptr) {
        LOGE("JNI_GetCreatedJavaVMs failed count=%d", (int)count);
        return;
    }

    JNIEnv* env = nullptr;
    jint env_ret = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (env_ret == JNI_EDETACHED) {
        env_ret = vm->AttachCurrentThread(&env, nullptr);
    }
    if (env_ret != JNI_OK || env == nullptr) {
        LOGE("GetEnv failed ret=%d", (int)env_ret);
        return;
    }

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
        return;
    }
    LOGI("lsplant::Init ok");

    install_device_id_hooks(env);
    LOGI("payload init ok");
}
