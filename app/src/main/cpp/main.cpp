#include <jni.h>
#include <android/log.h>
#include <functional>
#include <string>
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

// 由 dlopen 触发，无需 JVM。初始化 ShadowHook，为后续 LSPlant 做准备。
__attribute__((constructor))
static void payload_init() {
    int sh_ret = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    if (sh_ret != 0) {
        LOGE("shadowhook_init failed ret=%d", sh_ret);
        return;
    }
    LOGI("shadowhook_init ok");
    LOGI("payload constructor ok");
}

// ART 在 dlopen 后会自动调用 JNI_OnLoad（若库被加载进 Java 类加载器管理的进程）。
// 若未触发，后续阶段可改用 constructor 内通过 /proc/self/maps 找 JavaVM。
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
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
        return JNI_ERR;
    }
    LOGI("lsplant::Init ok");

    LOGI("JNI_OnLoad ok");
    return JNI_VERSION_1_6;
}
