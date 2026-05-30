#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <functional>
#include <string>
#include <string_view>
#include <shadowhook.h>
#include <lsplant.hpp>
#include "hooks.h"
#include "art_hooks.h"
#include "ssl_hooks.h"

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Returns true only when running inside a WeChat mini-program container process
// (com.tencent.mm:appbrand0, :appbrand1, ...).  All other WeChat processes
// (main, push, etc.) return false and payload_init() exits early without binding
// the @pecker socket or installing any hooks.
static bool is_appbrand_process() {
    char cmdline[256] = {};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;
    read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);
    return strstr(cmdline, ":appbrand") != nullptr;
}

static void* proxy_hook(void* target, void* hooker) {
    // XLoader verifies libart.so code-byte integrity. shadowhook_hook_func_addr
    // would patch libart.so function prologues, triggering the check.
    // Instead, return target itself as the "original" — lsplant::Init sees a
    // non-null return and considers its internal hooks "installed", but no code
    // bytes in libart.so are modified. LSPlant will dispatch solely via
    // ArtMethod entry_point_from_quick_compiled_code_ replacement, which XLoader
    // does not check in this path.
    (void)hooker;
    return target;
}

static bool proxy_unhook(void* func) {
    (void)func;
    return true;
}

__attribute__((constructor))
static void payload_init() {
    if (!is_appbrand_process()) {
        // Non-appbrand WeChat process (main, push, tools, etc.) — do nothing.
        // Ninjector injects into all com.tencent.mm:* processes via the zygote
        // hook; we activate only in appbrand containers where the mini-program
        // JS runtime runs.
        return;
    }
    LOGI("appbrand process detected, activating payload");

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
    install_art_inline_hooks(env, vm);
    init_ssl_hooks_jni(vm, env);
    install_ssl_hooks();
    LOGI("payload init ok");
}
