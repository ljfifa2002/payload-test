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

// should_activate decides whether payload hooks should be installed in the
// current process.
//
// For most APK tasks the answer is always true — we were injected into the
// target app and should run normally.
//
// The special case is WeChat (com.tencent.mm): Ninjector's spawn mode injects
// into the main WeChat process AND every child it forks via zygote, so we end
// up inside com.tencent.mm (main), com.tencent.mm:push, and eventually
// com.tencent.mm:appbrand0/1/... when the user opens a mini-program.  We only
// want to activate inside the appbrand containers; the main and push processes
// should be left untouched.
static bool should_activate() {
    char cmdline[256] = {};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return true;  // can't read — activate by default (safe fallback)
    read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);

    // If we're in any WeChat process, only activate in appbrand containers.
    if (strstr(cmdline, "com.tencent.mm") != nullptr) {
        return strstr(cmdline, ":appbrand") != nullptr;
    }
    // Every other APK: activate normally.
    return true;
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
    if (!should_activate()) {
        // WeChat non-appbrand process (main, push, tools, etc.) — do nothing.
        // Ninjector injects into all com.tencent.mm:* processes via the zygote
        // hook; we activate only in appbrand containers where the mini-program
        // JS runtime runs.
        return;
    }
    LOGI("payload_init: activating");

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
