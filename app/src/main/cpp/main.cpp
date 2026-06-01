#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
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
//
// Detection strategy (two layers):
//
// Layer 1 — env var NCORE_PROCESS_NAME (reliable, early):
//   ncore sets this env variable to the exact sub-process name just before
//   calling dlopen(payload.so).  This is set from selinux_android_setcontext,
//   which fires before android_os_Process_setArgV0, so /proc/self/cmdline has
//   not been updated yet at constructor time.  The env var is the only reliable
//   source of the final process name at this stage.
//
// Layer 2 — /proc/self/cmdline (fallback, post-specialisation):
//   If the env var is absent (e.g. payload loaded by a different injector),
//   fall back to reading /proc/self/cmdline.  By the time Java class loading
//   happens this is already correct, but in the C++ constructor it may still
//   show "zygote64" — use it only as a best-effort guard.
static bool should_activate() {
    // Layer 1: env var set by ncore before dlopen — most reliable.
    const char* env_name = getenv("NCORE_PROCESS_NAME");
    if (env_name != nullptr && env_name[0] != '\0') {
        if (strstr(env_name, "com.tencent.mm") != nullptr) {
            // Inside a WeChat process: only activate in appbrand containers.
            return strstr(env_name, ":appbrand") != nullptr;
        }
        // Any other package: activate normally.
        return true;
    }

    // Layer 2: /proc/self/cmdline fallback (may still be "zygote64" in C++ ctor).
    char cmdline[256] = {};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return true;
    read(fd, cmdline, sizeof(cmdline) - 1);
    close(fd);

    if (strstr(cmdline, "com.tencent.mm") != nullptr) {
        return strstr(cmdline, ":appbrand") != nullptr;
    }
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

    // ── Phase 10: delayed WeChat mini-program hooks (appbrand only) ────────
    // WeChat's mini-program framework classes (AppBrandRuntime, jsapi.m, xf1.q)
    // are loaded lazily — only when the user actually opens a mini-program, which
    // can be 10-30 s after the appbrand process starts.  A single sleep(2) fires
    // too early and gets ClassNotFoundException for all three targets.
    //
    // Strategy: retry every 2 s, up to 60 s total (30 attempts), stopping as
    // soon as installMiniHooks() returns > 0 (at least one hook installed).
    // This thread is ONLY started in appbrand processes.
    //
    // in_appbrand detection uses the same two-layer strategy as should_activate():
    //   Layer 1: NCORE_PROCESS_NAME env var (set by ncore ≥ 57a1c96 before dlopen)
    //   Layer 2: /proc/self/cmdline fallback (works on any ncore version)
    bool in_appbrand = false;
    {
        const char* env_name = getenv("NCORE_PROCESS_NAME");
        if (env_name != nullptr && env_name[0] != '\0') {
            in_appbrand = strstr(env_name, ":appbrand") != nullptr;
        } else {
            // Fallback: read process name from cmdline.
            // At this point (payload_init constructor) android_os_Process_setArgV0
            // has already run for appbrand children, so cmdline is reliable here.
            char cmdline[256] = {};
            int fd = open("/proc/self/cmdline", O_RDONLY);
            if (fd >= 0) {
                read(fd, cmdline, sizeof(cmdline) - 1);
                close(fd);
                in_appbrand = strstr(cmdline, ":appbrand") != nullptr;
            }
        }
    }
    if (in_appbrand) {
        JavaVM* vm_ref = vm;
        std::thread([vm_ref]() {
            JNIEnv* tenv = nullptr;
            if (vm_ref->AttachCurrentThread(&tenv, nullptr) != JNI_OK) return;

            jclass bridgeClass = tenv->FindClass("com/pecker/payload/HookerBridge");
            if (tenv->ExceptionCheck()) tenv->ExceptionClear();

            jmethodID installMini = nullptr;
            if (bridgeClass) {
                installMini = tenv->GetStaticMethodID(
                    bridgeClass, "installMiniHooks", "()I");
                if (tenv->ExceptionCheck()) tenv->ExceptionClear();
            }

            if (installMini) {
                // Retry every 2 s until hooks install or 60 s elapses.
                for (int attempt = 1; attempt <= 30; attempt++) {
                    sleep(2);
                    jint n = tenv->CallStaticIntMethod(bridgeClass, installMini);
                    if (tenv->ExceptionCheck()) tenv->ExceptionClear();
                    __android_log_print(ANDROID_LOG_INFO, "payload",
                        "mini hooks attempt %d: installed=%d", attempt, (int)n);
                    if (n > 0) break;  // at least one hook registered — done
                }
            }

            if (bridgeClass) tenv->DeleteLocalRef(bridgeClass);
            vm_ref->DetachCurrentThread();
        }).detach();
    }
}
