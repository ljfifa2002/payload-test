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

// Bumped on every pushed commit so logcat immediately reveals which binary is deployed.
// Format: YYYY.MM.DD-<short-hash>
#define PAYLOAD_VERSION "2026.06.02-mini-launch-fix"

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
    // XLoader verifies libart.so code-byte integrity, so we must not patch
    // function prologues that live inside libart.so.
    //
    // However, for JIT-compiled WeChat methods (e.g. jsapi.m.q0, AppBrandRuntime.i)
    // the entry_point is in the JIT code cache, not in libart.so. XLoader does not
    // protect the JIT cache. Callers of such methods use JIT direct calls that
    // bypass ArtMethod entry_point entirely — so a pure entry_point replacement
    // (the LSPlant default when inline_hooker returns target) is invisible to them.
    //
    // Strategy: use dladdr() to check whether target is inside libart.so.
    //   • If yes → no-op (return target): libart.so is XLoader-protected; cross-image
    //     calls from WeChat JIT always go through ArtMethod dispatch anyway, so the
    //     LSPlant entry_point replacement is sufficient.
    //   • If no  → use shadowhook to patch the code bytes: safe for JIT cache and
    //     other .so files; ensures all callers (including JIT direct calls) are
    //     intercepted.
    Dl_info info;
    int dl_ret = dladdr(target, &info);
    const char* fname = (dl_ret && info.dli_fname) ? info.dli_fname : "(anon/JIT)";
    if (dl_ret && info.dli_fname && strstr(info.dli_fname, "libart.so") != nullptr) {
        LOGI("proxy_hook: target=%p libart.so → no-op", target);
        (void)hooker;
        return target;
    }
    // JIT code cache or another .so — safe to patch with shadowhook.
    void* orig = nullptr;
    void* stub = shadowhook_hook_func_addr(target, hooker, &orig);
    LOGI("proxy_hook: target=%p fname=%s → shadowhook stub=%p orig=%p errno=%d",
         target, fname, stub, orig, shadowhook_get_errno());
    return orig ? orig : target;
}

static bool proxy_unhook(void* func) {
    // For libart.so targets proxy_hook was a no-op, nothing to unhook.
    // For JIT/other targets shadowhook manages its own stubs; we don't unhook
    // individually here (LSPlant calls this only during UnHook which we don't use).
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
    LOGI("payload_init: activating version=" PAYLOAD_VERSION);

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

    // ── Phase 10: delayed WeChat mini-program hooks ───────────────────────────
    // WeChat's mini-program framework classes (AppBrandRuntime, jsapi.m, xf1.q)
    // are loaded lazily — only when the user actually opens a mini-program.
    //
    // The appbrand check CANNOT be done here in the constructor: dlopen fires
    // inside selinux_android_setcontext, before android_os_Process_setArgV0
    // runs.  At this moment /proc/self/cmdline still shows "zygote64" regardless
    // of the final process name, and NCORE_PROCESS_NAME is only set by ncore ≥
    // commit 57a1c96.  Deferring the check to the thread body (post-sleep) is
    // the only reliable approach across all ncore versions.
    {
        JavaVM* vm_ref = vm;
        std::thread([vm_ref]() {
            // Sleep first so android_os_Process_setArgV0 completes and
            // /proc/self/cmdline reflects the actual process name.
            sleep(2);

            // Exit early if not running in an appbrand container.
            bool in_appbrand = false;
            {
                const char* env_name = getenv("NCORE_PROCESS_NAME");
                if (env_name != nullptr && env_name[0] != '\0') {
                    in_appbrand = strstr(env_name, ":appbrand") != nullptr;
                } else {
                    char cmdline[256] = {};
                    int fd = open("/proc/self/cmdline", O_RDONLY);
                    if (fd >= 0) {
                        read(fd, cmdline, sizeof(cmdline) - 1);
                        close(fd);
                        in_appbrand = strstr(cmdline, ":appbrand") != nullptr;
                    }
                }
            }
            if (!in_appbrand) return;

            // Use cached class and method ID from install_device_id_hooks() — those
            // were resolved on the app thread which has the InMemoryDexClassLoader
            // context. FindClass / GetStaticMethodID on a bare AttachCurrentThread
            // thread uses the system ClassLoader and cannot find HookerBridge.
            jclass    bridgeClass  = g_hooker_class_global;
            jmethodID installMini  = g_install_mini_method;
            if (!bridgeClass || !installMini) {
                __android_log_print(ANDROID_LOG_ERROR, "payload",
                    "mini hooks: cached class/method null, skipping");
                return;
            }

            JNIEnv* tenv = nullptr;
            if (vm_ref->AttachCurrentThread(&tenv, nullptr) != JNI_OK) return;

            // scheduleInstallMiniHooks() posts the actual hook work to the appbrand
            // main looper. Execution there uses WeChat's full thread context ClassLoader
            // (including Tinker patch DEXes), which is required to find the runtime
            // versions of jsapi.m, AppBrandRuntime, and xf1.q.
            // The retry loop is no longer needed: scheduling is reliable and the main
            // looper runs after WeChat's class loading is complete.
            tenv->CallStaticVoidMethod(bridgeClass, installMini);
            if (tenv->ExceptionCheck()) tenv->ExceptionClear();
            __android_log_print(ANDROID_LOG_INFO, "payload",
                "mini hooks: scheduleInstallMiniHooks posted to main looper");

            vm_ref->DetachCurrentThread();
        }).detach();
    }
}
