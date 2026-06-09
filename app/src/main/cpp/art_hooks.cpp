#include "art_hooks.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <shadowhook.h>
#include <vector>
#include <cstdint>
#include <cstdio>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// This file used to install inline ART hooks to bypass an assumed "Oplus watchdog".
// That path was removed once a clean single LSPlant hook was shown to work on
// ColorOS (the "watchdog" was a double-hook-era misdiagnosis).  Only the ArtMethod
// entry_point offset calibration remains — hooks.cpp (native_hook_method) uses
// (g_ep_offset - 28) to set kAccCompileDontBother on WeChat mini-program methods so
// the JIT does not recompile them and overwrite LSPlant's dispatch stub.
#if defined(__aarch64__)

// Standard arm64 ArtMethod layout puts entry_point_from_quick_compiled_code_ at
// offset 32.  Oplus inserts extra fields, shifting it; calibrate at startup.
int g_ep_offset = 32;

// Parse /proc/self/maps and collect [start, end) ranges that are executable.
struct ExecRange { uintptr_t start, end; };
static std::vector<ExecRange> load_exec_ranges() {
    std::vector<ExecRange> ranges;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return ranges;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uintptr_t s, e;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) == 3 && perms[2] == 'x') {
            ranges.push_back({s, e});
        }
    }
    fclose(f);
    return ranges;
}

static bool is_exec_ptr(uintptr_t addr, const std::vector<ExecRange>& ranges) {
    if (addr < 0x1000 || (addr >> 48) != 0) return false;  // obvious invalid
    for (const auto& r : ranges) {
        if (addr >= r.start && addr < r.end) return true;
    }
    return false;
}

// Calibrate entry_point offset.
// Strategy A: use shadowhook_dlopen to get libart handle (avoids namespace issues),
//             then find art_quick_generic_jni_trampoline and scan System.currentTimeMillis.
// Strategy B: if A fails, use a compiled Java method (String.length) and
//             scan for the first exec-mapped pointer in its ArtMethod.
static void calibrate_ep_offset(JNIEnv* env) {
    auto exec_ranges = load_exec_ranges();
    LOGI("art_hooks: loaded %zu exec ranges from maps", exec_ranges.size());

    // --- Strategy A: trampoline scan via shadowhook_dlopen ---
    void* libart = shadowhook_dlopen("libart.so");
    if (libart) {
        void* trampoline = shadowhook_dlsym_symtab(libart, "art_quick_generic_jni_trampoline");
        if (!trampoline) trampoline = dlsym(libart, "art_quick_generic_jni_trampoline");
        if (trampoline) {
            LOGI("art_hooks: jni_trampoline @ %p", trampoline);
            jclass sys = env->FindClass("java/lang/System");
            if (sys) {
                jmethodID mid = env->GetStaticMethodID(sys, "currentTimeMillis", "()J");
                if (mid) {
                    auto* am = reinterpret_cast<uint8_t*>(mid);
                    for (int off = 24; off <= 128; off += 8) {
                        uintptr_t v = *reinterpret_cast<uintptr_t*>(am + off);
                        if (v == reinterpret_cast<uintptr_t>(trampoline)) {
                            g_ep_offset = off;
                            LOGI("art_hooks: calibrated (A) ep_offset=%d", g_ep_offset);
                            return;
                        }
                    }
                    LOGI("art_hooks: strategy A scan exhausted");
                } else { env->ExceptionClear(); }
            } else { env->ExceptionClear(); }
        } else {
            LOGI("art_hooks: trampoline symbol not found in libart");
        }
    } else {
        LOGE("art_hooks: shadowhook_dlopen(libart.so) failed");
    }

    // --- Strategy B: exec-range scan on a compiled Java method ---
    // String.length() is a simple Java method always AOT-compiled into boot image.
    jclass str_cls = env->FindClass("java/lang/String");
    if (!str_cls) { env->ExceptionClear(); goto done; }
    {
        jmethodID mid = env->GetMethodID(str_cls, "length", "()I");
        if (!mid) { env->ExceptionClear(); goto done; }
        auto* am = reinterpret_cast<uint8_t*>(mid);
        // Dump ArtMethod bytes for diagnosis
        LOGI("art_hooks: String.length ArtMethod bytes:");
        for (int off = 0; off <= 72; off += 8) {
            uintptr_t v = *reinterpret_cast<uintptr_t*>(am + off);
            LOGI("art_hooks:   [%3d] = 0x%016lx  exec=%d", off, v, is_exec_ptr(v, exec_ranges));
        }
        // Find first exec pointer starting at offset 24
        for (int off = 24; off <= 128; off += 8) {
            uintptr_t v = *reinterpret_cast<uintptr_t*>(am + off);
            if (is_exec_ptr(v, exec_ranges)) {
                g_ep_offset = off;
                LOGI("art_hooks: calibrated (B) ep_offset=%d via String.length", g_ep_offset);
                return;
            }
        }
        LOGI("art_hooks: strategy B found no exec pointer");
    }
done:
    LOGI("art_hooks: calibration failed, keeping default offset=%d", g_ep_offset);
}

void calibrate_art_offsets(JNIEnv* env) {
    calibrate_ep_offset(env);
    LOGI("art_hooks: ep_offset=%d", g_ep_offset);
}

#else // !defined(__aarch64__)

// armeabi-v7a: standard ARM32 ArtMethod layout has
// entry_point_from_quick_compiled_code_ at offset 32 (same as ARM64) — no
// calibration needed.  g_ep_offset must still be defined (referenced by hooks.cpp).
int g_ep_offset = 32;

void calibrate_art_offsets(JNIEnv* /*env*/) {
    __android_log_print(ANDROID_LOG_INFO, "payload",
        "art_hooks: armeabi-v7a build, ep_offset=32 (no calibration)");
}

#endif // defined(__aarch64__)
