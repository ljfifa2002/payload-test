#include "art_hooks.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <shadowhook.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// ArtMethod* / entry_point helpers
// ---------------------------------------------------------------------------

// Standard arm64 ArtMethod layout (AOSP, offset in bytes):
//   [0]  declaring_class_  (uint32_t)
//   [4]  access_flags_     (uint32_t)
//   [8]  dex_code_item_offset_ (uint32_t)
//   [12] dex_method_index_ (uint32_t)
//   [16] method_index_     (uint16_t)
//   [18] hotness_count_    (uint16_t)
//   [20] imt_index_        (uint16_t) / padding
//   [24] data_             (uintptr_t)  — JNI fn ptr / profiling info
//   [32] entry_point_from_quick_compiled_code_  (uintptr_t)
//
// Oplus inserts extra fields before offset 0, shifting everything down.
// We calibrate by scanning for the first 8-byte-aligned offset whose value
// looks like a valid executable code pointer (verified via /proc/self/maps).

static int g_ep_offset = 32;

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

// Read the compiled-code entry point from an ArtMethod.
static void* get_entry_point(jmethodID mid) {
    auto* am = reinterpret_cast<uint8_t*>(mid);
    return *reinterpret_cast<void**>(am + g_ep_offset);
}

// ---------------------------------------------------------------------------
// Raw patch via /proc/self/mem  (bypasses W^X on OAT pages)
//
// Writes a 16-byte ARM64 absolute jump at `target`:
//   LDR X17, #8   ; 0x58000051
//   BR  X17       ; 0xD61F0220
//   <hook_fn ptr> ; 8 bytes
//
// Allocates a 32-byte RWX trampoline:
//   [0..15]  original 16 bytes of target
//   [16..31] same abs jump → target+16  (so caller can invoke the original)
//
// Returns the trampoline (== "orig" pointer), or nullptr on failure.
// ---------------------------------------------------------------------------

static bool is_pc_relative(uint32_t insn) {
    if ((insn & 0x7C000000) == 0x14000000) return true; // B/BL
    if ((insn & 0x1F000000) == 0x10000000) return true; // ADR/ADRP
    if ((insn & 0x7E000000) == 0x34000000) return true; // CBZ/CBNZ
    if ((insn & 0x7E000000) == 0x36000000) return true; // TBZ/TBNZ
    if ((insn & 0x3B000000) == 0x18000000) return true; // LDR literal
    if ((insn & 0xFF000010) == 0x54000000) return true; // B.cond
    return false;
}

// ARM64 abs-jump trampoline helper: write LDR X17, #8 / BR X17 / <addr> at `buf`.
// buf must have ≥16 bytes.
static void write_abs_jump(uint8_t* buf, uintptr_t dest) {
    *reinterpret_cast<uint32_t*>(buf + 0) = 0x58000051; // LDR X17, [PC+8]
    *reinterpret_cast<uint32_t*>(buf + 4) = 0xD61F0220; // BR  X17
    *reinterpret_cast<uintptr_t*>(buf + 8) = dest;
}

static void* raw_patch(void* target, void* hook_fn) {
    auto* insns = reinterpret_cast<uint32_t*>(target);

    // Dump first 6 instructions for diagnosis (24 bytes = typical ART stub size)
    LOGI("art_hooks: stub[%p]: %08x %08x %08x | %08x %08x | %08x",
         target, insns[0], insns[1], insns[2], insns[3], insns[4], insns[5]);

    bool insn0_is_ldr_lit = (insns[0] & 0x3B000000) == 0x18000000;

    if (!insn0_is_ldr_lit) {
        // Standard path: check first 4 instructions, 16-byte patch.
        for (int i = 0; i < 4; i++) {
            if (is_pc_relative(insns[i])) {
                LOGE("art_hooks: raw_patch: PC-relative insn[%d]=0x%08x, skip", i, insns[i]);
                return nullptr;
            }
        }
        void* tramp = mmap(nullptr, 32, PROT_READ|PROT_WRITE|PROT_EXEC,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (tramp == MAP_FAILED) { LOGE("art_hooks: mmap failed"); return nullptr; }
        memcpy(tramp, target, 16);
        write_abs_jump(reinterpret_cast<uint8_t*>(tramp) + 16,
                       reinterpret_cast<uintptr_t>(target) + 16);
        __builtin___clear_cache((char*)tramp, (char*)tramp + 32);
        uint8_t patch[16];
        write_abs_jump(patch, reinterpret_cast<uintptr_t>(hook_fn));
        int fd = open("/proc/self/mem", O_RDWR);
        if (fd < 0) { munmap(tramp, 32); return nullptr; }
        bool ok = (lseek(fd, (off_t)target, SEEK_SET) >= 0 && write(fd, patch, 16) == 16);
        close(fd);
        if (!ok) { munmap(tramp, 32); return nullptr; }
        __builtin___clear_cache((char*)target, (char*)target + 16);
        LOGI("art_hooks: raw_patch(16) %p -> %p tramp=%p", target, hook_fn, tramp);
        return tramp;
    }

    // LDR-literal stub path:
    // insns[0]   = LDR Xn, [PC + imm19*4]  (loads literal from ep + lit_off)
    // insns[1,2] = other instructions (must not be PC-relative)
    // insns[3,4] = 8-byte literal pool      (at ep + lit_off)
    // insns[5]   = final instruction (often BR X0 or RET)
    //
    // Strategy: patch all 24 bytes of the stub:
    //   ep+0:  LDR X17, [PC+16]            (loads hook_fn from ep+16)
    //   ep+4:  NOP
    //   ep+8:  NOP
    //   ep+12: BR X17                      (jump to hook)
    //   ep+16: <hook_fn address, 8 bytes>
    //
    // Trampoline (48 bytes) reconstructs original stub with pre-stored literal:
    //   [0]:  insns[0]  (LDR X0, [PC+12])  — loads from tramp+12 = pre-stored value)
    //   [4]:  insns[1]
    //   [8]:  insns[2]
    //   [12]: <original 8-byte literal pre-fetched here>
    //   [20]: insns[5]  (BR X0 / RET etc.)
    //   [24]: LDR X17, [PC+8]; BR X17; <target+24>  (safety fallthrough)

    // Decode lit_off from imm19 field of insns[0]
    int32_t imm19 = (int32_t)((insns[0] >> 5) & 0x7FFFF);
    if (imm19 & (1 << 18)) imm19 |= ~(int32_t)0x7FFFF;  // sign-extend
    int lit_off = imm19 * 4;

    // Sanity check: literal must be within the 24-byte stub
    if (lit_off < 4 || lit_off > 20) {
        LOGE("art_hooks: lit_off=%d out of range, skip", lit_off);
        return nullptr;
    }

    uint64_t lit_val = *reinterpret_cast<uint64_t*>(
        reinterpret_cast<uint8_t*>(target) + lit_off);
    LOGI("art_hooks: ldr_lit off=%d val=0x%016lx insn[5]=0x%08x",
         lit_off, lit_val, insns[5]);

    // Check insns[1] and insns[2] (insns[3/4] are the literal, skip)
    for (int i = 1; i <= 2; i++) {
        if (is_pc_relative(insns[i])) {
            LOGE("art_hooks: raw_patch: PC-relative insn[%d]=0x%08x, skip", i, insns[i]);
            return nullptr;
        }
    }

    void* tramp = mmap(nullptr, 48, PROT_READ|PROT_WRITE|PROT_EXEC,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) { LOGE("art_hooks: mmap tramp failed"); return nullptr; }

    auto* t = reinterpret_cast<uint8_t*>(tramp);
    // insns[0]: LDR X0, [PC+12] — loads from tramp+12 where we pre-store the literal
    memcpy(t + 0,  &insns[0], 4);
    memcpy(t + 4,  &insns[1], 4);
    memcpy(t + 8,  &insns[2], 4);
    memcpy(t + 12, &lit_val, 8);    // pre-stored original literal
    memcpy(t + 20, &insns[5], 4);   // final instruction (BR X0 / RET)
    write_abs_jump(t + 24, reinterpret_cast<uintptr_t>(target) + 24); // safety
    __builtin___clear_cache((char*)tramp, (char*)tramp + 48);

    // Write 24-byte patch at target (covers entire 24-byte stub)
    // LDR X17, [PC+16]; NOP; NOP; BR X17; <hook_fn addr>
    uint8_t patch[24];
    *reinterpret_cast<uint32_t*>(patch +  0) = 0x58000091; // LDR X17, [PC+16]
    *reinterpret_cast<uint32_t*>(patch +  4) = 0xD503201F; // NOP
    *reinterpret_cast<uint32_t*>(patch +  8) = 0xD503201F; // NOP
    *reinterpret_cast<uint32_t*>(patch + 12) = 0xD61F0220; // BR  X17
    *reinterpret_cast<uintptr_t*>(patch + 16) = reinterpret_cast<uintptr_t>(hook_fn);

    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) { munmap(tramp, 48); return nullptr; }
    bool ok = (lseek(fd, (off_t)target, SEEK_SET) >= 0 && write(fd, patch, 24) == 24);
    close(fd);
    if (!ok) { LOGE("art_hooks: write failed"); munmap(tramp, 48); return nullptr; }
    __builtin___clear_cache((char*)target, (char*)target + 24);

    LOGI("art_hooks: raw_patch(24) %p -> %p  tramp=%p  lit=0x%016lx",
         target, hook_fn, tramp, lit_val);
    return tramp;
}

// ---------------------------------------------------------------------------
// JNI helpers
// ---------------------------------------------------------------------------
static JavaVM* g_vm = nullptr;

static int get_env(JNIEnv** env_out) {
    if (!g_vm) return JNI_ERR;
    jint r = g_vm->GetEnv(reinterpret_cast<void**>(env_out), JNI_VERSION_1_6);
    if (r == JNI_EDETACHED) r = g_vm->AttachCurrentThread(env_out, nullptr);
    return r;
}

static void emit(const char* method, const char* data) {
    LOGI("{\"type\":\"behavior\",\"method\":\"%s\",\"data\":\"%s\"}", method, data);
}

// Convert a raw ART heap reference (returned from compiled code) to std::string.
// Wrapped in ExceptionCheck in case the pointer is not a valid String.
static std::string jstring_val(JNIEnv* env, void* raw_ref) {
    if (!raw_ref || !env) return "";
    auto jstr = reinterpret_cast<jstring>(raw_ref);
    // NewLocalRef promotes raw heap pointer to a proper JNI local ref
    jstring local = static_cast<jstring>(env->NewLocalRef(jstr));
    if (!local || env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    const char* cstr = env->GetStringUTFChars(local, nullptr);
    if (env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(local); return ""; }
    std::string result = cstr ? cstr : "";
    if (cstr) env->ReleaseStringUTFChars(local, cstr);
    env->DeleteLocalRef(local);
    return result;
}

// ---------------------------------------------------------------------------
// Hook functions — call orig directly (no ShadowHook macros needed)
// orig_X is set to the trampoline by install_one before any call can arrive.
// ---------------------------------------------------------------------------

using FnVoidRet = void*(*)(void*);
using FnTwoArg  = void*(*)(void*, void*);

static FnVoidRet orig_getDeviceId       = nullptr;
static FnVoidRet orig_getSubscriberId   = nullptr;
static FnVoidRet orig_getSimSerialNumber= nullptr;
static FnVoidRet orig_getLine1Number    = nullptr;
static FnTwoArg  orig_settingsGetString = nullptr;
static FnVoidRet orig_getMacAddress     = nullptr;
static FnVoidRet orig_getHardwareAddress= nullptr;

static void* hook_getDeviceId(void* thiz) {
    void* ret = orig_getDeviceId ? orig_getDeviceId(thiz) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getDeviceId", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getSubscriberId(void* thiz) {
    void* ret = orig_getSubscriberId ? orig_getSubscriberId(thiz) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getSubscriberId", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getSimSerialNumber(void* thiz) {
    void* ret = orig_getSimSerialNumber ? orig_getSimSerialNumber(thiz) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getSimSerialNumber", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getLine1Number(void* thiz) {
    void* ret = orig_getLine1Number ? orig_getLine1Number(thiz) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getLine1Number", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_settingsGetString(void* cr, void* key) {
    void* ret = orig_settingsGetString ? orig_settingsGetString(cr, key) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK) {
        std::string k = jstring_val(env, key);
        std::string v = jstring_val(env, ret);
        emit("Settings.Secure.getString", (k + "=" + v).c_str());
    }
    return ret;
}
static void* hook_getMacAddress(void* thiz) {
    void* ret = orig_getMacAddress ? orig_getMacAddress(thiz) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("WifiInfo.getMacAddress", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getHardwareAddress(void* thiz) {
    void* ret = orig_getHardwareAddress ? orig_getHardwareAddress(thiz) : nullptr;
    emit("NetworkInterface.getHardwareAddress", "called");
    return ret;
}

// ---------------------------------------------------------------------------
// Installer
// ---------------------------------------------------------------------------
struct HookTarget {
    const char* class_name;
    const char* method_name;
    const char* sig;
    bool        is_static;
    void*       hook_fn;
    void**      orig_out;
};

static void install_one(JNIEnv* env, const HookTarget& t) {
    jclass cls = env->FindClass(t.class_name);
    if (!cls) { env->ExceptionClear(); LOGE("art_hooks: FindClass failed: %s", t.class_name); return; }
    jmethodID mid = t.is_static
        ? env->GetStaticMethodID(cls, t.method_name, t.sig)
        : env->GetMethodID(cls, t.method_name, t.sig);
    if (!mid) { env->ExceptionClear(); LOGE("art_hooks: GetMethodID failed: %s.%s", t.class_name, t.method_name); return; }

    void* ep = get_entry_point(mid);
    if (!ep) { LOGE("art_hooks: entry_point null for %s.%s", t.class_name, t.method_name); return; }
    LOGI("art_hooks: ep %s.%s @ %p", t.class_name, t.method_name, ep);

    // Try ShadowHook first (works for dlopen'd libs)
    void* orig = nullptr;
    void* stub = shadowhook_hook_func_addr(ep, t.hook_fn, &orig);
    if (stub) {
        *t.orig_out = orig;
        LOGI("art_hooks: hooked (SH) %s.%s", t.class_name, t.method_name);
        return;
    }

    // Fall back to raw /proc/self/mem patch (works for OAT code)
    void* tramp = raw_patch(ep, t.hook_fn);
    if (!tramp) { LOGE("art_hooks: all hooks failed for %s.%s", t.class_name, t.method_name); return; }
    *t.orig_out = tramp;
    LOGI("art_hooks: hooked (raw) %s.%s", t.class_name, t.method_name);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
void install_art_inline_hooks(JNIEnv* env, JavaVM* vm) {
    g_vm = vm;
    calibrate_ep_offset(env);

    const HookTarget targets[] = {
        {"android/telephony/TelephonyManager", "getDeviceId",        "()Ljava/lang/String;",  false, (void*)hook_getDeviceId,        (void**)&orig_getDeviceId},
        {"android/telephony/TelephonyManager", "getSubscriberId",    "()Ljava/lang/String;",  false, (void*)hook_getSubscriberId,    (void**)&orig_getSubscriberId},
        {"android/telephony/TelephonyManager", "getSimSerialNumber", "()Ljava/lang/String;",  false, (void*)hook_getSimSerialNumber, (void**)&orig_getSimSerialNumber},
        {"android/telephony/TelephonyManager", "getLine1Number",     "()Ljava/lang/String;",  false, (void*)hook_getLine1Number,     (void**)&orig_getLine1Number},
        {"android/provider/Settings$Secure",   "getString",          "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", true,  (void*)hook_settingsGetString,  (void**)&orig_settingsGetString},
        {"android/net/wifi/WifiInfo",          "getMacAddress",      "()Ljava/lang/String;",  false, (void*)hook_getMacAddress,      (void**)&orig_getMacAddress},
        {"java/net/NetworkInterface",          "getHardwareAddress", "()[B",                  false, (void*)hook_getHardwareAddress, (void**)&orig_getHardwareAddress},
    };
    for (const auto& t : targets) install_one(env, t);
    LOGI("art_hooks: inline hooks installed (ep_offset=%d)", g_ep_offset);
}
