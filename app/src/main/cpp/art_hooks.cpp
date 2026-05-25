#include "art_hooks.h"
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
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
// Oplus two-level dispatch:
//   stub:  LDR X0,[PC+12]  / LDUR X16,[X0,#24] / BR X16 / <Level2*>
// Watchdog monitors Primary ArtMethod, NOT Level2.
// So: read Level2* from literal, patch Level2+24 with hook_fn.
// Returns original compiled-code ptr (for calling through), or nullptr.
// ---------------------------------------------------------------------------
static void* patch_level2_entry(void* stub_ep, void* hook_fn) {
    auto* insns = reinterpret_cast<uint32_t*>(stub_ep);
    LOGI("art_hooks: stub[%p]: %08x %08x %08x | %08x %08x | %08x",
         stub_ep, insns[0], insns[1], insns[2], insns[3], insns[4], insns[5]);

    // Confirm stub pattern: insns[0]=LDR literal, insns[1]=LDUR X16,[X0,#24], insns[2]=BR X16
    bool is_ldr_lit  = (insns[0] & 0x3B000000) == 0x18000000;
    bool is_ldur_x16 = (insns[1] == 0xF8418010);
    bool is_br_x16   = (insns[2] == 0xD61F0200);
    if (!is_ldr_lit || !is_ldur_x16 || !is_br_x16) {
        LOGE("art_hooks: unknown stub pattern, skip");
        return nullptr;
    }

    // Decode Level2* address from imm19 of LDR literal
    int32_t imm19 = (int32_t)((insns[0] >> 5) & 0x7FFFF);
    if (imm19 & (1 << 18)) imm19 |= ~(int32_t)0x7FFFF;
    int lit_off = imm19 * 4;
    if (lit_off < 0 || lit_off > 20) {
        LOGE("art_hooks: lit_off=%d out of range", lit_off);
        return nullptr;
    }
    void* level2 = *reinterpret_cast<void**>(
        reinterpret_cast<uint8_t*>(stub_ep) + lit_off);
    LOGI("art_hooks: Level2=%p", level2);
    if (!level2) return nullptr;

    // Level2+24 = entry_point_from_quick_compiled_code_ (same offset as calibrated)
    auto* ep_slot = reinterpret_cast<void**>(
        reinterpret_cast<uint8_t*>(level2) + 24);
    void* orig = *ep_slot;
    LOGI("art_hooks: Level2+24 = orig=%p", orig);

    // Patch via mprotect (Level2 is a data region, not exec — simpler than /proc/self/mem)
    uintptr_t page = reinterpret_cast<uintptr_t>(ep_slot) & ~(uintptr_t)0xFFF;
    if (mprotect(reinterpret_cast<void*>(page), 0x1000,
                 PROT_READ | PROT_WRITE) == 0) {
        *ep_slot = hook_fn;
        // Do NOT restore PROT_READ: on non-Oplus devices the JIT must be able to
        // update this slot when it compiles the method, or it will SEGV_ACCERR.
        // On Oplus the ART hardening prevents JIT from overwriting us anyway.
        LOGI("art_hooks: patched Level2+24 via mprotect -> %p", hook_fn);
        return orig;
    }
    LOGE("art_hooks: mprotect failed errno=%d, trying /proc/self/mem", errno);

    // Fallback: /proc/self/mem
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) { LOGE("art_hooks: open /proc/self/mem failed errno=%d", errno); return nullptr; }
    bool ok = (lseek(fd, reinterpret_cast<off_t>(ep_slot), SEEK_SET) >= 0 &&
               write(fd, &hook_fn, sizeof(hook_fn)) == (ssize_t)sizeof(hook_fn));
    close(fd);
    if (!ok) { LOGE("art_hooks: write /proc/self/mem failed errno=%d", errno); return nullptr; }
    __builtin___clear_cache(reinterpret_cast<char*>(ep_slot),
                            reinterpret_cast<char*>(ep_slot) + 8);
    LOGI("art_hooks: patched Level2+24 via /proc/self/mem -> %p", hook_fn);
    return orig;
}

// ---------------------------------------------------------------------------
// ART Thread* preservation helpers
//
// When our hook is called, X19 = ART Thread* (set by the runtime).
// The C compiler may clobber X19 before we call orig (e.g. to spill `am`).
// We capture X19 at hook entry and pass it as an extra arg to invoke_art_*
// which restores it into X19 just before branching to orig.
//
// invoke_art_2arg(orig, x0, x1, thread_ptr):
//   x0=am, x1=this  -> return void*
// invoke_art_3arg(orig, x0, x1, x2, thread_ptr):
//   x0=am, x1=arg0, x2=arg1 -> return void*
// ---------------------------------------------------------------------------

__attribute__((naked))
static void* invoke_art_2arg(void* orig, void* x0, void* x1, void* thread_ptr) {
    // ARM64 calling convention on entry:
    //   x0=orig, x1=arg_x0, x2=arg_x1, x3=thread_ptr
    asm volatile(
        "mov x16, x0\n"   // x16 = orig fn ptr
        "mov x0,  x1\n"   // x0  = am (Level2*)
        "mov x1,  x2\n"   // x1  = this
        "mov x19, x3\n"   // x19 = Thread*  (restored before call)
        "br  x16\n"       // tail-call: return value in x0 goes to caller
    );
}

__attribute__((naked))
static void* invoke_art_3arg(void* orig, void* x0, void* x1, void* x2, void* thread_ptr) {
    // x0=orig, x1=arg_x0, x2=arg_x1, x3=arg_x2, x4=thread_ptr
    asm volatile(
        "mov x16, x0\n"
        "mov x0,  x1\n"   // x0 = am
        "mov x1,  x2\n"   // x1 = arg0 (cr)
        "mov x2,  x3\n"   // x2 = arg1 (key)
        "mov x19, x4\n"   // x19 = Thread*
        "br  x16\n"
    );
}

// Capture X19 (ART Thread*) at the very start of a hook function.
#define READ_THREAD_PTR(var) \
    void* var; \
    asm volatile("mov %0, x19" : "=r"(var))

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

static std::string jstring_val(JNIEnv* env, void* raw_ref) {
    if (!raw_ref || !env) return "";
    jstring local = static_cast<jstring>(env->NewLocalRef(reinterpret_cast<jstring>(raw_ref)));
    if (!local || env->ExceptionCheck()) { env->ExceptionClear(); return ""; }
    const char* cstr = env->GetStringUTFChars(local, nullptr);
    if (env->ExceptionCheck()) { env->ExceptionClear(); env->DeleteLocalRef(local); return ""; }
    std::string r = cstr ? cstr : "";
    if (cstr) env->ReleaseStringUTFChars(local, cstr);
    env->DeleteLocalRef(local);
    return r;
}

// ---------------------------------------------------------------------------
// Hook functions
// ART arm64 quick calling convention: X0=ArtMethod*, X1=this (instance methods)
// X0=ArtMethod*, X1=arg0, X2=arg1 (static methods)
// orig_X = compiled code ptr saved from Level2+24 before patch
// ---------------------------------------------------------------------------
using FnArtInst   = void*(*)(void*, void*);           // (artmethod, this)
using FnArtStatic = void*(*)(void*, void*, void*);    // (artmethod, arg0, arg1)

static FnArtInst   orig_getDeviceId        = nullptr;
static FnArtInst   orig_getSubscriberId    = nullptr;
static FnArtInst   orig_getSimSerialNumber = nullptr;
static FnArtInst   orig_getLine1Number     = nullptr;
static FnArtStatic orig_settingsGetString  = nullptr;
static FnArtInst   orig_getMacAddress      = nullptr;
static FnArtInst   orig_getHardwareAddress = nullptr;

static void* hook_getDeviceId(void* am, void* thiz) {
    READ_THREAD_PTR(tp);
    void* ret = orig_getDeviceId ? invoke_art_2arg((void*)orig_getDeviceId, am, thiz, tp) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getDeviceId", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getSubscriberId(void* am, void* thiz) {
    READ_THREAD_PTR(tp);
    void* ret = orig_getSubscriberId ? invoke_art_2arg((void*)orig_getSubscriberId, am, thiz, tp) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getSubscriberId", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getSimSerialNumber(void* am, void* thiz) {
    READ_THREAD_PTR(tp);
    void* ret = orig_getSimSerialNumber ? invoke_art_2arg((void*)orig_getSimSerialNumber, am, thiz, tp) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getSimSerialNumber", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getLine1Number(void* am, void* thiz) {
    READ_THREAD_PTR(tp);
    void* ret = orig_getLine1Number ? invoke_art_2arg((void*)orig_getLine1Number, am, thiz, tp) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("TelephonyManager.getLine1Number", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_settingsGetString(void* am, void* cr, void* key) {
    READ_THREAD_PTR(tp);
    void* ret = orig_settingsGetString ? invoke_art_3arg((void*)orig_settingsGetString, am, cr, key, tp) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("Settings.Secure.getString", (jstring_val(env, key) + "=" + jstring_val(env, ret)).c_str());
    return ret;
}
static void* hook_getMacAddress(void* am, void* thiz) {
    READ_THREAD_PTR(tp);
    void* ret = orig_getMacAddress ? invoke_art_2arg((void*)orig_getMacAddress, am, thiz, tp) : nullptr;
    JNIEnv* env = nullptr;
    if (get_env(&env) == JNI_OK)
        emit("WifiInfo.getMacAddress", jstring_val(env, ret).c_str());
    return ret;
}
static void* hook_getHardwareAddress(void* am, void* thiz) {
    READ_THREAD_PTR(tp);
    void* ret = orig_getHardwareAddress ? invoke_art_2arg((void*)orig_getHardwareAddress, am, thiz, tp) : nullptr;
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
    if (!ep) { LOGE("art_hooks: ep null %s.%s", t.class_name, t.method_name); return; }
    LOGI("art_hooks: ep %s.%s @ %p", t.class_name, t.method_name, ep);

    // Try ShadowHook (works for dlopen'd DSOs)
    void* orig = nullptr;
    void* stub = shadowhook_hook_func_addr(ep, t.hook_fn, &orig);
    if (stub) {
        *t.orig_out = orig;
        LOGI("art_hooks: hooked (SH) %s.%s", t.class_name, t.method_name);
        return;
    }

    // Fall back: patch Level2 entry_point (Oplus two-level dispatch)
    orig = patch_level2_entry(ep, t.hook_fn);
    if (!orig) { LOGE("art_hooks: all hooks failed for %s.%s", t.class_name, t.method_name); return; }
    memcpy(t.orig_out, &orig, sizeof(void*));
    LOGI("art_hooks: hooked (L2) %s.%s orig=%p", t.class_name, t.method_name, orig);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// Returns true only on Oplus/ColorOS devices where the ART watchdog blocks LSPlant.
// On all other devices, LSPlant already works and art_hooks would double-hook,
// causing interpreter bridge to crash with SEGV because Level2 lacks declaring_class_.
static bool is_oplus_device() {
    char manufacturer[PROP_VALUE_MAX] = {};
    char brand[PROP_VALUE_MAX] = {};
    __system_property_get("ro.product.manufacturer", manufacturer);
    __system_property_get("ro.product.brand", brand);
    // Oplus ecosystem: OPPO, OnePlus, realme, IQOO, vivo (oplus ART hardening)
    for (const char* val : {manufacturer, brand}) {
        std::string s = val;
        for (auto& c : s) c = tolower(c);
        if (s.find("oppo") != std::string::npos ||
            s.find("oneplus") != std::string::npos ||
            s.find("realme") != std::string::npos ||
            s.find("oplus") != std::string::npos) {
            return true;
        }
    }
    return false;
}

void install_art_inline_hooks(JNIEnv* env, JavaVM* vm) {
    g_vm = vm;

    if (!is_oplus_device()) {
        LOGI("art_hooks: non-Oplus device, skipping inline hooks (LSPlant handles it)");
        return;
    }

    calibrate_ep_offset(env);

    const HookTarget targets[] = {
        {"android/telephony/TelephonyManager", "getDeviceId",        "()Ljava/lang/String;",  false, (void*)hook_getDeviceId,        (void**)&orig_getDeviceId},
        {"android/telephony/TelephonyManager", "getSubscriberId",    "()Ljava/lang/String;",  false, (void*)hook_getSubscriberId,    (void**)&orig_getSubscriberId},
        {"android/telephony/TelephonyManager", "getSimSerialNumber", "()Ljava/lang/String;",  false, (void*)hook_getSimSerialNumber, (void**)&orig_getSimSerialNumber},
        {"android/telephony/TelephonyManager", "getLine1Number",     "()Ljava/lang/String;",  false, (void*)hook_getLine1Number,     (void**)&orig_getLine1Number},
        {"android/provider/Settings$Secure",   "getString",          "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;", true, (void*)hook_settingsGetString, (void**)&orig_settingsGetString},
        {"android/net/wifi/WifiInfo",          "getMacAddress",      "()Ljava/lang/String;",  false, (void*)hook_getMacAddress,      (void**)&orig_getMacAddress},
        {"java/net/NetworkInterface",          "getHardwareAddress", "()[B",                  false, (void*)hook_getHardwareAddress, (void**)&orig_getHardwareAddress},
    };
    for (const auto& tgt : targets) install_one(env, tgt);
    LOGI("art_hooks: inline hooks installed (ep_offset=%d)", g_ep_offset);
}

