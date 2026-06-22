#include "hooks.h"
#include "art_hooks.h"
#include <jni.h>
#include <android/log.h>
#include <functional>
#include <string>
#include <lsplant.hpp>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <sys/stat.h>

#define TAG "payload"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Check and clear pending exception; return true if exception occurred.
static bool check_exception(JNIEnv* env, const char* ctx) {
    if (env->ExceptionCheck()) {
        LOGE("hooks: exception in %s", ctx);
        env->ExceptionDescribe();
        env->ExceptionClear();
        return true;
    }
    return false;
}

// App context classloader — saved during load_hooker_class for app-bundled libs (e.g. OkHttp3).
static jobject g_app_cl = nullptr;

// Find a class through the app's context classloader.
// Use for classes not visible to FindClass (e.g. OkHttp3 bundled inside the app).
static jclass find_app_class(JNIEnv* env, const char* jni_name) {
    if (!g_app_cl) return nullptr;
    std::string dot_name = jni_name;
    for (auto& c : dot_name) if (c == '/') c = '.';
    jclass cl_cls = env->GetObjectClass(g_app_cl);
    jmethodID load_cls = env->GetMethodID(cl_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load_cls) { env->ExceptionClear(); return nullptr; }
    jstring jname = env->NewStringUTF(dot_name.c_str());
    auto result = static_cast<jclass>(env->CallObjectMethod(g_app_cl, load_cls, jname));
    env->DeleteLocalRef(jname);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    return result;
}

extern "C" {
#include "aes.h"
}
#include <stdlib.h>
#include <string.h>

// ⚠⚠ 必须与 tools/enc_dex.c 的 KEY 逐字节一致（轮换：两处同步改 + 重新 enc_dex + 重编 .so）。
//    示例值，落地前请用 tools 里的生成器换成自己随机生成的一套。
static const uint8_t DEX_KEY[32] = {
    0xA4, 0xF5, 0x9A, 0x28, 0x1D, 0xEA, 0x66, 0x76,
    0xE9, 0x20, 0xFE, 0x49, 0x24, 0xC1, 0xC8, 0x9C,
    0x5F, 0xEE, 0xA4, 0x9B, 0x4B, 0xFC, 0x56, 0xBF,
    0x6D, 0x11, 0x3D, 0x0D, 0x44, 0xE6, 0xD5, 0x0C,
};

// ── per-hook 开关（denylist）：不再关注的 hook 在安装时跳过 = 零运行时成本 + 缩小检测面 ──
// key = HookerBridge 上的回调名（hookXxx）。当前留空 = 全部安装(对现有行为零影响)。
// 填法：从 xlsx「Hook点清单(源码)」勾"关闭?"的 callback 名，在 nullptr 上方加 "hookXxx",。
static const char* const kDisabledHooks[] = {
    nullptr,   // ← 占位，勿删；在此行上方按需添加 "hookXxx",
};
static bool hook_enabled(const char* callback_name) {
    for (const char* d : kDisabledHooks)
        if (d != nullptr && strcmp(d, callback_name) == 0) return false;
    return true;
}

// Load hooker.dex.enc from /data/local/tmp, AES-256-CTR decrypt in native, then
// InMemoryDexClassLoader (API 26+). Reading bytes natively + loading from a
// ByteBuffer avoids any file path in /proc/self/maps and bypasses SELinux
// restrictions on DexClassLoader; the plaintext dex never lands on disk.
static jclass load_hooker_class(JNIEnv* env) {
    // --- Read encrypted dex: [16-byte IV][AES-256-CTR ciphertext] ---
    const char* dex_path = "/data/local/tmp/hooker.dex.enc";
    int fd = open(dex_path, O_RDONLY);
    if (fd < 0) { LOGE("hooks: open hooker.dex.enc failed errno=%d", errno); return nullptr; }
    struct stat st;
    fstat(fd, &st);
    size_t file_size = (size_t)st.st_size;
    if (file_size <= 16) { LOGE("hooks: enc too small (%zu)", file_size); close(fd); return nullptr; }

    // Read whole encrypted file into a temp native buffer
    uint8_t* raw = (uint8_t*)malloc(file_size);
    if (raw == nullptr) { close(fd); return nullptr; }
    ssize_t n = read(fd, raw, file_size);
    close(fd);
    if (n != (ssize_t)file_size) { LOGE("hooks: read enc failed n=%zd", n); free(raw); return nullptr; }

    uint8_t iv[16];
    memcpy(iv, raw, 16);                       // first 16 bytes = IV
    uint8_t* cipher = raw + 16;
    jsize dex_size = (jsize)(file_size - 16);

    // Allocate a direct ByteBuffer of plaintext size
    jclass bb_class = env->FindClass("java/nio/ByteBuffer");
    if (check_exception(env, "FindClass ByteBuffer") || bb_class == nullptr) { free(raw); return nullptr; }
    jmethodID allocate_direct = env->GetStaticMethodID(bb_class, "allocateDirect", "(I)Ljava/nio/ByteBuffer;");
    if (check_exception(env, "GetStaticMethodID allocateDirect") || allocate_direct == nullptr) { free(raw); return nullptr; }
    jobject byte_buf = env->CallStaticObjectMethod(bb_class, allocate_direct, dex_size);
    if (check_exception(env, "allocateDirect") || byte_buf == nullptr) { free(raw); return nullptr; }

    void* buf_ptr = env->GetDirectBufferAddress(byte_buf);
    if (buf_ptr == nullptr) { LOGE("hooks: GetDirectBufferAddress failed"); free(raw); return nullptr; }

    // Copy ciphertext into the direct buffer and AES-256-CTR decrypt in place.
    // Plaintext dex lives only in this direct buffer (held by InMemoryDexClassLoader);
    // /data/local/tmp keeps only the encrypted .enc — no plaintext dex on disk.
    memcpy(buf_ptr, cipher, dex_size);
    struct AES_ctx aes;
    AES_init_ctx_iv(&aes, DEX_KEY, iv);
    AES_CTR_xcrypt_buffer(&aes, (uint8_t*)buf_ptr, (size_t)dex_size);

    memset(raw, 0, file_size);                 // wipe local ciphertext buffer
    free(raw);

    // Sanity: decrypted buffer must start with the dex magic, else wrong DEX_KEY.
    if (memcmp(buf_ptr, "dex\n", 4) != 0) {
        LOGE("hooks: decrypted dex magic mismatch (wrong DEX_KEY?)");
        return nullptr;
    }

    // --- Get parent classloader ---
    jclass thread_class = env->FindClass("java/lang/Thread");
    jmethodID current_thread = env->GetStaticMethodID(thread_class, "currentThread", "()Ljava/lang/Thread;");
    jmethodID get_context_cl = env->GetMethodID(thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    jobject cur_thread = env->CallStaticObjectMethod(thread_class, current_thread);
    jobject parent_cl = env->CallObjectMethod(cur_thread, get_context_cl);
    if (check_exception(env, "getContextClassLoader")) parent_cl = nullptr;
    if (parent_cl && !g_app_cl) g_app_cl = env->NewGlobalRef(parent_cl);

    // --- InMemoryDexClassLoader(ByteBuffer dexBuffer, ClassLoader parent) ---
    jclass imdcl_class = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (check_exception(env, "FindClass InMemoryDexClassLoader") || imdcl_class == nullptr) return nullptr;
    jmethodID imdcl_ctor = env->GetMethodID(imdcl_class, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (check_exception(env, "GetMethodID InMemoryDexClassLoader.<init>") || imdcl_ctor == nullptr) return nullptr;

    jobject dex_cl = env->NewObject(imdcl_class, imdcl_ctor, byte_buf, parent_cl);
    if (check_exception(env, "new InMemoryDexClassLoader") || dex_cl == nullptr) {
        LOGE("hooks: InMemoryDexClassLoader construction failed");
        return nullptr;
    }

    // --- classLoader.loadClass("com.pecker.payload.HookerBridge") ---
    jmethodID load_class = env->GetMethodID(
        env->FindClass("java/lang/ClassLoader"), "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
    if (check_exception(env, "GetMethodID loadClass") || load_class == nullptr) return nullptr;
    jstring class_name = env->NewStringUTF("com.pecker.payload.HookerBridge");
    jclass hooker_class = static_cast<jclass>(
        env->CallObjectMethod(dex_cl, load_class, class_name));
    if (check_exception(env, "loadClass HookerBridge") || hooker_class == nullptr) {
        LOGE("hooks: loadClass HookerBridge failed");
        return nullptr;
    }

    return hooker_class;
}

// Create a HookerBridge instance.
static jobject create_hooker(JNIEnv* env, jclass hooker_class) {
    jmethodID ctor = env->GetMethodID(hooker_class, "<init>", "()V");
    if (check_exception(env, "GetMethodID HookerBridge.<init>") || ctor == nullptr) return nullptr;
    jobject obj = env->NewObject(hooker_class, ctor);
    if (check_exception(env, "NewObject HookerBridge")) return nullptr;
    return obj;
}

// Install a single hook and store the backup in the hooker's field.
// target_class_name: JNI class name (e.g. "android/telephony/TelephonyManager")
// target_method_name: method name
// target_sig: JNI method descriptor for target
// callback_name: method name on HookerBridge
// callback_sig: JNI descriptor for callback (includes hooker as first param)
// backup_field: name of backup Method field on HookerBridge
// is_static: whether target method is static
// use_app_cl: look up target class via app classloader (for app-bundled libs like OkHttp3)
// optional: if true, a missing method is logged at INFO level instead of ERROR (API version gaps)
static void hook_one(JNIEnv* env,
                     jobject hooker_obj,
                     jclass hooker_class,
                     const char* target_class_name,
                     const char* target_method_name,
                     const char* target_sig,
                     const char* callback_name,
                     const char* callback_sig,
                     const char* backup_field,
                     bool is_static,
                     bool use_app_cl = false,
                     bool optional = false) {
    if (!hook_enabled(callback_name)) {        // per-hook 开关：被关的 hook 安装时跳过(零成本)
        LOGI("hooks: skip disabled hook %s", callback_name);
        return;
    }
    // --- get target class ---
    jclass target_class = use_app_cl
        ? find_app_class(env, target_class_name)
        : env->FindClass(target_class_name);
    if (use_app_cl && target_class == nullptr) {
        LOGI("hooks: app class not found (optional): %s", target_class_name);
        return;
    }
    if (check_exception(env, target_class_name) || target_class == nullptr) {
        LOGE("hooks: FindClass failed: %s", target_class_name);
        return;
    }

    // --- get target method as reflected Method ---
    jobject target_method;
    if (is_static) {
        jmethodID mid = env->GetStaticMethodID(target_class, target_method_name, target_sig);
        if (check_exception(env, target_method_name) || mid == nullptr) {
            LOGE("hooks: GetStaticMethodID failed: %s %s", target_method_name, target_sig);
            return;
        }
        target_method = env->ToReflectedMethod(target_class, mid, JNI_TRUE);
    } else {
        jmethodID mid = env->GetMethodID(target_class, target_method_name, target_sig);
        if (check_exception(env, target_method_name) || mid == nullptr) {
            if (optional) {
                LOGI("hooks: method not found (optional): %s %s", target_method_name, target_sig);
            } else {
                LOGE("hooks: GetMethodID failed: %s %s", target_method_name, target_sig);
            }
            return;
        }
        target_method = env->ToReflectedMethod(target_class, mid, JNI_FALSE);
    }
    if (check_exception(env, "ToReflectedMethod") || target_method == nullptr) return;

    // --- get callback method as reflected Method (instance method — LSPlant calls it virtually) ---
    jmethodID cb_mid = env->GetMethodID(hooker_class, callback_name, callback_sig);
    if (check_exception(env, callback_name) || cb_mid == nullptr) {
        LOGE("hooks: GetMethodID callback failed: %s %s", callback_name, callback_sig);
        return;
    }
    jobject callback_method = env->ToReflectedMethod(hooker_class, cb_mid, JNI_FALSE);
    if (check_exception(env, "ToReflectedMethod callback") || callback_method == nullptr) return;

    // --- call lsplant::Hook ---
    jobject backup = lsplant::Hook(env, target_method, hooker_obj, callback_method);
    if (backup == nullptr) {
        LOGE("hooks: lsplant::Hook failed for %s.%s", target_class_name, target_method_name);
        return;
    }
    LOGI("hooks: hooked %s.%s", target_class_name, target_method_name);

    // --- store backup in hooker field ---
    jfieldID fid = env->GetFieldID(hooker_class, backup_field, "Ljava/lang/reflect/Method;");
    if (check_exception(env, backup_field) || fid == nullptr) {
        LOGE("hooks: GetFieldID failed: %s", backup_field);
        return;
    }
    env->SetObjectField(hooker_obj, fid, backup);
    check_exception(env, "SetObjectField backup");
}

// Module-level globals: hooker instance and class kept alive for Phase 10 delayed hooking.
// Declared extern in hooks.h so main.cpp's Phase 10 thread can use them directly
// instead of calling FindClass on a bare native thread (wrong ClassLoader).
static jobject   g_hooker_obj_global    = nullptr;
jclass           g_hooker_class_global  = nullptr;
jmethodID        g_install_mini_method  = nullptr;

// JNI: HookerBridge.hookNative(Object target, Object hooker, Object callback) -> Object (backup)
// Called from installMiniHooks() on a background thread to register WeChat-specific hooks
// via LSPlant after WeChat's dex classes are loaded (2 s after injection).
static jobject JNICALL native_hook_method(JNIEnv* env, jclass /*cls*/,
                                           jobject target_method,
                                           jobject hooker_obj,
                                           jobject callback_method) {
    if (!target_method || !hooker_obj || !callback_method) {
        LOGE("hookNative: null argument passed");
        return nullptr;
    }
    // Prevent ART JIT from compiling (or re-compiling) the target method after
    // lsplant::Hook() replaces its entry_point.  Without this, the JIT background
    // thread compiles the method a few seconds after the first call and overwrites
    // LSPlant's dispatch stub, silently disabling the hook.
    //
    // kAccCompileDontBother (0x02000000) is an ArtMethod access_flags bit that
    // tells the JIT profiling system to never schedule this method for compilation.
    // access_flags_ is always at (entry_point_offset - 28) within ArtMethod*.
    // g_ep_offset is calibrated by art_hooks.cpp (default 32, Oplus devices may differ).
    {
        jmethodID mid = env->FromReflectedMethod(target_method);
        if (mid) {
            auto* am = reinterpret_cast<uint8_t*>(mid);
            int flags_offset = g_ep_offset - 28;  // standard: 32-28=4
            auto* flags = reinterpret_cast<uint32_t*>(am + flags_offset);
            constexpr uint32_t kAccCompileDontBother = 0x02000000u;
            *flags |= kAccCompileDontBother;
            LOGI("hookNative: set kAccCompileDontBother on method (flags_offset=%d flags=0x%08x)",
                 flags_offset, *flags);
        }
    }
    jobject backup = lsplant::Hook(env, target_method, hooker_obj, callback_method);
    if (!backup) LOGE("hookNative: lsplant::Hook returned null");
    return backup;
}

// JNI: HookerBridge.deoptimizeNative(Object method) -> void
// Called from installMiniHooks() after hooking a WeChat method to force its JIT-compiled
// callers back to the interpreter, so that ArtMethod entry_point dispatch is used and
// our LSPlant hook actually fires.
static void JNICALL native_deoptimize(JNIEnv* env, jclass /*cls*/, jobject method) {
    if (!method) {
        LOGE("deoptimizeNative: null method");
        return;
    }
    bool ok = lsplant::Deoptimize(env, method);
    if (ok) {
        LOGI("deoptimizeNative: ok");
    } else {
        LOGE("deoptimizeNative: failed");
    }
}

void install_device_id_hooks(JNIEnv* env) {
    jclass hooker_class = load_hooker_class(env);
    if (hooker_class == nullptr) {
        LOGE("hooks: load_hooker_class failed");
        return;
    }

    jobject hooker_obj = create_hooker(env, hooker_class);
    if (hooker_obj == nullptr) {
        LOGE("hooks: create_hooker failed");
        return;
    }

    // Keep hooker alive for the lifetime of the process.
    // Also save globals for Phase 10 delayed hook registration.
    g_hooker_obj_global   = env->NewGlobalRef(hooker_obj);
    g_hooker_class_global = static_cast<jclass>(env->NewGlobalRef(hooker_class));

    // Set HookerBridge.sInstance so installMiniHooks() can reach the hooker from Java.
    jfieldID sinst_fid = env->GetStaticFieldID(hooker_class, "sInstance",
                                                "Lcom/pecker/payload/HookerBridge;");
    if (!check_exception(env, "GetStaticFieldID sInstance") && sinst_fid) {
        env->SetStaticObjectField(hooker_class, sinst_fid, hooker_obj);
        check_exception(env, "SetStaticObjectField sInstance");
    }

    // Register hookNative and deoptimizeNative for Phase 10.
    JNINativeMethod mini_native[] = {
        {"hookNative",
         "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
         reinterpret_cast<void*>(native_hook_method)},
        {"deoptimizeNative",
         "(Ljava/lang/Object;)V",
         reinterpret_cast<void*>(native_deoptimize)},
    };
    if (env->RegisterNatives(hooker_class, mini_native, 2) != 0) {
        check_exception(env, "RegisterNatives hookNative/deoptimizeNative");
        LOGE("hooks: RegisterNatives hookNative/deoptimizeNative failed");
    } else {
        LOGI("hooks: hookNative+deoptimizeNative registered for Phase 10");
        // Cache scheduleInstallMiniHooks() method ID (void, no-arg) on the app thread
        // while the InMemoryDexClassLoader context is active. The Phase 10 thread posts
        // to the appbrand main looper via this method so installMiniHooks() runs on a
        // WeChat app thread whose context ClassLoader includes Tinker patch DEXes.
        g_install_mini_method = env->GetStaticMethodID(
            g_hooker_class_global, "scheduleInstallMiniHooks", "()V");
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            g_install_mini_method = nullptr;
            LOGE("hooks: GetStaticMethodID scheduleInstallMiniHooks failed");
        } else {
            LOGI("hooks: scheduleInstallMiniHooks method ID cached for Phase 10");
        }
    }

    // LSPlant 6.4 always dispatches via ([Ljava/lang/Object;)Ljava/lang/Object;
    // args = [hookerInstance, thiz, param1, param2, ...] for instance methods
    // args = [hookerInstance, param1, param2, ...]       for static methods
    static const char* kCbSig = "([Ljava/lang/Object;)Ljava/lang/Object;";

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getDeviceId", "()Ljava/lang/String;",
        "hookGetDeviceId", kCbSig, "backupGetDeviceId", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getSubscriberId", "()Ljava/lang/String;",
        "hookGetSubscriberId", kCbSig, "backupGetSubscriberId", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getSimSerialNumber", "()Ljava/lang/String;",
        "hookGetSimSerialNumber", kCbSig, "backupGetSimSerialNumber", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getLine1Number", "()Ljava/lang/String;",
        "hookGetLine1Number", kCbSig, "backupGetLine1Number", false);

    // ── B: 设备标识补充 ──（no-arg here; slot (int) overloads added right below; all optional）
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getImei", "()Ljava/lang/String;",
        "hookGetImei", kCbSig, "backupGetImei", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getMeid", "()Ljava/lang/String;",
        "hookGetMeid", kCbSig, "backupGetMeid", false, false, true);
    // slot 重载 getImei(int)/getMeid(int)/getDeviceId(int) — 行为监测(不论取值)，
    // 各自独立 handler/backup，复用无参 key；optional 兜底。
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getImei", "(I)Ljava/lang/String;",
        "hookGetImeiSlot", kCbSig, "backupGetImeiSlot", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getMeid", "(I)Ljava/lang/String;",
        "hookGetMeidSlot", kCbSig, "backupGetMeidSlot", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getDeviceId", "(I)Ljava/lang/String;",
        "hookGetDeviceIdSlot", kCbSig, "backupGetDeviceIdSlot", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/os/Build", "getSerial", "()Ljava/lang/String;",
        "hookBuildGetSerial", kCbSig, "backupBuildGetSerial", true, false, true);   // static
    hook_one(env, hooker_obj, hooker_class,
        "android/media/MediaDrm", "getPropertyByteArray", "(Ljava/lang/String;)[B",
        "hookMediaDrmGetPropertyByteArray", kCbSig, "backupMediaDrmGetPropertyByteArray", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/os/SystemProperties", "get", "(Ljava/lang/String;)Ljava/lang/String;",
        "hookSystemPropertiesGet", kCbSig, "backupSystemPropertiesGet", true, false, true);   // static, hidden
    hook_one(env, hooker_obj, hooker_class,
        "android/bluetooth/BluetoothAdapter", "getAddress", "()Ljava/lang/String;",
        "hookBluetoothGetAddress", kCbSig, "backupBluetoothGetAddress", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/bluetooth/BluetoothAdapter", "getName", "()Ljava/lang/String;",
        "hookBluetoothGetName", kCbSig, "backupBluetoothGetName", false, false, true);
    // OAID (MSA) — app-bundled, static; modern InitSdk(Context,boolean,IIdentifierListener)
    hook_one(env, hooker_obj, hooker_class,
        "com/bun/miitmdid/core/MdidSdkHelper", "InitSdk",
        "(Landroid/content/Context;ZLcom/bun/miitmdid/interfaces/IIdentifierListener;)I",
        "hookOaidInitSdk", kCbSig, "backupOaidInitSdk", true, true, true);   // static, use_app_cl

    // Settings.Secure.getString — hooked on all devices. The old ColorOS skip
    // (LSPlant trampoline crash from iFlytek/Tratao JNI contexts) was an artifact
    // of the inline-hook era; under a clean single LSPlant hook it no longer
    // reproduces (validated on OP528F).
    hook_one(env, hooker_obj, hooker_class,
        "android/provider/Settings$Secure",
        "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
        "hookSettingsSecureGetString", kCbSig, "backupSettingsSecureGetString", true);

    hook_one(env, hooker_obj, hooker_class,
        "android/net/wifi/WifiInfo", "getMacAddress", "()Ljava/lang/String;",
        "hookGetMacAddress", kCbSig, "backupWifiGetMacAddress", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/net/NetworkInterface", "getHardwareAddress", "()[B",
        "hookGetHardwareAddress", kCbSig, "backupNetworkInterfaceGetHardwareAddress", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/Activity", "onCreate", "(Landroid/os/Bundle;)V",
        "hookActivityOnCreate", kCbSig, "backupActivityOnCreate", false);

    // Activity.onCreate hook removed — fires on all Activities including the app's
    // own MainActivity; returning null for a void method disrupts super.onCreate()
    // call chains and causes white-screen hangs on apps with anti-tamper checks.
    // Re-enable only if a safer probe point is identified.
    // hook_one(env, hooker_obj, hooker_class,
    //     "android/app/Activity", "onCreate", "(Landroid/os/Bundle;)V",
    //     "hookActivityOnCreate", kCbSig, "backupActivityOnCreate", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "getLastKnownLocation",
        "(Ljava/lang/String;)Landroid/location/Location;",
        "hookGetLastKnownLocation", kCbSig, "backupGetLastKnownLocation", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/location/Location", "getLatitude", "()D",
        "hookLocationGetLatitude", kCbSig, "backupLocationGetLatitude", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/location/Location", "getLongitude", "()D",
        "hookLocationGetLongitude", kCbSig, "backupLocationGetLongitude", false);

    // Phase 3: requestLocationUpdates — 4 overloads
    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "requestLocationUpdates",
        "(Ljava/lang/String;JFLandroid/location/LocationListener;)V",
        "hookRequestLocationUpdatesStr", kCbSig, "backupRequestLocationUpdatesStr", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "requestLocationUpdates",
        "(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V",
        "hookRequestLocationUpdatesStrLooper", kCbSig, "backupRequestLocationUpdatesStrLooper", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "requestLocationUpdates",
        "(Landroid/location/Criteria;JFLandroid/location/LocationListener;)V",
        "hookRequestLocationUpdatesCriteria", kCbSig, "backupRequestLocationUpdatesCriteria", false,
        false, true);

    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "requestLocationUpdates",
        "(Landroid/location/Criteria;JFLandroid/location/LocationListener;Landroid/os/Looper;)V",
        "hookRequestLocationUpdatesCriteriaLooper", kCbSig, "backupRequestLocationUpdatesCriteriaLooper", false,
        false, true);


    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContentResolver", "query",
        "(Landroid/net/Uri;[Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/database/Cursor;",
        "hookContentResolverQuery", kCbSig, "backupContentResolverQuery", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/camera2/CameraManager", "openCamera",
        "(Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;Landroid/os/Handler;)V",
        "hookCameraManagerOpenCamera", kCbSig, "backupCameraManagerOpenCamera", false);

    // Phase 5: network
    hook_one(env, hooker_obj, hooker_class,
        "java/net/URL", "openConnection", "()Ljava/net/URLConnection;",
        "hookUrlOpenConnection", kCbSig, "backupUrlOpenConnection", false);

    // OkHttp3 — optional, only present in apps that bundle it
    hook_one(env, hooker_obj, hooker_class,
        "okhttp3/OkHttpClient", "newCall", "(Lokhttp3/Request;)Lokhttp3/Call;",
        "hookOkHttpNewCall", kCbSig, "backupOkHttpNewCall", false, true);

    // Phase 4b: clipboard / camera / audio / process / shell / navigation
    hook_one(env, hooker_obj, hooker_class,
        "android/content/ClipboardManager", "getPrimaryClip",
        "()Landroid/content/ClipData;",
        "hookClipboardGetPrimaryClip", kCbSig, "backupClipboardGetPrimaryClip", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/Camera", "open",
        "()Landroid/hardware/Camera;",
        "hookCameraOpen0", kCbSig, "backupCameraOpen0", true);

    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/Camera", "open",
        "(I)Landroid/hardware/Camera;",
        "hookCameraOpenInt", kCbSig, "backupCameraOpenInt", true);

    hook_one(env, hooker_obj, hooker_class,
        "android/media/AudioRecord", "startRecording", "()V",
        "hookAudioRecordStartRecording", kCbSig, "backupAudioRecordStartRecording", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/ActivityManager", "getRunningAppProcesses",
        "()Ljava/util/List;",
        "hookGetRunningAppProcesses", kCbSig, "backupGetRunningAppProcesses", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/lang/Runtime", "exec",
        "(Ljava/lang/String;)Ljava/lang/Process;",
        "hookRuntimeExecStr", kCbSig, "backupRuntimeExecStr", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/lang/Runtime", "exec",
        "([Ljava/lang/String;)Ljava/lang/Process;",
        "hookRuntimeExecArray", kCbSig, "backupRuntimeExecArray", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/lang/ProcessBuilder", "start", "()Ljava/lang/Process;",
        "hookProcessBuilderStart", kCbSig, "backupProcessBuilderStart", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/Activity", "startActivity",
        "(Landroid/content/Intent;)V",
        "hookStartActivity", kCbSig, "backupStartActivity", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/Activity", "startActivity",
        "(Landroid/content/Intent;Landroid/os/Bundle;)V",
        "hookStartActivityWithOptions", kCbSig, "backupStartActivityWithOptions", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/Activity", "startActivityForResult",
        "(Landroid/content/Intent;I)V",
        "hookStartActivityForResult", kCbSig, "backupStartActivityForResult", false);

    // ContextWrapper.startActivity — covers Custom Tabs and any Context-level startActivity.
    // CustomTabsIntent.launchUrl() calls Context.startActivity() not Activity.startActivity().
    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "startActivity",
        "(Landroid/content/Intent;)V",
        "hookContextStartActivity", kCbSig, "backupContextStartActivity", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "startActivity",
        "(Landroid/content/Intent;Landroid/os/Bundle;)V",
        "hookContextStartActivityWithOptions", kCbSig, "backupContextStartActivityWithOptions", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/media/MediaRecorder", "start", "()V",
        "hookMediaRecorderStart", kCbSig, "backupMediaRecorderStart", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/content/BroadcastReceiver", "onReceive",
        "(Landroid/content/Context;Landroid/content/Intent;)V",
        "hookBroadcastReceiverOnReceive", kCbSig, "backupBroadcastReceiverOnReceive", false);

    // Phase 5b: OkHttp3 RealCall.execute — optional, only if okhttp3 is bundled
    hook_one(env, hooker_obj, hooker_class,
        "okhttp3/RealCall", "execute",
        "()Lokhttp3/Response;",
        "hookRealCallExecute", kCbSig, "backupRealCallExecute", false, true);

    hook_one(env, hooker_obj, hooker_class,
        "okhttp3/RealCall", "enqueue",
        "(Lokhttp3/Callback;)V",
        "hookRealCallEnqueue", kCbSig, "backupRealCallEnqueue", false, true);

    // Volley — optional, only if com.android.volley is bundled
    hook_one(env, hooker_obj, hooker_class,
        "com/android/volley/toolbox/StringRequest", "deliverResponse",
        "(Ljava/lang/String;)V",
        "hookVolleyDeliverResponse", kCbSig, "backupVolleyDeliverResponse", false, true);

    // HttpURLConnection.getResponseCode — Android concrete implementation class.
    // java.net.HttpURLConnection is abstract; the actual class used by URL.openConnection()
    // is com.android.okhttp.internal.huc.HttpURLConnectionImpl which overrides getResponseCode(),
    // so we must hook the override directly (lsplant hooks a specific ArtMethod, not vtable slots).
    // DelegatingHttpsURLConnection (HTTPS) delegates to HttpURLConnectionImpl, so one hook covers both.
    // Marked optional: falls back gracefully on Android versions with a different class name.
    hook_one(env, hooker_obj, hooker_class,
        "com/android/okhttp/internal/huc/HttpURLConnectionImpl", "getResponseCode", "()I",
        "hookHttpURLConnectionGetResponseCode", kCbSig, "backupHttpURLConnectionGetResponseCode", false, true);

    // HttpURLConnection body capture:
    //   getOutputStream — cache request body written before connect()
    //   getInputStream  — read response body after getResponseCode(), log complete entry
    //   getErrorStream  — same for 4xx/5xx error responses
    hook_one(env, hooker_obj, hooker_class,
        "com/android/okhttp/internal/huc/HttpURLConnectionImpl", "getOutputStream",
        "()Ljava/io/OutputStream;",
        "hookHttpURLConnectionGetOutputStream", kCbSig,
        "backupHttpURLConnectionGetOutputStream", false, true);
    hook_one(env, hooker_obj, hooker_class,
        "com/android/okhttp/internal/huc/HttpURLConnectionImpl", "getInputStream",
        "()Ljava/io/InputStream;",
        "hookHttpURLConnectionGetInputStream", kCbSig,
        "backupHttpURLConnectionGetInputStream", false, true);
    hook_one(env, hooker_obj, hooker_class,
        "com/android/okhttp/internal/huc/HttpURLConnectionImpl", "getErrorStream",
        "()Ljava/io/InputStream;",
        "hookHttpURLConnectionGetErrorStream", kCbSig,
        "backupHttpURLConnectionGetErrorStream", false, true);

    // Phase 6b: SSL Pinning bypass
    // CertificatePinner.check — optional, only if okhttp3 is bundled
    hook_one(env, hooker_obj, hooker_class,
        "okhttp3/CertificatePinner", "check",
        "(Ljava/lang/String;Ljava/util/List;)V",
        "hookCertificatePinnerCheck", kCbSig, "backupCertificatePinnerCheck", false, true);

    hook_one(env, hooker_obj, hooker_class,
        "javax/net/ssl/SSLContext", "init",
        "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V",
        "hookSslContextInit", kCbSig, "backupSslContextInit", false);

    hook_one(env, hooker_obj, hooker_class,
        "javax/net/ssl/HttpsURLConnection", "setDefaultHostnameVerifier",
        "(Ljavax/net/ssl/HostnameVerifier;)V",
        "hookSetDefaultHostnameVerifier", kCbSig, "backupSetDefaultHostnameVerifier", true);

    // Phase 6: sensors
    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/SensorManager", "registerListener",
        "(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;I)Z",
        "hookSensorRegister3", kCbSig, "backupSensorRegister3", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/SensorManager", "registerListener",
        "(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;II)Z",
        "hookSensorRegister4Int", kCbSig, "backupSensorRegister4Int", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/SensorManager", "registerListener",
        "(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;ILandroid/os/Handler;)Z",
        "hookSensorRegister4Handler", kCbSig, "backupSensorRegister4Handler", false);

    // Phase 7: permission requests
    hook_one(env, hooker_obj, hooker_class,
        "android/app/Activity", "requestPermissions",
        "([Ljava/lang/String;I)V",
        "hookRequestPermissions", kCbSig, "backupRequestPermissions", false);

    // ActivityCompat.requestPermissions — optional, only if androidx is bundled
    hook_one(env, hooker_obj, hooker_class,
        "androidx/core/app/ActivityCompat", "requestPermissions",
        "(Landroid/app/Activity;[Ljava/lang/String;I)V",
        "hookActivityCompatRequestPermissions", kCbSig,
        "backupActivityCompatRequestPermissions", true, true);

    // android.app.Fragment.requestPermissions — framework (deprecated) Fragment,
    // bootclasspath so present at init. Used by older permission libs (early
    // XXPermissions) and platform-Fragment apps; the androidx Fragment is hooked
    // late from the ClassLoader.loadClass hook instead.
    hook_one(env, hooker_obj, hooker_class,
        "android/app/Fragment", "requestPermissions",
        "([Ljava/lang/String;I)V",
        "hookFrameworkFragmentRequestPermissions", kCbSig,
        "backupFrameworkFragmentRequestPermissions", false, true);

    // Phase 7b: PackageInstaller.Session.commit
    hook_one(env, hooker_obj, hooker_class,
        "android/content/pm/PackageInstaller$Session", "commit",
        "(Landroid/content/IntentSender;)V",
        "hookPackageInstallerCommit", kCbSig, "backupPackageInstallerCommit", false);

    // Phase 8: cell info, wifi, package list, tasks, broadcast, media projection
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getCellLocation",
        "()Landroid/telephony/CellLocation;",
        "hookGetCellLocation", kCbSig, "backupGetCellLocation", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getAllCellInfo",
        "()Ljava/util/List;",
        "hookGetAllCellInfo", kCbSig, "backupGetAllCellInfo", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getNetworkOperator",
        "()Ljava/lang/String;",
        "hookGetNetworkOperator", kCbSig, "backupGetNetworkOperator", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/TelephonyManager", "getNetworkOperatorName",
        "()Ljava/lang/String;",
        "hookGetNetworkOperatorName", kCbSig, "backupGetNetworkOperatorName", false);

    // ApplicationPackageManager — concrete impl of PackageManager; use app classloader
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getInstalledPackages",
        "(I)Ljava/util/List;",
        "hookGetInstalledPackages", kCbSig, "backupGetInstalledPackages", false, true);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getInstalledApplications",
        "(I)Ljava/util/List;",
        "hookGetInstalledApplications", kCbSig, "backupGetInstalledApplications", false, true);

    // ── B: 应用列表补充（ApplicationPackageManager，use_app_cl，optional）──
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        "hookGetPackageInfo", kCbSig, "backupGetPackageInfo", false, true, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getApplicationInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;",
        "hookGetApplicationInfo", kCbSig, "backupGetApplicationInfo", false, true, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "queryIntentActivities",
        "(Landroid/content/Intent;I)Ljava/util/List;",
        "hookQueryIntentActivities", kCbSig, "backupQueryIntentActivities", false, true, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "resolveActivity",
        "(Landroid/content/Intent;I)Landroid/content/pm/ResolveInfo;",
        "hookResolveActivity", kCbSig, "backupResolveActivity", false, true, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getLaunchIntentForPackage",
        "(Ljava/lang/String;)Landroid/content/Intent;",
        "hookGetLaunchIntentForPackage", kCbSig, "backupGetLaunchIntentForPackage", false, true, true);
    // API 33 overload — same behavior, reuses key PackageManager.getInstalledPackages in handler
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getInstalledPackages",
        "(Landroid/content/pm/PackageManager$PackageInfoFlags;)Ljava/util/List;",
        "hookGetInstalledPackagesFlags", kCbSig, "backupGetInstalledPackagesFlags", false, true, true);
    // API 33 overload — reuses key PackageManager.getInstalledApplications (parity with packages flags)
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "getInstalledApplications",
        "(Landroid/content/pm/PackageManager$ApplicationInfoFlags;)Ljava/util/List;",
        "hookGetInstalledApplicationsFlags", kCbSig, "backupGetInstalledApplicationsFlags", false, true, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/app/usage/UsageStatsManager", "queryUsageStats",
        "(IJJ)Ljava/util/List;",
        "hookQueryUsageStats", kCbSig, "backupQueryUsageStats", false, false, true);

    // ── B: 位置补充 ──
    hook_one(env, hooker_obj, hooker_class,
        "android/location/Geocoder", "getFromLocation",
        "(DDI)Ljava/util/List;",
        "hookGeocoderGetFromLocation", kCbSig, "backupGeocoderGetFromLocation", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "requestSingleUpdate",
        "(Ljava/lang/String;Landroid/location/LocationListener;Landroid/os/Looper;)V",
        "hookRequestSingleUpdate", kCbSig, "backupRequestSingleUpdate", false, false, true);
    // getCurrentLocation(String, CancellationSignal, Executor, Consumer) — API 30 单次定位
    hook_one(env, hooker_obj, hooker_class,
        "android/location/LocationManager", "getCurrentLocation",
        "(Ljava/lang/String;Landroid/os/CancellationSignal;Ljava/util/concurrent/Executor;Ljava/util/function/Consumer;)V",
        "hookGetCurrentLocation", kCbSig, "backupGetCurrentLocation", false, false, true);
    // GMS fused-location: hook the stable public factory (getLastLocation lives on an obfuscated
    // impl that can't be reliably LSPlant-hooked). Detects fused-location usage. static, use_app_cl.
    hook_one(env, hooker_obj, hooker_class,
        "com/google/android/gms/location/LocationServices", "getFusedLocationProviderClient",
        "(Landroid/content/Context;)Lcom/google/android/gms/location/FusedLocationProviderClient;",
        "hookFusedLocationClient", kCbSig, "backupFusedLocationClient", true, true, true);

    // ── B: WiFi 补充 ──
    hook_one(env, hooker_obj, hooker_class,
        "android/net/wifi/WifiManager", "getConnectionInfo",
        "()Landroid/net/wifi/WifiInfo;",
        "hookWifiGetConnectionInfo", kCbSig, "backupWifiGetConnectionInfo", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/net/wifi/WifiManager", "getScanResults",
        "()Ljava/util/List;",
        "hookWifiGetScanResults", kCbSig, "backupWifiGetScanResults", false, false, true);

    // ── B: 账户补充 ──
    hook_one(env, hooker_obj, hooker_class,
        "android/accounts/AccountManager", "getAccounts",
        "()[Landroid/accounts/Account;",
        "hookGetAccounts", kCbSig, "backupGetAccounts", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/accounts/AccountManager", "getAccountsByType",
        "(Ljava/lang/String;)[Landroid/accounts/Account;",
        "hookGetAccountsByType", kCbSig, "backupGetAccountsByType", false, false, true);
    // getAuthToken — 账户认证Token(比账号名敏感得多)；两个常用6参重载(Activity/boolean)，同一 key
    hook_one(env, hooker_obj, hooker_class,
        "android/accounts/AccountManager", "getAuthToken",
        "(Landroid/accounts/Account;Ljava/lang/String;Landroid/os/Bundle;Landroid/app/Activity;Landroid/accounts/AccountManagerCallback;Landroid/os/Handler;)Landroid/accounts/AccountManagerFuture;",
        "hookGetAuthTokenActivity", kCbSig, "backupGetAuthTokenActivity", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/accounts/AccountManager", "getAuthToken",
        "(Landroid/accounts/Account;Ljava/lang/String;Landroid/os/Bundle;ZLandroid/accounts/AccountManagerCallback;Landroid/os/Handler;)Landroid/accounts/AccountManagerFuture;",
        "hookGetAuthTokenNotify", kCbSig, "backupGetAuthTokenNotify", false, false, true);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/ActivityManager", "getRunningTasks",
        "(I)Ljava/util/List;",
        "hookGetRunningTasks", kCbSig, "backupGetRunningTasks", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/app/ActivityManager", "getRunningServices",
        "(I)Ljava/util/List;",
        "hookGetRunningServices", kCbSig, "backupGetRunningServices", false);

    // ── 2026-06 补充：蓝牙扫描族(bluetoothmac) / 最近任务 / 已配置WiFi(ssid) / 多卡订阅(imsi) ──
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ActivityManager", "getRecentTasks", "(II)Ljava/util/List;",
        "hookGetRecentTasks", kCbSig, "backupGetRecentTasks", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/bluetooth/BluetoothAdapter", "startDiscovery", "()Z",
        "hookBluetoothStartDiscovery", kCbSig, "backupBluetoothStartDiscovery", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/bluetooth/BluetoothAdapter", "getBondedDevices", "()Ljava/util/Set;",
        "hookBluetoothGetBondedDevices", kCbSig, "backupBluetoothGetBondedDevices", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/bluetooth/le/BluetoothLeScanner", "startScan",
        "(Landroid/bluetooth/le/ScanCallback;)V",
        "hookBleStartScan", kCbSig, "backupBleStartScan", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/bluetooth/le/BluetoothLeScanner", "startScan",
        "(Ljava/util/List;Landroid/bluetooth/le/ScanSettings;Landroid/bluetooth/le/ScanCallback;)V",
        "hookBleStartScanFilters", kCbSig, "backupBleStartScanFilters", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/net/wifi/WifiManager", "getConfiguredNetworks", "()Ljava/util/List;",
        "hookWifiGetConfiguredNetworks", kCbSig, "backupWifiGetConfiguredNetworks", false, false, true);
    hook_one(env, hooker_obj, hooker_class,
        "android/telephony/SubscriptionManager", "getActiveSubscriptionInfoList", "()Ljava/util/List;",
        "hookGetActiveSubscriptionInfoList", kCbSig, "backupGetActiveSubscriptionInfoList", false, false, true);

    hook_one(env, hooker_obj, hooker_class,
        "android/net/wifi/WifiInfo", "getSSID",
        "()Ljava/lang/String;",
        "hookWifiGetSSID", kCbSig, "backupWifiGetSSID", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/net/wifi/WifiInfo", "getBSSID",
        "()Ljava/lang/String;",
        "hookWifiGetBSSID", kCbSig, "backupWifiGetBSSID", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "sendBroadcast",
        "(Landroid/content/Intent;)V",
        "hookSendBroadcast", kCbSig, "backupSendBroadcast", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "sendOrderedBroadcast",
        "(Landroid/content/Intent;Ljava/lang/String;)V",
        "hookSendOrderedBroadcast", kCbSig, "backupSendOrderedBroadcast", false);

    // 关联启动：跨应用 startService / bindService（ContextWrapper，平台类）
    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "startService",
        "(Landroid/content/Intent;)Landroid/content/ComponentName;",
        "hookContextStartService", kCbSig, "backupContextStartService", false);
    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "bindService",
        "(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z",
        "hookContextBindService", kCbSig, "backupContextBindService", false);
    // 自启动：JobScheduler.schedule —— 具体实现类 JobSchedulerImpl（抽象 JobScheduler 无法挂）；
    // 跨版本类名可能不同，optional=true，未命中即 no-op。
    hook_one(env, hooker_obj, hooker_class,
        "android/app/JobSchedulerImpl", "schedule",
        "(Landroid/app/job/JobInfo;)I",
        "hookJobSchedulerSchedule", kCbSig, "backupJobSchedulerSchedule", false, false, true);

    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "checkPermission",
        "(Ljava/lang/String;II)I",
        "hookContextCheckPermission", kCbSig, "backupContextCheckPermission", false);

    // ContextCompat.checkSelfPermission — static, use app classloader
    hook_one(env, hooker_obj, hooker_class,
        "androidx/core/content/ContextCompat", "checkSelfPermission",
        "(Landroid/content/Context;Ljava/lang/String;)I",
        "hookContextCompatCheckSelfPermission", kCbSig,
        "backupContextCompatCheckSelfPermission", true, true);

    // A.2: PackageManager.checkPermission(permName, pkgName) — concrete impl is
    // android.app.ApplicationPackageManager (PackageManager is abstract). Probes whether a
    // package holds a permission; reported unconditionally under "PackageManager.checkPermission".
    hook_one(env, hooker_obj, hooker_class,
        "android/app/ApplicationPackageManager", "checkPermission",
        "(Ljava/lang/String;Ljava/lang/String;)I",
        "hookPackageManagerCheckPermission", kCbSig,
        "backupPackageManagerCheckPermission", false, true, true);

    // A.3: Health Connect readRecords — app-bundled AndroidX lib (use_app_cl), Android 14+.
    // readRecords is a suspend fn → signature carries kotlin.coroutines.Continuation and returns
    // Object. The concrete impl class differs by androidx version; register both as optional so
    // whichever the app bundles gets hooked (an app bundles at most one).
    hook_one(env, hooker_obj, hooker_class,
        "androidx/health/connect/client/impl/HealthConnectClientImpl", "readRecords",
        "(Landroidx/health/connect/client/request/ReadRecordsRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "hookHealthConnectReadRecords", kCbSig,
        "backupHealthConnectReadRecords", false, true, true);
    hook_one(env, hooker_obj, hooker_class,
        "androidx/health/connect/client/impl/HealthConnectClientUpsideDownImpl", "readRecords",
        "(Landroidx/health/connect/client/request/ReadRecordsRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "hookHealthConnectReadRecords", kCbSig,
        "backupHealthConnectReadRecords", false, true, true);

    // getSystemService filtered on "media_projection" only
    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContextWrapper", "getSystemService",
        "(Ljava/lang/String;)Ljava/lang/Object;",
        "hookGetSystemService", kCbSig, "backupGetSystemService", false);

    // 实际录屏：MediaProjection.createVirtualDisplay（8参公有重载，开始抓帧）。归 screen。
    hook_one(env, hooker_obj, hooker_class,
        "android/media/projection/MediaProjection", "createVirtualDisplay",
        "(Ljava/lang/String;IIIILandroid/view/Surface;Landroid/hardware/display/VirtualDisplay$Callback;Landroid/os/Handler;)Landroid/hardware/display/VirtualDisplay;",
        "hookCreateVirtualDisplay", kCbSig, "backupCreateVirtualDisplay", false, false, true);
    // 申请录屏授权：MediaProjectionManager.createScreenCaptureIntent()。按"申请→permissions"归 permissions。
    hook_one(env, hooker_obj, hooker_class,
        "android/media/projection/MediaProjectionManager", "createScreenCaptureIntent",
        "()Landroid/content/Intent;",
        "hookCreateScreenCaptureIntent", kCbSig, "backupCreateScreenCaptureIntent", false, false, true);

    // 无障碍·主动读屏：AccessibilityService.getRootInActiveWindow()（基类具体方法，子类继承→挂基类即全覆盖）。
    // 归 accessibility；可被循环调用，agent 侧 dedupFlags(accessibility) 500ms 限频。
    hook_one(env, hooker_obj, hooker_class,
        "android/accessibilityservice/AccessibilityService", "getRootInActiveWindow",
        "()Landroid/view/accessibility/AccessibilityNodeInfo;",
        "hookGetRootInActiveWindow", kCbSig, "backupGetRootInActiveWindow", false, false, true);

    // 无障碍·被动事件文本：AccessibilityEvent.getText()（具体方法，替代难挂的抽象 onAccessibilityEvent）。
    // 取系统推送事件文本(他应用输入/界面变化、近似键盘记录)；高频→agent dedupFlags(accessibility) 500ms 限频。
    hook_one(env, hooker_obj, hooker_class,
        "android/view/accessibility/AccessibilityEvent", "getText",
        "()Ljava/util/List;",
        "hookAccessibilityEventGetText", kCbSig, "backupAccessibilityEventGetText", false, false, true);

    // Third-party location SDKs — optional
    hook_one(env, hooker_obj, hooker_class,
        "com/baidu/location/LocationClient", "start", "()V",
        "hookBaiduLocationStart", kCbSig, "backupBaiduLocationStart", false, true);

    hook_one(env, hooker_obj, hooker_class,
        "com/amap/api/location/AMapLocationClient", "startLocation", "()V",
        "hookAmapLocationStart", kCbSig, "backupAmapLocationStart", false, true);

    // Phase 9: FileInputStream / FileOutputStream constructors (external storage filter in Java)
    hook_one(env, hooker_obj, hooker_class,
        "java/io/FileInputStream", "<init>", "(Ljava/lang/String;)V",
        "hookFileInputStreamStr", kCbSig, "backupFileInputStreamStr", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/io/FileInputStream", "<init>", "(Ljava/io/File;)V",
        "hookFileInputStreamFile", kCbSig, "backupFileInputStreamFile", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/io/FileOutputStream", "<init>", "(Ljava/lang/String;)V",
        "hookFileOutputStreamStr", kCbSig, "backupFileOutputStreamStr", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/io/FileOutputStream", "<init>", "(Ljava/lang/String;Z)V",
        "hookFileOutputStreamStrAppend", kCbSig, "backupFileOutputStreamStrAppend", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/io/FileOutputStream", "<init>", "(Ljava/io/File;)V",
        "hookFileOutputStreamFile", kCbSig, "backupFileOutputStreamFile", false);

    hook_one(env, hooker_obj, hooker_class,
        "java/io/FileOutputStream", "<init>", "(Ljava/io/File;Z)V",
        "hookFileOutputStreamFileAppend", kCbSig, "backupFileOutputStreamFileAppend", false);

    // TencentLocationManager — optional
    hook_one(env, hooker_obj, hooker_class,
        "com/tencent/map/geolocation/TencentLocationManager", "requestLocationUpdates",
        "(Lcom/tencent/map/geolocation/TencentLocationRequest;Lcom/tencent/map/geolocation/TencentLocationListener;)I",
        "hookTencentLocationStart", kCbSig, "backupTencentLocationStart", false, true);

    // Phase 11: WebView privacy policy capture via title recognition
    // loadUrl: store WebView→URL mapping (unconditional, no keyword filter)
    hook_one(env, hooker_obj, hooker_class,
        "android/webkit/WebView", "loadUrl", "(Ljava/lang/String;)V",
        "hookWebViewLoadUrl", kCbSig, "backupWebViewLoadUrl", false,
        false, true); // optional: WebView class may not be loaded early

    // onReceivedTitle: fires when HTML <title> is parsed; check title keywords
    // to identify privacy policy pages and emit webview_privacy_url event.
    hook_one(env, hooker_obj, hooker_class,
        "android/webkit/WebChromeClient", "onReceivedTitle",
        "(Landroid/webkit/WebView;Ljava/lang/String;)V",
        "hookOnReceivedTitle", kCbSig, "backupWebChromeClientOnReceivedTitle", false,
        false, true); // optional

    // TBS X5 WebView equivalents — loaded via app classloader (use_app_cl=true).
    // Some apps embed Tencent TBS SDK which replaces system WebView entirely.
    hook_one(env, hooker_obj, hooker_class,
        "com/tencent/smtt/sdk/WebView", "loadUrl", "(Ljava/lang/String;)V",
        "hookTbsWebViewLoadUrl", kCbSig, "backupTbsWebViewLoadUrl", false,
        true, true); // use_app_cl=true, optional

    hook_one(env, hooker_obj, hooker_class,
        "com/tencent/smtt/sdk/WebChromeClient", "onReceivedTitle",
        "(Lcom/tencent/smtt/sdk/WebView;Ljava/lang/String;)V",
        "hookTbsOnReceivedTitle", kCbSig, "backupTbsWebChromeClientOnReceivedTitle", false,
        true, true); // use_app_cl=true, optional

    // Phase 12: ClassLoader.loadClass — collect loaded third-party class names for SDK detection.
    // Hooked on the base ClassLoader so all subclass loaders (PathClassLoader, DexClassLoader, etc.)
    // dispatch through our trampoline. Batching and system-package filtering are done in Java.
    hook_one(env, hooker_obj, hooker_class,
        "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;",
        "hookClassLoaderLoadClass", kCbSig, "backupClassLoaderLoadClass", false);

    LOGI("hooks: device id hooks installed");
}
