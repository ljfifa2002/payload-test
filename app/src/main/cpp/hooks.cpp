#include "hooks.h"
#include <jni.h>
#include <android/log.h>
#include <functional>
#include <string>
#include <lsplant.hpp>

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

// Load hooker.dex from /data/local/tmp, return HookerBridge class or nullptr.
static jclass load_hooker_class(JNIEnv* env) {
    // Use DexClassLoader via JNI reflection
    jclass cl_class = env->FindClass("dalvik/system/DexClassLoader");
    if (check_exception(env, "FindClass DexClassLoader") || cl_class == nullptr) return nullptr;

    jmethodID cl_ctor = env->GetMethodID(cl_class, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (check_exception(env, "GetMethodID DexClassLoader.<init>") || cl_ctor == nullptr) return nullptr;

    // Parent classloader: current thread's context classloader
    jclass thread_class = env->FindClass("java/lang/Thread");
    jmethodID current_thread = env->GetStaticMethodID(thread_class, "currentThread", "()Ljava/lang/Thread;");
    jmethodID get_context_cl = env->GetMethodID(thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    jobject cur_thread = env->CallStaticObjectMethod(thread_class, current_thread);
    jobject parent_cl = env->CallObjectMethod(cur_thread, get_context_cl);
    if (check_exception(env, "getContextClassLoader")) parent_cl = nullptr;

    // Save for find_app_class (OkHttp3 etc.)
    if (parent_cl && !g_app_cl) g_app_cl = env->NewGlobalRef(parent_cl);

    jstring dex_path = env->NewStringUTF("/data/local/tmp/hooker.dex");
    // optimizedDirectory is ignored on API 26+; use null
    jobject dex_cl = env->NewObject(cl_class, cl_ctor,
        dex_path, nullptr, nullptr, parent_cl);
    if (check_exception(env, "new DexClassLoader") || dex_cl == nullptr) {
        LOGE("hooks: DexClassLoader construction failed");
        return nullptr;
    }

    // classLoader.loadClass("com.pecker.payload.HookerBridge")
    jmethodID load_class = env->GetMethodID(cl_class, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;");
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
                     bool use_app_cl = false) {
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
            LOGE("hooks: GetMethodID failed: %s %s", target_method_name, target_sig);
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

    // Keep hooker alive for the lifetime of the process
    jobject hooker_global = env->NewGlobalRef(hooker_obj);
    (void)hooker_global;

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

    // Phase 4: sensitive data
    hook_one(env, hooker_obj, hooker_class,
        "android/content/ContentResolver", "query",
        "(Landroid/net/Uri;[Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/database/Cursor;",
        "hookContentResolverQuery", kCbSig, "backupContentResolverQuery", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/hardware/camera2/CameraManager", "openCamera",
        "(Ljava/lang/String;Landroid/hardware/camera2/CameraDevice$StateCallback;Landroid/os/Handler;)V",
        "hookCameraManagerOpenCamera", kCbSig, "backupCameraManagerOpenCamera", false);

    hook_one(env, hooker_obj, hooker_class,
        "android/media/MediaRecorder", "setAudioSource", "(I)V",
        "hookMediaRecorderSetAudioSource", kCbSig, "backupMediaRecorderSetAudioSource", false);

    // Phase 5: network
    hook_one(env, hooker_obj, hooker_class,
        "java/net/URL", "openConnection", "()Ljava/net/URLConnection;",
        "hookUrlOpenConnection", kCbSig, "backupUrlOpenConnection", false);

    // OkHttp3 — optional, only present in apps that bundle it
    hook_one(env, hooker_obj, hooker_class,
        "okhttp3/OkHttpClient", "newCall", "(Lokhttp3/Request;)Lokhttp3/Call;",
        "hookOkHttpNewCall", kCbSig, "backupOkHttpNewCall", false, true);

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

    LOGI("hooks: device id hooks installed");
}
