package com.pecker.payload;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

public class HookerBridge {

    private static final String TAG = "payload";

    // Abstract Unix domain socket server for adb forward channel.
    // Binds on class load (before any hook fires), so pecker-agent can
    // connect as soon as adb forward is set up — no retry delay needed.
    //
    // adb forward equivalent: adb forward tcp:PORT localabstract:pecker
    //
    // Layer-2 process filter (Java side):
    // By the time this static initializer runs, android_os_Process_setArgV0
    // has already executed and ActivityThread.currentProcessName() returns the
    // correct final process name.  For WeChat mini-program support, Ninjector
    // injects payload into all com.tencent.mm:* sub-processes via the zygote
    // hook, but we must only bind the socket in appbrand containers.
    private static final class SocketChannel {
        private static volatile OutputStream activeOut = null;
        private static final Object LOCK = new Object();

        static {
            // Java-layer process name guard (Method B / Layer 2).
            // Works reliably here because class loading happens after
            // android_os_Process_setArgV0 updates the process name.
            // The C++ constructor's env-var check (Layer 1) handles the early
            // gate; this is a belt-and-suspenders safety net.
            String procName = currentProcessName();

            // Each appbrand process gets its own socket name to avoid the bind
            // race when WeChat pre-warms appbrand0 and appbrand1 simultaneously.
            //   com.tencent.mm:appbrand0 → @pecker_appbrand0
            //   com.tencent.mm:appbrand1 → @pecker_appbrand1
            //   APK tasks (any other process)  → @pecker  (unchanged)
            final String socketName;
            if (procName != null && procName.contains(":appbrand")) {
                socketName = "pecker_" + procName.substring(procName.lastIndexOf(':') + 1);
            } else {
                socketName = "pecker";
            }

            if (procName != null
                    && procName.startsWith("com.tencent.mm")
                    && !procName.contains(":appbrand")) {
                // WeChat non-appbrand process (main, push, sandbox, etc.) —
                // do not bind the socket; leave data collection to the appbrand
                // container that will be forked when the user opens a mini-program.
                Log.i(TAG, "socket_channel: skipping non-appbrand WeChat process: " + procName);
                // Static initializer exits without starting the server thread.
                // send() will be a no-op because activeOut stays null.
            } else {
                Thread t = new Thread(() -> {
                    try (LocalServerSocket srv = new LocalServerSocket(socketName)) {
                        Log.i(TAG, "socket_channel: listening @" + socketName
                                + (procName != null ? " proc=" + procName : ""));
                        while (true) {
                            LocalSocket conn = srv.accept();
                            Log.i(TAG, "socket_channel: client connected");
                            synchronized (LOCK) { activeOut = conn.getOutputStream(); }
                            // Block until client closes — signals task end.
                            try { conn.getInputStream().read(); } catch (Exception ignored) {}
                            synchronized (LOCK) {
                                if (activeOut == conn.getOutputStream()) activeOut = null;
                            }
                            Log.i(TAG, "socket_channel: client disconnected");
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "socket_channel: fatal: " + e);
                    }
                }, "pecker-socket");
                t.setDaemon(true);
                t.start();
            }
        }

        // Returns the current process name using ActivityThread, falling back to
        // reading /proc/self/cmdline if the reflection call fails.
        private static String currentProcessName() {
            try {
                Class<?> at = Class.forName("android.app.ActivityThread");
                Method m = at.getDeclaredMethod("currentProcessName");
                m.setAccessible(true);
                return (String) m.invoke(null);
            } catch (Exception ignored) {}
            // Fallback: /proc/self/cmdline (null-terminated, may have trailing nulls)
            try {
                java.io.RandomAccessFile f = new java.io.RandomAccessFile("/proc/self/cmdline", "r");
                byte[] buf = new byte[256];
                int n = f.read(buf);
                f.close();
                if (n > 0) {
                    // cmdline is null-terminated; trim trailing null bytes
                    int end = 0;
                    while (end < n && buf[end] != 0) end++;
                    return new String(buf, 0, end, StandardCharsets.UTF_8);
                }
            } catch (Exception ignored) {}
            return null;
        }

        static void send(String line) {
            OutputStream out;
            synchronized (LOCK) { out = activeOut; }
            if (out == null) return;
            try {
                out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            } catch (Exception e) {
                synchronized (LOCK) { activeOut = null; }
            }
        }
    }

    public Method backupGetDeviceId;
    public Method backupGetSubscriberId;
    public Method backupGetSimSerialNumber;
    public Method backupGetLine1Number;
    public Method backupSettingsSecureGetString;
    public Method backupWifiGetMacAddress;
    public Method backupNetworkInterfaceGetHardwareAddress;
    public Method backupActivityOnCreate;
    public Method backupGetLastKnownLocation;
    public Method backupLocationGetLatitude;
    public Method backupLocationGetLongitude;
    public Method backupRequestLocationUpdatesStr;
    public Method backupRequestLocationUpdatesStrLooper;
    public Method backupRequestLocationUpdatesCriteria;
    public Method backupRequestLocationUpdatesCriteriaLooper;
    // Phase 4
    public Method backupContentResolverQuery;
    public Method backupCameraManagerOpenCamera;
    // Phase 4b: clipboard / camera / audio / process / shell / navigation
    public Method backupClipboardGetPrimaryClip;
    public Method backupCameraOpen0;
    public Method backupCameraOpenInt;
    public Method backupAudioRecordStartRecording;
    public Method backupGetRunningAppProcesses;
    public Method backupRuntimeExecStr;
    public Method backupRuntimeExecArray;
    public Method backupProcessBuilderStart;
    public Method backupStartActivity;
    public Method backupStartActivityForResult;
    public Method backupMediaRecorderStart;
    public Method backupBroadcastReceiverOnReceive;
    // Phase 5
    public Method backupUrlOpenConnection;
    public Method backupOkHttpNewCall;
    public Method backupRealCallExecute;
    public Method backupRealCallEnqueue;
    public Method backupVolleyDeliverResponse;
    public Method backupHttpURLConnectionGetResponseCode;
    public Method backupHttpURLConnectionGetOutputStream;
    public Method backupHttpURLConnectionGetInputStream;
    public Method backupHttpURLConnectionGetErrorStream;
    // Phase 6: sensors
    // Phase 6b: SSL Pinning bypass
    public Method backupCertificatePinnerCheck;
    public Method backupSslContextInit;
    public Method backupSetDefaultHostnameVerifier;
    public Method backupSensorRegister3;
    public Method backupSensorRegister4Int;
    public Method backupSensorRegister4Handler;
    // Phase 7: permissions
    public Method backupRequestPermissions;
    public Method backupActivityCompatRequestPermissions;
    // Phase 7b: package install
    public Method backupPackageInstallerCommit;
    // Phase 8: cell info, wifi, package list, tasks, broadcast, media projection
    public Method backupGetCellLocation;
    public Method backupGetAllCellInfo;
    public Method backupGetNetworkOperator;
    public Method backupGetNetworkOperatorName;
    public Method backupGetInstalledPackages;
    public Method backupGetInstalledApplications;
    public Method backupGetRunningTasks;
    public Method backupWifiGetSSID;
    public Method backupWifiGetBSSID;
    public Method backupSendBroadcast;
    public Method backupSendOrderedBroadcast;
    public Method backupContextCheckPermission;
    public Method backupContextCompatCheckSelfPermission;
    public Method backupGetSystemService;
    // Phase 8: third-party location SDKs (optional)
    public Method backupBaiduLocationStart;
    public Method backupAmapLocationStart;
    // Phase 9: file stream constructors, tencent location
    public Method backupFileInputStreamStr;
    public Method backupFileInputStreamFile;
    public Method backupFileOutputStreamStr;
    public Method backupFileOutputStreamStrAppend;
    public Method backupFileOutputStreamFile;
    public Method backupFileOutputStreamFileAppend;
    public Method backupTencentLocationStart;

    // LSPlant 6.4 calls the hooker as a virtual (instance) method:
    //   hookerInstance.hookXxx(Object[] args)
    // For instance targets: args = [thiz, param1, param2, ...]
    // For static targets:   args = [param1, param2, ...]
    // 'this' is the HookerBridge instance.

    // Set by install_device_id_hooks() in hooks.cpp so that installMiniHooks() can
    // reach the hooker object when called from the delayed Phase 10 thread.
    static HookerBridge sInstance;

    // Bridge into LSPlant from Java: hooks targetMethod via LSPlant and returns
    // the backup Method.  Implemented in libpayload.so and registered with
    // RegisterNatives during install_device_id_hooks().
    static native Object hookNative(Object targetMethod, Object hookerObj, Object callbackMethod);
    // Force a method's JIT-compiled callers back to interpreter so LSPlant's
    // ArtMethod entry_point dispatch fires correctly.
    static native void deoptimizeNative(Object method);

    private String safeInvoke(Method m, Object thiz, Object... params) {
        try { return (String) m.invoke(thiz, params); }
        catch (Exception e) { Log.e(TAG, "backup invoke failed: " + e); return null; }
    }

    private byte[] safeInvokeBytes(Method m, Object thiz) {
        try { return (byte[]) m.invoke(thiz); }
        catch (Exception e) { Log.e(TAG, "backup invoke bytes failed: " + e); return null; }
    }

    private Object safeInvokeObject(Method m, Object thiz, Object... params) {
        try { return m.invoke(thiz, params); }
        catch (Exception e) { Log.e(TAG, "backup invoke object failed: " + e); return null; }
    }

    private static String captureStack() {
        StackTraceElement[] frames = Thread.currentThread().getStackTrace();
        StringBuilder sb = new StringBuilder();
        int kept = 0;
        for (StackTraceElement f : frames) {
            String cls = f.getClassName();
            // Skip VM internals, reflection, our own bridge frames, and LSPlant trampoline frames
            if (cls.startsWith("com.pecker.payload.")
                    || cls.startsWith("LSPHooker_")
                    || cls.startsWith("java.lang.Thread")
                    || cls.startsWith("java.lang.reflect.")
                    || cls.startsWith("sun.reflect.")
                    || cls.startsWith("dalvik.system.")
                    || cls.equals("de.robv.android.xposed.XposedBridge")) {
                continue;
            }
            if (kept > 0) sb.append('|');
            sb.append(cls).append('.').append(f.getMethodName())
              .append(':').append(f.getLineNumber());
            if (++kept == 12) break;
        }
        if (kept == 0) {
            StringBuilder diag = new StringBuilder("DIAG_EMPTY_STACK:");
            for (StackTraceElement f : frames) {
                diag.append(' ').append(f.getClassName()).append('.').append(f.getMethodName());
            }
            Log.w(TAG, diag.toString());
        }
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) { sb.append(String.format("\\u%04x", (int) c)); }
                    else           { sb.append(c); }
            }
        }
        return sb.toString();
    }

    private static void log(String method, String data) {
        String stack = captureStack();
        String json = "{\"type\":\"behavior\",\"method\":\"" + method
                + "\",\"data\":\"" + jsonEscape(data)
                + "\",\"stack\":\"" + jsonEscape(stack)
                + "\",\"timestamp\":" + System.currentTimeMillis() + "}";
        Log.i(TAG, json);
        SocketChannel.send(json);
    }

    private static void logNetwork(String httpMethod, String url, int statusCode) {
        logNetworkFull(httpMethod, url, statusCode, null, null);
    }

    // Public so JNI (ssl_hooks.cpp) can call it via reflection-free static dispatch.
    public static void jniLogNetwork(String httpMethod, String url, int statusCode,
                                     String reqBody, String respBody) {
        logNetworkFull(httpMethod, url, statusCode, reqBody, respBody);
    }

    private static void logNetworkFull(String httpMethod, String url, int statusCode,
                                       String reqBody, String respBody) {
        StringBuilder sb = new StringBuilder("{\"type\":\"network\"")
                .append(",\"method\":\"").append(jsonEscape(httpMethod)).append('"')
                .append(",\"url\":\"").append(jsonEscape(url)).append('"')
                .append(",\"statusCode\":").append(statusCode);
        if (reqBody != null && !reqBody.isEmpty())
            sb.append(",\"requestBody\":\"").append(jsonEscape(reqBody)).append('"');
        if (respBody != null && !respBody.isEmpty())
            sb.append(",\"responseBody\":\"").append(jsonEscape(respBody)).append('"');
        sb.append(",\"timestamp\":").append(System.currentTimeMillis()).append('}');
        String json = sb.toString();
        Log.i(TAG, json);
        SocketChannel.send(json);
    }

    // ---- Instance hook callbacks ([Ljava/lang/Object;)Ljava/lang/Object; ----

    // TelephonyManager.getDeviceId()  instance: args={thiz}
    public Object hookGetDeviceId(Object[] args) {
        Object thiz = args[0];
        String v = backupGetDeviceId != null ? safeInvoke(backupGetDeviceId, thiz) : null;
        log("getDeviceId", v != null ? v : "");
        return v;
    }

    public Object hookGetSubscriberId(Object[] args) {
        Object thiz = args[0];
        String v = backupGetSubscriberId != null ? safeInvoke(backupGetSubscriberId, thiz) : null;
        log("getSubscriberId", v != null ? v : "");
        return v;
    }

    public Object hookGetSimSerialNumber(Object[] args) {
        Object thiz = args[0];
        String v = backupGetSimSerialNumber != null ? safeInvoke(backupGetSimSerialNumber, thiz) : null;
        log("getSimSerialNumber", v != null ? v : "");
        return v;
    }

    public Object hookGetLine1Number(Object[] args) {
        Object thiz = args[0];
        String v = backupGetLine1Number != null ? safeInvoke(backupGetLine1Number, thiz) : null;
        log("getLine1Number", v != null ? v : "");
        return v;
    }

    // Settings.Secure.getString(ContentResolver, String)  static: args={cr, name}
    public Object hookSettingsSecureGetString(Object[] args) {
        Object cr   = args[0];
        String name = (String) args[1];
        String v = backupSettingsSecureGetString != null
                ? safeInvoke(backupSettingsSecureGetString, null, cr, name)
                : null;
        if ("android_id".equals(name)) {
            log("getString_android_id", v != null ? v : "");
        } else if ("bluetooth_address".equals(name)) {
            log("getString_bluetooth_address", v != null ? v : "");
        } else if ("bluetooth_name".equals(name)) {
            log("getString_bluetooth_name", v != null ? v : "");
        }
        return v;
    }

    public Object hookGetMacAddress(Object[] args) {
        Object thiz = args[0];
        String v = backupWifiGetMacAddress != null ? safeInvoke(backupWifiGetMacAddress, thiz) : null;
        log("getMacAddress", v != null ? v : "");
        return v;
    }

    public Object hookGetHardwareAddress(Object[] args) {
        Object thiz = args[0];
        byte[] v = backupNetworkInterfaceGetHardwareAddress != null
                ? safeInvokeBytes(backupNetworkInterfaceGetHardwareAddress, thiz)
                : null;
        if (v != null) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < v.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02x", v[i] & 0xff));
            }
            log("getHardwareAddress", sb.toString());
        }
        return v;
    }

    // Activity.onCreate(Bundle)  instance: args={thiz, bundle}
    public Object hookActivityOnCreate(Object[] args) {
        Object thiz   = args[0];
        Object bundle = args[1];
        // Log the activity class name in unified JSON format
        String activityName = thiz != null ? thiz.getClass().getName() : "?";
        log("Activity.onCreate", activityName);
        if (backupActivityOnCreate != null) {
            try { backupActivityOnCreate.invoke(thiz, bundle); }
            catch (Exception e) { Log.e(TAG, "backup Activity.onCreate failed: " + e); }
        }
        return null;
    }

    // LocationManager.getLastKnownLocation(String provider)  instance: args={thiz, provider}
    public Object hookGetLastKnownLocation(Object[] args) {
        Object thiz     = args[0];
        String provider = (String) args[1];
        Object location = null;
        if (backupGetLastKnownLocation != null) {
            try { location = backupGetLastKnownLocation.invoke(thiz, provider); }
            catch (Exception e) { Log.e(TAG, "backup getLastKnownLocation failed: " + e); }
        }
        if (location != null) {
            try {
                double lat = (Double) location.getClass().getMethod("getLatitude").invoke(location);
                double lon = (Double) location.getClass().getMethod("getLongitude").invoke(location);
                log("LocationManager.getLastKnownLocation", provider + " " + lat + "," + lon);
            } catch (Exception e) {
                log("LocationManager.getLastKnownLocation", provider);
            }
        } else {
            log("LocationManager.getLastKnownLocation", provider);
        }
        return location;
    }

    // Location.getLatitude()  instance: args={thiz}
    public Object hookLocationGetLatitude(Object[] args) {
        Object thiz = args[0];
        Double v = null;
        if (backupLocationGetLatitude != null) {
            try { v = (Double) backupLocationGetLatitude.invoke(thiz); }
            catch (Exception e) { Log.e(TAG, "backup getLatitude failed: " + e); }
        }
        log("Location.getLatitude", v != null ? v.toString() : "0.0");
        return v != null ? v : 0.0;
    }

    // Location.getLongitude()  instance: args={thiz}
    public Object hookLocationGetLongitude(Object[] args) {
        Object thiz = args[0];
        Double v = null;
        if (backupLocationGetLongitude != null) {
            try { v = (Double) backupLocationGetLongitude.invoke(thiz); }
            catch (Exception e) { Log.e(TAG, "backup getLongitude failed: " + e); }
        }
        log("Location.getLongitude", v != null ? v.toString() : "0.0");
        return v != null ? v : 0.0;
    }

    // ---- Phase 3: requestLocationUpdates (4 overloads) ----

    private static String fmtLocationUpdate(String providerOrCriteria, Object[] args, int listenerIdx) {
        long minTime = args[listenerIdx - 2] != null ? ((Number) args[listenerIdx - 2]).longValue() : -1;
        float minDist = args[listenerIdx - 1] != null ? ((Number) args[listenerIdx - 1]).floatValue() : -1;
        return providerOrCriteria + " minTime=" + minTime + "ms minDist=" + minDist + "m";
    }

    // requestLocationUpdates(String, long, float, LocationListener)  instance
    // args={thiz, provider, minTime, minDistance, listener}
    public Object hookRequestLocationUpdatesStr(Object[] args) {
        String provider = args[1] != null ? args[1].toString() : "?";
        log("LocationManager.requestLocationUpdates", fmtLocationUpdate(provider, args, 4));
        if (backupRequestLocationUpdatesStr != null)
            safeInvokeObject(backupRequestLocationUpdatesStr, args[0], args[1], args[2], args[3], args[4]);
        return null;
    }

    // requestLocationUpdates(String, long, float, LocationListener, Looper)  instance
    // args={thiz, provider, minTime, minDistance, listener, looper}
    public Object hookRequestLocationUpdatesStrLooper(Object[] args) {
        String provider = args[1] != null ? args[1].toString() : "?";
        log("LocationManager.requestLocationUpdates", fmtLocationUpdate(provider, args, 4));
        if (backupRequestLocationUpdatesStrLooper != null)
            safeInvokeObject(backupRequestLocationUpdatesStrLooper, args[0], args[1], args[2], args[3], args[4], args[5]);
        return null;
    }

    // requestLocationUpdates(Criteria, long, float, LocationListener)  instance
    // args={thiz, criteria, minTime, minDistance, listener}
    public Object hookRequestLocationUpdatesCriteria(Object[] args) {
        String criteria = args[1] != null ? criteriaDesc(args[1]) : "?";
        log("LocationManager.requestLocationUpdates", fmtLocationUpdate(criteria, args, 4));
        if (backupRequestLocationUpdatesCriteria != null)
            safeInvokeObject(backupRequestLocationUpdatesCriteria, args[0], args[1], args[2], args[3], args[4]);
        return null;
    }

    // requestLocationUpdates(Criteria, long, float, LocationListener, Looper)  instance
    // args={thiz, criteria, minTime, minDistance, listener, looper}
    public Object hookRequestLocationUpdatesCriteriaLooper(Object[] args) {
        String criteria = args[1] != null ? criteriaDesc(args[1]) : "?";
        log("LocationManager.requestLocationUpdates", fmtLocationUpdate(criteria, args, 4));
        if (backupRequestLocationUpdatesCriteriaLooper != null)
            safeInvokeObject(backupRequestLocationUpdatesCriteriaLooper, args[0], args[1], args[2], args[3], args[4], args[5]);
        return null;
    }

    private static String criteriaDesc(Object criteria) {
        try {
            int accuracy = (Integer) criteria.getClass().getMethod("getAccuracy").invoke(criteria);
            // Criteria.ACCURACY_FINE=1, ACCURACY_COARSE=2
            return "Criteria(accuracy=" + (accuracy == 1 ? "FINE" : accuracy == 2 ? "COARSE" : accuracy) + ")";
        } catch (Exception e) { return "Criteria"; }
    }



    // ContentResolver.query(Uri, String[], Bundle, CancellationSignal)  instance
    // args={thiz, uri, projection, queryArgs, cancellationSignal}
    public Object hookContentResolverQuery(Object[] args) {
        Object thiz   = args[0];
        Object uri    = args[1];
        String uriStr = uri != null ? uri.toString() : "";
        Object cursor = backupContentResolverQuery != null
                ? safeInvokeObject(backupContentResolverQuery, thiz, args[1], args[2], args[3], args[4])
                : null;
        // Route to the same per-category keys as frida (hook.js)
        String key = null;
        if (uriStr.contains("contact"))                                      key = "ContentResolver.query_contacts";
        else if (uriStr.contains("sms") || uriStr.contains("mms"))          key = "ContentResolver.query_sms";
        else if (uriStr.contains("call_log") || uriStr.contains("calls"))   key = "ContentResolver.query_call_log";
        else if (uriStr.contains("calendar"))                                key = "ContentResolver.query_calendar";
        if (key != null) log(key, uriStr);
        return cursor;
    }

    // CameraManager.openCamera(String, StateCallback, Handler)  instance: args={thiz, cameraId, cb, handler}
    public Object hookCameraManagerOpenCamera(Object[] args) {
        String cameraId = args[1] != null ? args[1].toString() : "";
        log("Camera2.openCamera", cameraId);
        if (backupCameraManagerOpenCamera != null)
            safeInvokeObject(backupCameraManagerOpenCamera, args[0], args[1], args[2], args[3]);
        return null;
    }

    // ---- Phase 5: network ----

    // URL.openConnection()  instance: args={thiz}
    public Object hookUrlOpenConnection(Object[] args) {
        String url = args[0] != null ? args[0].toString() : "";
        log("URL.openConnection", url);
        return backupUrlOpenConnection != null
                ? safeInvokeObject(backupUrlOpenConnection, args[0])
                : null;
    }

    // OkHttpClient.newCall(Request)  instance: args={thiz, request}
    public Object hookOkHttpNewCall(Object[] args) {
        try {
            String url = args[1].getClass().getMethod("url").invoke(args[1]).toString();
            log("OkHttpClient.newCall", url);
        } catch (Exception e) {
            log("OkHttpClient.newCall", "?");
        }
        return backupOkHttpNewCall != null
                ? safeInvokeObject(backupOkHttpNewCall, args[0], args[1])
                : null;
    }

    // ---- Phase 4b: clipboard / camera / audio / process / shell / navigation ----

    // ClipboardManager.getPrimaryClip()  instance: args={thiz}
    public Object hookClipboardGetPrimaryClip(Object[] args) {
        Object clip = backupClipboardGetPrimaryClip != null
                ? safeInvokeObject(backupClipboardGetPrimaryClip, args[0])
                : null;
        String text = "";
        if (clip != null) {
            try {
                int count = (Integer) clip.getClass().getMethod("getItemCount").invoke(clip);
                if (count > 0) {
                    Object item = clip.getClass().getMethod("getItemAt", int.class).invoke(clip, 0);
                    Object cs = item.getClass().getMethod("getText").invoke(item);
                    text = cs != null ? cs.toString() : "";
                }
            } catch (Exception ignored) {}
        }
        log("ClipboardManager.getPrimaryClip", text);
        log("ClipboardManager.getText", text);
        return clip;
    }

    // Camera.open()  static: args={}
    public Object hookCameraOpen0(Object[] args) {
        log("Camera.open", "default");
        return backupCameraOpen0 != null
                ? safeInvokeObject(backupCameraOpen0, null)
                : null;
    }

    // Camera.open(int cameraId)  static: args={cameraId}
    public Object hookCameraOpenInt(Object[] args) {
        String id = args[0] != null ? args[0].toString() : "?";
        log("Camera.open", id);
        return backupCameraOpenInt != null
                ? safeInvokeObject(backupCameraOpenInt, null, args[0])
                : null;
    }

    // AudioRecord.startRecording()  instance: args={thiz}
    public Object hookAudioRecordStartRecording(Object[] args) {
        log("AudioRecord.startRecording", "");
        if (backupAudioRecordStartRecording != null)
            safeInvokeObject(backupAudioRecordStartRecording, args[0]);
        return null;
    }

    // ActivityManager.getRunningAppProcesses()  instance: args={thiz}
    public Object hookGetRunningAppProcesses(Object[] args) {
        Object list = backupGetRunningAppProcesses != null
                ? safeInvokeObject(backupGetRunningAppProcesses, args[0])
                : null;
        // xweb (Chromium) and WeChat telemetry/matrix call this for internal process detection,
        // not as a privacy-sensitive behavior — skip to avoid noise in mini-program tasks.
        StackTraceElement[] frames = Thread.currentThread().getStackTrace();
        for (int i = 0; i < Math.min(frames.length, 20); i++) {
            String c = frames[i].getClassName();
            if (c.startsWith("com.tencent.xweb")
                    || c.startsWith("org.chromium")
                    || c.startsWith("com.tencent.matrix")) {
                return list;
            }
        }
        log("ActivityManager.getRunningAppProcesses", list != null ? "count=" + getListSize(list) : "null");
        return list;
    }

    private static int getListSize(Object list) {
        try { return (Integer) list.getClass().getMethod("size").invoke(list); }
        catch (Exception e) { return -1; }
    }

    // Runtime.exec(String)  instance: args={thiz, cmd}
    public Object hookRuntimeExecStr(Object[] args) {
        String cmd = args[1] != null ? args[1].toString() : "";
        log("Runtime.exec", cmd);
        return backupRuntimeExecStr != null
                ? safeInvokeObject(backupRuntimeExecStr, args[0], args[1])
                : null;
    }

    // Runtime.exec(String[])  instance: args={thiz, cmdArray}
    public Object hookRuntimeExecArray(Object[] args) {
        String cmd = "";
        if (args[1] instanceof Object[]) {
            StringBuilder sb = new StringBuilder();
            for (Object o : (Object[]) args[1]) {
                if (sb.length() > 0) sb.append(' ');
                sb.append(o != null ? o.toString() : "");
            }
            cmd = sb.toString();
        }
        log("Runtime.exec", cmd);
        return backupRuntimeExecArray != null
                ? safeInvokeObject(backupRuntimeExecArray, args[0], args[1])
                : null;
    }

    // ProcessBuilder.start()  instance: args={thiz}
    public Object hookProcessBuilderStart(Object[] args) {
        String cmd = "";
        try {
            Object cmdList = args[0].getClass().getMethod("command").invoke(args[0]);
            cmd = cmdList != null ? cmdList.toString() : "";
        } catch (Exception ignored) {}
        log("ProcessBuilder.start", cmd);
        return backupProcessBuilderStart != null
                ? safeInvokeObject(backupProcessBuilderStart, args[0])
                : null;
    }

    // Activity.startActivity(Intent)  instance: args={thiz, intent}
    public Object hookStartActivity(Object[] args) {
        String targetPkg = getIntentPackage(args[1]);
        String currentPkg = getCurrentPackage(args[0]);
        String key = (targetPkg != null && !targetPkg.isEmpty() && !targetPkg.equals(currentPkg))
                ? "Activity.startActivity_other" : "Activity.startActivity_self";
        log(key, targetPkg != null ? targetPkg : "");
        if (backupStartActivity != null)
            safeInvokeObject(backupStartActivity, args[0], args[1]);
        return null;
    }

    // Activity.startActivityForResult(Intent, int)  instance: args={thiz, intent, requestCode}
    public Object hookStartActivityForResult(Object[] args) {
        String targetPkg = getIntentPackage(args[1]);
        String currentPkg = getCurrentPackage(args[0]);
        String key = (targetPkg != null && !targetPkg.isEmpty() && !targetPkg.equals(currentPkg))
                ? "Activity.startActivity_other" : "Activity.startActivity_self";
        log(key, targetPkg != null ? targetPkg : "");
        if (backupStartActivityForResult != null)
            safeInvokeObject(backupStartActivityForResult, args[0], args[1], args[2]);
        return null;
    }

    private static String getIntentPackage(Object intent) {
        if (intent == null) return null;
        try {
            Object component = intent.getClass().getMethod("getComponent").invoke(intent);
            if (component != null)
                return (String) component.getClass().getMethod("getPackageName").invoke(component);
        } catch (Exception ignored) {}
        return null;
    }

    private static String getCurrentPackage(Object context) {
        if (context == null) return null;
        try {
            return (String) context.getClass().getMethod("getPackageName").invoke(context);
        } catch (Exception ignored) {}
        return null;
    }

    // MediaRecorder.start()  instance: args={thiz}
    public Object hookMediaRecorderStart(Object[] args) {
        log("MediaRecorder.start_audio", "");
        if (backupMediaRecorderStart != null)
            safeInvokeObject(backupMediaRecorderStart, args[0]);
        return null;
    }

    // BroadcastReceiver.onReceive(Context, Intent)  instance: args={thiz, context, intent}
    // Note: hooks abstract base — fires only if ART does not bypass via vtable of subclass.
    public Object hookBroadcastReceiverOnReceive(Object[] args) {
        String action = "";
        if (args[2] != null) {
            try { action = (String) args[2].getClass().getMethod("getAction").invoke(args[2]); }
            catch (Exception ignored) {}
        }
        if ("android.intent.action.BOOT_COMPLETED".equals(action) ||
                "android.intent.action.QUICKBOOT_POWERON".equals(action)) {
            log("BroadcastReceiver.onReceive_BOOT", action != null ? action : "");
        }
        if (backupBroadcastReceiverOnReceive != null)
            safeInvokeObject(backupBroadcastReceiverOnReceive, args[0], args[1], args[2]);
        return null;
    }

    // ---- Phase 5b: OkHttp3 RealCall.execute (sync, captures response code) ----

    // RealCall.execute()  instance: args={thiz}
    public Object hookRealCallExecute(Object[] args) {
        // Capture request body before execution (body stream not yet consumed).
        String reqBody = extractOkHttpRequestBody(args[0]);

        Object response = backupRealCallExecute != null
                ? safeInvokeObject(backupRealCallExecute, args[0])
                : null;
        try {
            Object request = args[0].getClass().getMethod("request").invoke(args[0]);
            String url = request.getClass().getMethod("url").invoke(request).toString();
            String httpMethod = (String) request.getClass().getMethod("method").invoke(request);
            int code = response != null
                    ? (Integer) response.getClass().getMethod("code").invoke(response)
                    : -1;
            String respBody = response != null ? peekOkHttpResponseBody(response) : null;
            logNetworkFull(httpMethod != null ? httpMethod : "?", url, code, reqBody, respBody);
        } catch (Exception e) {
            logNetwork("?", "?", -1);
        }
        return response;
    }

    private static final int BODY_PREVIEW = 4096;

    // Reads up to BODY_PREVIEW bytes from an OkHttp RequestBody by writing to a
    // temporary okio.Buffer.  Returns null on any failure (one-shot bodies, etc.).
    private static String extractOkHttpRequestBody(Object realCall) {
        try {
            Object request = realCall.getClass().getMethod("request").invoke(realCall);
            Object body = request.getClass().getMethod("body").invoke(request);
            if (body == null) return null;
            // Check content length — skip bodies > 256KB to avoid OOM
            long len = (Long) body.getClass().getMethod("contentLength").invoke(body);
            if (len > 262144) return null;
            // Use the app's ClassLoader (from realCall) to load okio classes.
            // Class.forName() uses HookerBridge's ClassLoader which cannot see
            // the app's OkHttp/Okio dependency.
            ClassLoader appCL = realCall.getClass().getClassLoader();
            Class<?> bufClass = Class.forName("okio.Buffer", true, appCL);
            Class<?> bufferedSinkClass = Class.forName("okio.BufferedSink", true, appCL);
            Object buf = bufClass.newInstance();
            body.getClass().getMethod("writeTo", bufferedSinkClass).invoke(body, buf);
            long size = (Long) bufClass.getMethod("size").invoke(buf);
            int readLen = (int) Math.min(size, BODY_PREVIEW);
            if (readLen <= 0) return null;
            byte[] bytes = (byte[]) bufClass.getMethod("readByteArray", long.class).invoke(buf, (long) readLen);
            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    // Uses OkHttp's peekBody() to read up to BODY_PREVIEW bytes without consuming the stream.
    private static String peekOkHttpResponseBody(Object response) {
        try {
            Object peeked = response.getClass()
                    .getMethod("peekBody", long.class).invoke(response, (long) BODY_PREVIEW);
            return (String) peeked.getClass().getMethod("string").invoke(peeked);
        } catch (Exception e) {
            return null;
        }
    }

    // RealCall.enqueue(Callback)  instance: args={thiz, callback}
    // Wraps the original Callback in a java.lang.reflect.Proxy to intercept
    // onResponse/onFailure so we can log URL + response code asynchronously.
    public Object hookRealCallEnqueue(Object[] args) {
        Object realCall = args[0];
        Object origCallback = args[1];
        String url;
        String httpMethod;
        String reqBody;
        try {
            Object request = realCall.getClass().getMethod("request").invoke(realCall);
            url = request.getClass().getMethod("url").invoke(request).toString();
            httpMethod = (String) request.getClass().getMethod("method").invoke(request);
            if (httpMethod == null) httpMethod = "?";
        } catch (Exception e) {
            url = "?";
            httpMethod = "?";
        }
        reqBody = extractOkHttpRequestBody(realCall);
        final String capturedUrl = url;
        final String capturedMethod = httpMethod;
        final String capturedReqBody = reqBody;

        // Build a proxy that implements okhttp3.Callback
        Object wrappedCallback = origCallback;
        if (origCallback != null) {
            try {
                Class<?> cls = origCallback.getClass();
                Class<?> callbackIface = null;
                outer:
                for (; cls != null; cls = cls.getSuperclass()) {
                    for (Class<?> iface : cls.getInterfaces()) {
                        if (iface.getName().equals("okhttp3.Callback")) {
                            callbackIface = iface;
                            break outer;
                        }
                    }
                }
                if (callbackIface != null) {
                    final Object finalOrig = origCallback;
                    final Class<?> finalIface = callbackIface;
                    wrappedCallback = java.lang.reflect.Proxy.newProxyInstance(
                        origCallback.getClass().getClassLoader(),
                        new Class<?>[]{ finalIface },
                        (proxy, method, methodArgs) -> {
                            String mname = method.getName();
                            if ("onResponse".equals(mname) && methodArgs != null && methodArgs.length >= 2) {
                                try {
                                    int code = (Integer) methodArgs[1].getClass()
                                            .getMethod("code").invoke(methodArgs[1]);
                                    String respBody = peekOkHttpResponseBody(methodArgs[1]);
                                    logNetworkFull(capturedMethod, capturedUrl, code, capturedReqBody, respBody);
                                } catch (Exception ignored) {
                                    logNetwork(capturedMethod, capturedUrl, -1);
                                }
                            } else if ("onFailure".equals(mname)) {
                                logNetwork(capturedMethod, capturedUrl, -1);
                            }
                            return method.invoke(finalOrig, methodArgs);
                        });
                }
            } catch (Exception e) {
                logNetwork(capturedMethod, capturedUrl, -1);
            }
        }

        if (backupRealCallEnqueue != null)
            safeInvokeObject(backupRealCallEnqueue, realCall, wrappedCallback);
        return null;
    }

    // Volley StringRequest.deliverResponse(String)  instance: args={thiz, response}
    private static final int VOLLEY_PREVIEW = 256;
    private static final String[] VOLLEY_METHODS = {"GET","POST","PUT","DELETE","HEAD","OPTIONS","TRACE","PATCH"};
    public Object hookVolleyDeliverResponse(Object[] args) {
        String volleyUrl = "";
        String volleyMethod = "GET";
        try { volleyUrl = (String) args[0].getClass().getMethod("getUrl").invoke(args[0]); }
        catch (Exception ignored) {}
        try {
            int m = (Integer) args[0].getClass().getMethod("getMethod").invoke(args[0]);
            if (m >= 0 && m < VOLLEY_METHODS.length) volleyMethod = VOLLEY_METHODS[m];
        } catch (Exception ignored) {}
        // deliverResponse is the success path — status code is implicitly 200
        logNetwork(volleyMethod, volleyUrl != null ? volleyUrl : "?", 200);
        if (backupVolleyDeliverResponse != null)
            safeInvokeObject(backupVolleyDeliverResponse, args[0], args[1]);
        return null;
    }

    // ---- HttpURLConnection.getResponseCode — fires after each HTTP request ----

    // ---- HttpURLConnection body capture ----
    //
    // Data flow:
    //   getOutputStream() → CachingOutputStream (buffers request body)
    //   getResponseCode() → stores PendingLog{url, method, code, reqBody}
    //   getInputStream()  → reads response body, completes log, returns SequenceInputStream
    //   getErrorStream()  → same as getInputStream for 4xx/5xx
    //
    // Key: System.identityHashCode(conn) — cheap int, safe with ConcurrentHashMap.
    // Cleaned up when log entry is completed (getInputStream/Error) or when fallback
    // fires in getResponseCode if the connection never delivers a body.

    private static final java.util.concurrent.ConcurrentHashMap<Integer, CachingOutputStream>
            connOutStreams = new java.util.concurrent.ConcurrentHashMap<>();

    private static final java.util.concurrent.ConcurrentHashMap<Integer, String[]>
            connPending = new java.util.concurrent.ConcurrentHashMap<>();
    // connPending value: String[4] = {url, method, statusCode-as-string, reqBody}

    private static class CachingOutputStream extends java.io.OutputStream {
        private final java.io.OutputStream base;
        private final java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        private boolean capped;
        CachingOutputStream(java.io.OutputStream base) { this.base = base; }
        @Override public void write(int b) throws java.io.IOException {
            base.write(b);
            if (!capped) { buf.write(b); if (buf.size() >= BODY_PREVIEW) capped = true; }
        }
        @Override public void write(byte[] b, int off, int len) throws java.io.IOException {
            base.write(b, off, len);
            if (!capped && len > 0) {
                int rem = BODY_PREVIEW - buf.size();
                if (rem > 0) { buf.write(b, off, Math.min(len, rem)); if (buf.size() >= BODY_PREVIEW) capped = true; }
            }
        }
        @Override public void flush() throws java.io.IOException { base.flush(); }
        @Override public void close() throws java.io.IOException { base.close(); }
        String get() {
            if (buf.size() == 0) return null;
            byte[] bytes = buf.toByteArray();
            return isBinaryContent(bytes, bytes.length) ? null
                    : new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    // getOutputStream  instance: args={thiz}
    public Object hookHttpURLConnectionGetOutputStream(Object[] args) {
        Object out = backupHttpURLConnectionGetOutputStream != null
                ? safeInvokeObject(backupHttpURLConnectionGetOutputStream, args[0])
                : null;
        if (out instanceof java.io.OutputStream) {
            CachingOutputStream caching = new CachingOutputStream((java.io.OutputStream) out);
            connOutStreams.put(System.identityHashCode(args[0]), caching);
            return caching;
        }
        return out;
    }

    // java.net.HttpURLConnection.getResponseCode()  instance: args={thiz}
    public Object hookHttpURLConnectionGetResponseCode(Object[] args) {
        Integer result = null;
        if (backupHttpURLConnectionGetResponseCode != null) {
            try { result = (Integer) backupHttpURLConnectionGetResponseCode.invoke(args[0]); }
            catch (Exception e) { Log.e(TAG, "backup getResponseCode failed: " + e); }
        }
        try {
            Object urlObj = args[0].getClass().getMethod("getURL").invoke(args[0]);
            String url = urlObj != null ? urlObj.toString() : "?";
            String method = (String) args[0].getClass().getMethod("getRequestMethod").invoke(args[0]);
            if (method == null) method = "GET";
            int code = result != null ? result : -1;

            // Retrieve cached request body (written before this call).
            int key = System.identityHashCode(args[0]);
            CachingOutputStream cos = connOutStreams.remove(key);
            String reqBody = cos != null ? cos.get() : null;

            // Store pending log; completed by getInputStream/getErrorStream.
            connPending.put(key, new String[]{ url, method, String.valueOf(code), reqBody });
        } catch (Exception ignored) {}
        return result != null ? result : 0;
    }

    // getInputStream / getErrorStream  instance: args={thiz}
    public Object hookHttpURLConnectionGetInputStream(Object[] args) {
        return readConnBody(args[0], backupHttpURLConnectionGetInputStream);
    }
    public Object hookHttpURLConnectionGetErrorStream(Object[] args) {
        return readConnBody(args[0], backupHttpURLConnectionGetErrorStream);
    }

    private Object readConnBody(Object conn, Method backup) {
        java.io.InputStream realIs = null;
        try {
            realIs = backup != null ? (java.io.InputStream) backup.invoke(conn) : null;
        } catch (Exception e) { Log.e(TAG, "backup getInputStream failed: " + e); }
        if (realIs == null) return null;

        try {
            // Read up to BODY_PREVIEW bytes; return SequenceInputStream so app sees full body.
            byte[] buf = new byte[BODY_PREVIEW];
            int total = 0;
            while (total < BODY_PREVIEW) {
                int n = realIs.read(buf, total, BODY_PREVIEW - total);
                if (n < 0) break;
                total += n;
            }
            String respBody = (total > 0 && !isBinaryContent(buf, total))
                    ? new String(buf, 0, total, java.nio.charset.StandardCharsets.UTF_8)
                    : null;

            int key = System.identityHashCode(conn);
            String[] pending = connPending.remove(key);
            if (pending != null) {
                // Normal path: pending was set by getResponseCode hook.
                int code = -1;
                try { code = Integer.parseInt(pending[2]); } catch (NumberFormatException ignored) {}
                logNetworkFull(pending[1], pending[0], code, pending[3], respBody);
            } else if (respBody != null) {
                // Fallback: getInputStream fired without a preceding getResponseCode hook
                // (e.g. after an HTTP redirect that consumed the earlier pending entry).
                try {
                    Object urlObj = conn.getClass().getMethod("getURL").invoke(conn);
                    String url = urlObj != null ? urlObj.toString() : "?";
                    String method = (String) conn.getClass().getMethod("getRequestMethod").invoke(conn);
                    if (method == null) method = "GET";
                    logNetworkFull(method, url, -1, null, respBody);
                } catch (Exception ignored) {}
            }

            if (total > 0) {
                return new java.io.SequenceInputStream(
                    new java.io.ByteArrayInputStream(buf, 0, total), realIs);
            }
        } catch (Exception e) { Log.e(TAG, "readConnBody failed: " + e); }
        return realIs;
    }

    // Returns true if buf[0..len) looks like binary (> 12% C0 control codes).
    // Excludes: tab (0x09), LF (0x0A), CR (0x0D) which are valid in text.
    private static boolean isBinaryContent(byte[] buf, int len) {
        if (len == 0) return false;
        int check = Math.min(len, 128);
        int ctrl = 0;
        for (int i = 0; i < check; i++) {
            int b = buf[i] & 0xFF;
            if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) ctrl++;
        }
        return ctrl * 8 > check; // > 12.5% control chars → binary
    }

    // ---- Phase 6b: SSL Pinning bypass ----

    // OkHttp3 CertificatePinner.check(String hostname, List<Certificate>)
    // Just return without throwing — bypasses certificate pinning.
    // args={thiz, hostname, peerCertificates}
    public Object hookCertificatePinnerCheck(Object[] args) {
        String host = args[1] != null ? args[1].toString() : "?";
        log("SSLPinning.bypass", "CertificatePinner.check host=" + host);
        // Do NOT call backup — returning null bypasses the pin check entirely.
        return null;
    }

    // javax.net.ssl.SSLContext.init(KeyManager[], TrustManager[], SecureRandom)
    // Replace TrustManagers with a trust-all proxy so all certs are accepted.
    // args={thiz, keyManagers, trustManagers, secureRandom}
    public Object hookSslContextInit(Object[] args) {
        log("SSLPinning.bypass", "SSLContext.init replaced TrustManager");
        Object trustAll = buildTrustAllManager();
        Object tmArray = trustAll != null
                ? java.lang.reflect.Array.newInstance(trustAll.getClass().getInterfaces()[0], 1)
                : args[2];
        if (trustAll != null) {
            try { java.lang.reflect.Array.set(tmArray, 0, trustAll); }
            catch (Exception ignored) { tmArray = args[2]; }
        }
        if (backupSslContextInit != null)
            safeInvokeObject(backupSslContextInit, args[0], args[1], tmArray, args[3]);
        return null;
    }

    // javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier)  static
    // Replace with an always-true verifier so hostname mismatches are ignored.
    // args={verifier}
    public Object hookSetDefaultHostnameVerifier(Object[] args) {
        log("SSLPinning.bypass", "setDefaultHostnameVerifier replaced");
        Object trustAll = buildTrustAllVerifier(args[0]);
        if (backupSetDefaultHostnameVerifier != null)
            safeInvokeObject(backupSetDefaultHostnameVerifier, null,
                    trustAll != null ? trustAll : args[0]);
        return null;
    }

    private static Object buildTrustAllManager() {
        try {
            Class<?> x509Cls = Class.forName("javax.net.ssl.X509TrustManager");
            return java.lang.reflect.Proxy.newProxyInstance(
                x509Cls.getClassLoader(),
                new Class<?>[]{ x509Cls },
                (proxy, method, methodArgs) -> {
                    switch (method.getName()) {
                        case "checkClientTrusted":
                        case "checkServerTrusted":
                            return null;          // accept all
                        case "getAcceptedIssuers":
                            return java.lang.reflect.Array.newInstance(
                                Class.forName("java.security.cert.X509Certificate"), 0);
                        default:
                            return method.getDefaultValue();
                    }
                });
        } catch (Exception e) {
            Log.e(TAG, "buildTrustAllManager failed: " + e);
            return null;
        }
    }

    private static Object buildTrustAllVerifier(Object original) {
        try {
            Class<?> hvCls = Class.forName("javax.net.ssl.HostnameVerifier");
            ClassLoader cl = original != null
                    ? original.getClass().getClassLoader()
                    : hvCls.getClassLoader();
            return java.lang.reflect.Proxy.newProxyInstance(
                cl,
                new Class<?>[]{ hvCls },
                (proxy, method, methodArgs) -> {
                    if ("verify".equals(method.getName())) return Boolean.TRUE;
                    return method.getDefaultValue();
                });
        } catch (Exception e) {
            Log.e(TAG, "buildTrustAllVerifier failed: " + e);
            return null;
        }
    }


    private static String sensorTypeName(int type) {
        switch (type) {
            case 1:  return "ACCELEROMETER";
            case 2:  return "MAGNETIC_FIELD";
            case 3:  return "ORIENTATION";
            case 4:  return "GYROSCOPE";
            case 5:  return "LIGHT";
            case 6:  return "PRESSURE";
            case 7:  return "TEMPERATURE";
            case 8:  return "PROXIMITY";
            case 9:  return "GRAVITY";
            case 10: return "LINEAR_ACCELERATION";
            case 11: return "ROTATION_VECTOR";
            case 12: return "RELATIVE_HUMIDITY";
            case 13: return "AMBIENT_TEMPERATURE";
            case 14: return "MAGNETIC_FIELD_UNCALIBRATED";
            case 15: return "GAME_ROTATION_VECTOR";
            case 16: return "GYROSCOPE_UNCALIBRATED";
            case 17: return "SIGNIFICANT_MOTION";
            case 18: return "STEP_DETECTOR";
            case 19: return "STEP_COUNTER";
            case 20: return "GEOMAGNETIC_ROTATION_VECTOR";
            case 21: return "HEART_RATE";
            case 28: return "POSE_6DOF";
            case 29: return "STATIONARY_DETECT";
            case 30: return "MOTION_DETECT";
            case 31: return "HEART_BEAT";
            case 34: return "LOW_LATENCY_OFFBODY_DETECT";
            case 35: return "ACCELEROMETER_UNCALIBRATED";
            case 36: return "HINGE_ANGLE";
            default: return "TYPE_" + type;
        }
    }

    private static void logSensor(Object sensor, int rate) {
        if (sensor == null) return;
        try {
            int type    = (Integer) sensor.getClass().getMethod("getType").invoke(sensor);
            String name = (String)  sensor.getClass().getMethod("getName").invoke(sensor);
            log("SensorManager.registerListener",
                type + "(" + sensorTypeName(type) + ")/" + name + " rate=" + rate);
        } catch (Exception e) {
            log("SensorManager.registerListener", "?");
        }
    }

    // registerListener(SensorEventListener, Sensor, int)  instance: args={thiz, listener, sensor, rate}
    public Object hookSensorRegister3(Object[] args) {
        logSensor(args[2], args[3] != null ? ((Number) args[3]).intValue() : -1);
        return backupSensorRegister3 != null
                ? safeInvokeObject(backupSensorRegister3, args[0], args[1], args[2], args[3])
                : Boolean.FALSE;
    }

    // registerListener(SensorEventListener, Sensor, int, int)  instance: args={thiz, listener, sensor, rate, maxLatency}
    public Object hookSensorRegister4Int(Object[] args) {
        logSensor(args[2], args[3] != null ? ((Number) args[3]).intValue() : -1);
        return backupSensorRegister4Int != null
                ? safeInvokeObject(backupSensorRegister4Int, args[0], args[1], args[2], args[3], args[4])
                : Boolean.FALSE;
    }

    // registerListener(SensorEventListener, Sensor, int, Handler)  instance: args={thiz, listener, sensor, rate, handler}
    public Object hookSensorRegister4Handler(Object[] args) {
        logSensor(args[2], args[3] != null ? ((Number) args[3]).intValue() : -1);
        return backupSensorRegister4Handler != null
                ? safeInvokeObject(backupSensorRegister4Handler, args[0], args[1], args[2], args[3], args[4])
                : Boolean.FALSE;
    }

    // ---- Phase 7: permission requests ----

    private static void logPermission(String method, Object[] permArray) {
        if (permArray == null) return;
        for (Object p : permArray) {
            String perm = p != null ? p.toString() : "";
            log(method, perm);
        }
    }

    // Activity.requestPermissions(String[] perms, int requestCode)  instance: args={thiz, perms, code}
    public Object hookRequestPermissions(Object[] args) {
        try { logPermission("Activity.requestPermissions", (Object[]) args[1]); }
        catch (Exception e) { log("Activity.requestPermissions", "?"); }
        if (backupRequestPermissions != null)
            safeInvokeObject(backupRequestPermissions, args[0], args[1], args[2]);
        return null;
    }

    // ActivityCompat.requestPermissions(Activity, String[], int)  static: args={activity, perms, code}
    public Object hookActivityCompatRequestPermissions(Object[] args) {
        try { logPermission("ActivityCompat.requestPermissions", (Object[]) args[1]); }
        catch (Exception e) { log("ActivityCompat.requestPermissions", "?"); }
        if (backupActivityCompatRequestPermissions != null)
            safeInvokeObject(backupActivityCompatRequestPermissions, null, args[0], args[1], args[2]);
        return null;
    }

    // PackageInstaller.Session.commit(IntentSender)  instance: args={thiz, statusReceiver}
    public Object hookPackageInstallerCommit(Object[] args) {
        log("PackageInstaller.Session.commit", "");
        if (backupPackageInstallerCommit != null)
            safeInvokeObject(backupPackageInstallerCommit, args[0], args[1]);
        return null;
    }

    // ---- Phase 8: cell info, wifi, package list, tasks, broadcast, media projection ----

    // TelephonyManager.getCellLocation()  instance: args={thiz}
    public Object hookGetCellLocation(Object[] args) {
        Object loc = backupGetCellLocation != null
                ? safeInvokeObject(backupGetCellLocation, args[0])
                : null;
        log("TelephonyManager.getCellLocation", loc != null ? loc.toString() : "null");
        return loc;
    }

    // TelephonyManager.getAllCellInfo()  instance: args={thiz}
    public Object hookGetAllCellInfo(Object[] args) {
        Object list = backupGetAllCellInfo != null
                ? safeInvokeObject(backupGetAllCellInfo, args[0])
                : null;
        log("TelephonyManager.getAllCellInfo", list != null ? "count=" + getListSize(list) : "null");
        return list;
    }

    // TelephonyManager.getNetworkOperator()  instance: args={thiz}
    public Object hookGetNetworkOperator(Object[] args) {
        String v = backupGetNetworkOperator != null ? safeInvoke(backupGetNetworkOperator, args[0]) : null;
        log("TelephonyManager.getNetworkOperator", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getNetworkOperatorName()  instance: args={thiz}
    public Object hookGetNetworkOperatorName(Object[] args) {
        String v = backupGetNetworkOperatorName != null ? safeInvoke(backupGetNetworkOperatorName, args[0]) : null;
        log("TelephonyManager.getNetworkOperatorName", v != null ? v : "");
        return v;
    }

    // ApplicationPackageManager.getInstalledPackages(int)  instance: args={thiz, flags}
    public Object hookGetInstalledPackages(Object[] args) {
        Object list = backupGetInstalledPackages != null
                ? safeInvokeObject(backupGetInstalledPackages, args[0], args[1])
                : null;
        log("PackageManager.getInstalledPackages", list != null ? "count=" + getListSize(list) : "null");
        return list;
    }

    // ApplicationPackageManager.getInstalledApplications(int)  instance: args={thiz, flags}
    public Object hookGetInstalledApplications(Object[] args) {
        Object list = backupGetInstalledApplications != null
                ? safeInvokeObject(backupGetInstalledApplications, args[0], args[1])
                : null;
        log("PackageManager.getInstalledApplications", list != null ? "count=" + getListSize(list) : "null");
        return list;
    }

    // ActivityManager.getRunningTasks(int)  instance: args={thiz, maxNum}
    public Object hookGetRunningTasks(Object[] args) {
        Object list = backupGetRunningTasks != null
                ? safeInvokeObject(backupGetRunningTasks, args[0], args[1])
                : null;
        log("ActivityManager.getRunningTasks", list != null ? "count=" + getListSize(list) : "null");
        return list;
    }

    // WifiInfo.getSSID()  instance: args={thiz}
    public Object hookWifiGetSSID(Object[] args) {
        String v = backupWifiGetSSID != null ? safeInvoke(backupWifiGetSSID, args[0]) : null;
        log("WifiInfo.getSSID", v != null ? v : "");
        return v;
    }

    // WifiInfo.getBSSID()  instance: args={thiz}
    public Object hookWifiGetBSSID(Object[] args) {
        String v = backupWifiGetBSSID != null ? safeInvoke(backupWifiGetBSSID, args[0]) : null;
        log("WifiInfo.getBSSID", v != null ? v : "");
        return v;
    }

    // ContextWrapper.sendBroadcast(Intent)  instance: args={thiz, intent}
    public Object hookSendBroadcast(Object[] args) {
        String action = "";
        if (args[1] != null) {
            try { action = (String) args[1].getClass().getMethod("getAction").invoke(args[1]); }
            catch (Exception ignored) {}
            if (action == null) action = args[1].toString();
        }
        // WeChat's internal cross-process KV reporting — not a mini-program privacy behavior.
        if ("com.tencent.mm.plugin.report.service.KVCommCrossProcessReceiver".equals(action)) {
            if (backupSendBroadcast != null) safeInvokeObject(backupSendBroadcast, args[0], args[1]);
            return null;
        }
        log("Context.sendBroadcast", action != null ? action : "");
        if (backupSendBroadcast != null)
            safeInvokeObject(backupSendBroadcast, args[0], args[1]);
        return null;
    }

    // ContextWrapper.sendOrderedBroadcast(Intent, String)  instance: args={thiz, intent, receiverPermission}
    public Object hookSendOrderedBroadcast(Object[] args) {
        String action = "";
        if (args[1] != null) {
            try { action = (String) args[1].getClass().getMethod("getAction").invoke(args[1]); }
            catch (Exception ignored) {}
            if (action == null) action = args[1].toString();
        }
        log("Context.sendBroadcast", action != null ? action : "");
        if (backupSendOrderedBroadcast != null)
            safeInvokeObject(backupSendOrderedBroadcast, args[0], args[1], args[2]);
        return null;
    }

    // ContextWrapper.checkPermission(String, int, int)  instance: args={thiz, permission, pid, uid}
    public Object hookContextCheckPermission(Object[] args) {
        String perm = args[1] != null ? args[1].toString() : "";
        Integer result = null;
        if (backupContextCheckPermission != null) {
            try { result = (Integer) backupContextCheckPermission.invoke(args[0], perm, args[2], args[3]); }
            catch (Exception e) { Log.e(TAG, "backup checkPermission failed: " + e); }
        }
        if (result == null || result != 0)
            log("Context.checkPermission", perm);
        return result != null ? result : -1;
    }

    // ContextCompat.checkSelfPermission(Context, String)  static: args={context, permission}
    public Object hookContextCompatCheckSelfPermission(Object[] args) {
        String perm = args[1] != null ? args[1].toString() : "";
        Integer result = null;
        if (backupContextCompatCheckSelfPermission != null) {
            try { result = (Integer) backupContextCompatCheckSelfPermission.invoke(null, args[0], perm); }
            catch (Exception e) { Log.e(TAG, "backup ContextCompat.checkSelfPermission failed: " + e); }
        }
        // Chromium's own service/media initialization checks (ad attribution, BT for audio) are
        // framework noise inside the xweb process — not meaningful mini-program privacy behaviors.
        StackTraceElement[] frames = Thread.currentThread().getStackTrace();
        for (int i = 0; i < Math.min(frames.length, 20); i++) {
            if (frames[i].getClassName().startsWith("org.chromium")) {
                return result != null ? result : -1;
            }
        }
        log("ContextCompat.checkSelfPermission", perm);
        return result != null ? result : -1;
    }

    // ContextWrapper.getSystemService(String)  instance: args={thiz, name}
    // Only log when name is "media_projection" to avoid noise.
    public Object hookGetSystemService(Object[] args) {
        Object result = backupGetSystemService != null
                ? safeInvokeObject(backupGetSystemService, args[0], args[1])
                : null;
        if (args[1] != null && "media_projection".equals(args[1].toString()))
            log("getSystemService_media_projection", "");
        return result;
    }

    // Baidu LocationClient.start()  instance: args={thiz}
    public Object hookBaiduLocationStart(Object[] args) {
        log("LocationClient.start", "baidu");
        if (backupBaiduLocationStart != null)
            safeInvokeObject(backupBaiduLocationStart, args[0]);
        return null;
    }

    // AMapLocationClient.startLocation()  instance: args={thiz}
    public Object hookAmapLocationStart(Object[] args) {
        log("AMapLocationClient.startLocation", "amap");
        if (backupAmapLocationStart != null)
            safeInvokeObject(backupAmapLocationStart, args[0]);
        return null;
    }

    // ---- Phase 9: file stream constructors (external storage only) ----

    private static boolean isExternalStorage(String path) {
        if (path == null) return false;
        return path.startsWith("/sdcard")
            || path.startsWith("/storage/")
            || path.startsWith("/mnt/");
    }

    private static String fileArgToPath(Object arg) {
        if (arg == null) return null;
        if (arg instanceof String) return (String) arg;
        try {
            return (String) arg.getClass().getMethod("getAbsolutePath").invoke(arg);
        } catch (Exception e) { return arg.toString(); }
    }

    // FileInputStream(String path)  instance: args={thiz, path}
    public Object hookFileInputStreamStr(Object[] args) {
        if (backupFileInputStreamStr != null)
            safeInvokeObject(backupFileInputStreamStr, args[0], args[1]);
        String path = args[1] != null ? args[1].toString() : "";
        if (isExternalStorage(path)) log("FileInputStream.read", path);
        return null;
    }

    // FileInputStream(File file)  instance: args={thiz, file}
    public Object hookFileInputStreamFile(Object[] args) {
        if (backupFileInputStreamFile != null)
            safeInvokeObject(backupFileInputStreamFile, args[0], args[1]);
        String path = fileArgToPath(args[1]);
        if (isExternalStorage(path)) log("FileInputStream.read", path);
        return null;
    }

    // FileOutputStream(String path)  instance: args={thiz, path}
    public Object hookFileOutputStreamStr(Object[] args) {
        if (backupFileOutputStreamStr != null)
            safeInvokeObject(backupFileOutputStreamStr, args[0], args[1]);
        String path = args[1] != null ? args[1].toString() : "";
        if (isExternalStorage(path)) log("FileOutputStream.write", path);
        return null;
    }

    // FileOutputStream(String path, boolean append)  instance: args={thiz, path, append}
    public Object hookFileOutputStreamStrAppend(Object[] args) {
        if (backupFileOutputStreamStrAppend != null)
            safeInvokeObject(backupFileOutputStreamStrAppend, args[0], args[1], args[2]);
        String path = args[1] != null ? args[1].toString() : "";
        if (isExternalStorage(path)) log("FileOutputStream.write", path);
        return null;
    }

    // FileOutputStream(File file)  instance: args={thiz, file}
    public Object hookFileOutputStreamFile(Object[] args) {
        if (backupFileOutputStreamFile != null)
            safeInvokeObject(backupFileOutputStreamFile, args[0], args[1]);
        String path = fileArgToPath(args[1]);
        if (isExternalStorage(path)) log("FileOutputStream.write", path);
        return null;
    }

    // FileOutputStream(File file, boolean append)  instance: args={thiz, file, append}
    public Object hookFileOutputStreamFileAppend(Object[] args) {
        if (backupFileOutputStreamFileAppend != null)
            safeInvokeObject(backupFileOutputStreamFileAppend, args[0], args[1], args[2]);
        String path = fileArgToPath(args[1]);
        if (isExternalStorage(path)) log("FileOutputStream.write", path);
        return null;
    }

    // TencentLocationManager.requestLocationUpdates()  instance: args={thiz, request, listener}
    public Object hookTencentLocationStart(Object[] args) {
        log("TencentLocationManager.requestLocationUpdates", "tencent");
        if (backupTencentLocationStart != null)
            safeInvokeObject(backupTencentLocationStart, args[0], args[1], args[2]);
        return null;
    }

    // ---- Phase 10: WeChat mini-program hooks ----
    //
    // These hooks capture mini-program lifecycle and API events inside the
    // com.tencent.mm:appbrand* processes. Class names are obfuscated and
    // version-specific (tested on WeChat 8.0.x); each hook is isolated by a
    // try/catch so a class-not-found in a different version is silently skipped.
    //
    // Three data types produced:
    //   mini_launch   – mini-program started (appId, brandName, iconUrl, version)
    //   mini_call_api – wx.* JS API dispatched (api name + call arguments)
    //   mini_request  – wx.request() HTTP round-trip (url, method, status, body)
    //
    // Installation: called from a detached JVM thread in main.cpp after a 2-second
    // delay so WeChat's lazy-loaded classes are available by the time we hook them.

    // Blacklisted mini_call_api names that produce too much noise (storage, UI, logs).
    private static final java.util.Set<String> MINI_API_BLACKLIST = new java.util.HashSet<>(java.util.Arrays.asList(
        "onRequestTaskStateChange", "hideToast", "setStorageSync", "reportIDKey",
        "systemLog", "insertTextView", "updateTextView", "updateImageView",
        "reportKeyValue", "reportRealtimeAction", "createDownloadTaskAsync",
        "onDownloadTaskStateChange", "createRequestTaskAsync",
        "getStorageSync", "getStorage", "setStorage", "operateAudio", "setAudioState"
    ));

    // Pending wx.request() tasks keyed by task-id string (args[6] of xf1.q.q).
    private static final java.util.concurrent.ConcurrentHashMap<String, String[]>
        wxPendingRequests = new java.util.concurrent.ConcurrentHashMap<>();
    // String[]: {url, method, body}

    /**
     * Install WeChat mini-program specific hooks via LSPlant.
     * Called once from a background thread in payload_init() with a 2 s delay so that
     * WeChat's dex classes are loaded before we attempt to hook them.
     * Each hook target is wrapped in its own try/catch — partial failure is acceptable.
     *
     * @return number of hooks successfully installed
     */
    public static int installMiniHooks() {
        HookerBridge inst = sInstance;
        if (inst == null) {
            Log.w(TAG, "mini_hooks: sInstance null, skipping");
            return 0;
        }
        int installed = 0;

        // Use the calling thread's context ClassLoader to resolve WeChat classes.
        // This method must be called on a WeChat app thread (via Handler/main looper)
        // so that the context ClassLoader includes WeChat's full class hierarchy —
        // base PathClassLoader AND any Tinker/plugin patch DEXes loaded at runtime.
        // Calling from a bare AttachCurrentThread native thread gives only BootCL,
        // and ActivityThread.currentApplication().getClassLoader() gives only base
        // PathCL — neither can see Tinker-patched versions of jsapi.m, AppBrandRuntime,
        // or xf1.q that WeChat actually uses at runtime.
        ClassLoader appCL = Thread.currentThread().getContextClassLoader();
        if (appCL == null) {
            Log.w(TAG, "mini_hooks: thread context CL null, aborting");
            return 0;
        }
        Log.i(TAG, "mini_hooks: using CL=" + appCL.getClass().getName());

        // ── AppBrandRuntime.i → mini_launch ─────────────────────────────────
        // Callstack evidence (WeChat 8.0.71): AppBrandRuntime.i:48 is the
        // mini-program launch entry point. Method dump shows i(2) — two parameters,
        // first is non-primitive (AppBrandInitConfig subclass).
        try {
            Class<?> runtimeCls = Class.forName("com.tencent.mm.plugin.appbrand.AppBrandRuntime", true, appCL);
            java.lang.reflect.Method target = null;
            for (java.lang.reflect.Method m : runtimeCls.getDeclaredMethods()) {
                if ("i".equals(m.getName()) && m.getParameterTypes().length == 2
                        && !m.getParameterTypes()[0].isPrimitive()) {
                    target = m;
                    break;
                }
            }
            if (target != null) {
                target.setAccessible(true);
                java.lang.reflect.Method cb = HookerBridge.class.getDeclaredMethod(
                        "hookAppBrandRuntimeM0", Object[].class);
                Object backup = hookNative(target, inst, cb);
                if (backup instanceof java.lang.reflect.Method) {
                    inst.backupAppBrandRuntimeM0 = (java.lang.reflect.Method) backup;
                    installed++;
                    Log.i(TAG, "mini_hooks: AppBrandRuntime.i hooked → mini_launch");
                } else {
                    Log.w(TAG, "mini_hooks: AppBrandRuntime.i hookNative returned null");
                }
            } else {
                // Dump all method names to help diagnose future version changes
                java.lang.reflect.Method[] all = runtimeCls.getDeclaredMethods();
                StringBuilder sb = new StringBuilder("mini_hooks: AppBrandRuntime methods: ");
                for (java.lang.reflect.Method m : all) sb.append(m.getName()).append('(').append(m.getParameterTypes().length).append(") ");
                Log.w(TAG, sb.toString());
            }
        } catch (Exception e) {
            Log.w(TAG, "mini_hooks: AppBrandRuntime.i failed: " + e);
        }

        // ── jsapi.m.q0 → mini_call_api ──────────────────────────────────────
        // Callstack evidence (WeChat 8.0.71):
        //   jsapi.m.q0:248/329  ← top-level API queue entry, called for EVERY wx.* call
        //   direct caller:       service.c0.q0:23 (single confirmed caller)
        //
        // service.c0.q0 is JIT-compiled and calls jsapi.m.q0 via a direct call that
        // bypasses ArtMethod entry_point dispatch. After hooking q0, we deoptimize
        // service.c0.q0 to force it back to the interpreter so the hook fires.
        try {
            Class<?> jsapiCls = Class.forName("com.tencent.mm.plugin.appbrand.jsapi.m", true, appCL);
            java.lang.reflect.Method target = null;
            for (java.lang.reflect.Method m : jsapiCls.getDeclaredMethods()) {
                if ("q0".equals(m.getName()) && m.getParameterTypes().length >= 2) {
                    target = m;
                    break;
                }
            }
            if (target != null) {
                target.setAccessible(true);
                java.lang.reflect.Method cb = HookerBridge.class.getDeclaredMethod(
                        "hookJsapiQ0", Object[].class);
                Object backup = hookNative(target, inst, cb);
                if (backup instanceof java.lang.reflect.Method) {
                    inst.backupJsapiQ0 = (java.lang.reflect.Method) backup;
                    installed++;
                    Log.i(TAG, "mini_hooks: jsapi.m.q0 hooked → mini_call_api (params="
                            + target.getParameterTypes().length + ")");
                    // Deoptimize service.c0.q0 (the JIT-compiled direct caller) so it
                    // re-dispatches through ArtMethod entry_point and our hook fires.
                    try {
                        Class<?> svcCls = Class.forName(
                                "com.tencent.mm.plugin.appbrand.service.c0", true, appCL);
                        for (java.lang.reflect.Method m : svcCls.getDeclaredMethods()) {
                            if ("q0".equals(m.getName())) {
                                deoptimizeNative(m);
                                Log.i(TAG, "mini_hooks: service.c0.q0 deoptimized");
                                break;
                            }
                        }
                    } catch (Exception de) {
                        Log.w(TAG, "mini_hooks: deoptimize service.c0.q0 failed: " + de);
                    }
                } else {
                    Log.w(TAG, "mini_hooks: jsapi.m.q0 hookNative returned null");
                }
            } else {
                // Dump all method names/param-counts to aid future diagnosis
                java.lang.reflect.Method[] all = jsapiCls.getDeclaredMethods();
                StringBuilder sb = new StringBuilder("mini_hooks: jsapi.m methods: ");
                for (java.lang.reflect.Method m : all) sb.append(m.getName()).append('(').append(m.getParameterTypes().length).append(") ");
                Log.w(TAG, sb.toString());
            }
        } catch (Exception e) {
            Log.w(TAG, "mini_hooks: jsapi.m.q0 failed: " + e);
        }

        // ── xf1.q.q / xf1.q.d → mini_request ──────────────────────────────
        // q: outgoing request (param count varies by WeChat version)
        // d: response callback (9 declared params including status-code + body)
        try {
            Class<?> xf1q = Class.forName("xf1.q", true, appCL);
            java.lang.reflect.Method targetQ = null;
            java.lang.reflect.Method targetD = null;
            // Dump all methods to log so we can confirm actual param counts
            StringBuilder xf1Dump = new StringBuilder("mini_hooks: xf1.q methods: ");
            for (java.lang.reflect.Method m : xf1q.getDeclaredMethods()) {
                xf1Dump.append(m.getName()).append('(').append(m.getParameterTypes().length).append(") ");
                int pc = m.getParameterTypes().length;
                // In WeChat 8.0.71 with Tinker patch the send-side method was
                // renamed from "q" to "g" (8 params). Accept either name.
                if (("q".equals(m.getName()) || "g".equals(m.getName())) && pc >= 6 && targetQ == null) targetQ = m;
                else if ("d".equals(m.getName()) && pc >= 8 && targetD == null) targetD = m;
            }
            Log.i(TAG, xf1Dump.toString());
            if (targetQ != null) {
                targetQ.setAccessible(true);
                java.lang.reflect.Method cb = HookerBridge.class.getDeclaredMethod(
                        "hookXf1QQ", Object[].class);
                Object backup = hookNative(targetQ, inst, cb);
                if (backup instanceof java.lang.reflect.Method) {
                    inst.backupXf1QQ = (java.lang.reflect.Method) backup;
                    installed++;
                    // Log actual param count and types to confirm correct overload was hooked
                    StringBuilder sig = new StringBuilder("mini_hooks: xf1.q.q hooked params=");
                    sig.append(targetQ.getParameterTypes().length).append(" [");
                    for (Class<?> t : targetQ.getParameterTypes())
                        sig.append(t.getSimpleName()).append(',');
                    sig.append(']');
                    Log.i(TAG, sig.toString());
                } else {
                    Log.w(TAG, "mini_hooks: xf1.q.q hookNative returned null");
                }
            } else {
                Log.w(TAG, "mini_hooks: xf1.q send-side (q/g, >=6 params) not found");
            }
            if (targetD != null) {
                targetD.setAccessible(true);
                java.lang.reflect.Method cb = HookerBridge.class.getDeclaredMethod(
                        "hookXf1QD", Object[].class);
                Object backup = hookNative(targetD, inst, cb);
                if (backup instanceof java.lang.reflect.Method) {
                    inst.backupXf1QD = (java.lang.reflect.Method) backup;
                    installed++;
                    StringBuilder sig2 = new StringBuilder("mini_hooks: xf1.q.d hooked params=");
                    sig2.append(targetD.getParameterTypes().length).append(" [");
                    for (Class<?> t : targetD.getParameterTypes())
                        sig2.append(t.getSimpleName()).append(',');
                    sig2.append(']');
                    Log.i(TAG, sig2.toString());
                } else {
                    Log.w(TAG, "mini_hooks: xf1.q.d hookNative returned null");
                }
            } else {
                Log.w(TAG, "mini_hooks: xf1.q.d (9 params) not found");
            }
        } catch (Exception e) {
            Log.w(TAG, "mini_hooks: xf1.q failed: " + e);
        }

        Log.i(TAG, "mini_hooks: installed=" + installed);
        return installed;
    }

    // Called from the Phase 10 C++ native thread. Posts installMiniHooks() to the
    // appbrand main looper so it runs on a WeChat app thread whose context ClassLoader
    // includes Tinker/plugin patch DEXes — the only way to find the runtime versions
    // of jsapi.m, AppBrandRuntime, and xf1.q that WeChat actually calls.
    // Returns immediately; the actual hook installation is asynchronous.
    public static void scheduleInstallMiniHooks() {
        Looper main = Looper.getMainLooper();
        if (main == null) {
            Log.w(TAG, "mini_hooks: main looper null, falling back to direct call");
            installMiniHooks();
            return;
        }
        new Handler(main).post(() -> {
            Log.i(TAG, "mini_hooks: running on main looper thread="
                    + Thread.currentThread().getName());
            installMiniHooks();
        });
    }

    // Called by C++ LSPlant after it hooks AppBrandRuntime.m0.
    // args = {thiz, AppBrandInitConfig}
    public Method backupAppBrandRuntimeM0;
    public Object hookAppBrandRuntimeM0(Object[] args) {
        if (backupAppBrandRuntimeM0 != null)
            safeInvokeObject(backupAppBrandRuntimeM0, args[0], args[1], args[2]);
        try {
            Object config = args[1];
            // Cast to AppBrandInitConfigWC for brand fields (v / d / e / f)
            Class<?> wcCls  = Class.forName("com.tencent.mm.plugin.appbrand.config.AppBrandInitConfigWC");
            Class<?> luCls  = Class.forName("com.tencent.luggage.sdk.config.AppBrandInitConfigLU");
            String username = fieldStr(wcCls, config, "v");
            String appId    = fieldStr(wcCls, config, "d");
            String brand    = fieldStr(wcCls, config, "e");
            String icon     = fieldStr(wcCls, config, "f");
            String ver      = fieldStr(luCls,  config, "J");
            String json = "{\"type\":\"mini_launch\""
                + ",\"appId\":\""        + jsonEscape(appId)    + "\""
                + ",\"brandName\":\""    + jsonEscape(brand)    + "\""
                + ",\"appletBrandName\":\"" + jsonEscape(brand) + "\""
                + ",\"iconUrl\":\""      + jsonEscape(icon)     + "\""
                + ",\"appletIconUrl\":\"" + jsonEscape(icon)    + "\""
                + ",\"appVersion\":\""   + jsonEscape(ver)      + "\""
                + ",\"appletVersion\":\"" + jsonEscape(ver)     + "\""
                + ",\"username\":\""     + jsonEscape(username) + "\""
                + ",\"timestamp\":"      + System.currentTimeMillis()
                + "}";
            Log.i(TAG, json);
            SocketChannel.send(json);
        } catch (Exception e) {
            Log.w(TAG, "hookAppBrandRuntimeM0 failed: " + e);
        }
        return null;
    }

    // Called by C++ LSPlant after it hooks jsapi_g.q0.
    // args = {thiz, String apiName, String data, String callbackId, int, boolean, c0, int}
    public Method backupJsapiQ0;
    public Object hookJsapiQ0(Object[] args) {
        Object result = null;
        if (backupJsapiQ0 != null)
            result = safeInvokeObject(backupJsapiQ0, args[0], args[1], args[2],
                                       args[3], args[4], args[5], args[6], args[7]);
        try {
            String api  = args[1] != null ? args[1].toString() : "";
            String data = args[2] != null ? args[2].toString() : "";
            if (!MINI_API_BLACKLIST.contains(api)) {
                String json = "{\"type\":\"mini_call_api\""
                    + ",\"api\":\""    + jsonEscape(api)  + "\""
                    + ",\"method\":\"" + jsonEscape(api)  + "\""
                    + ",\"data\":\""   + jsonEscape(data) + "\""
                    + ",\"timestamp\":" + System.currentTimeMillis()
                    + "}";
                Log.i(TAG, json);
                SocketChannel.send(json);
            }
        } catch (Exception e) {
            Log.w(TAG, "hookJsapiQ0 failed: " + e);
        }
        return result;
    }

    // Called by C++ LSPlant for xf1.q.q (request initiation).
    // args = {thiz, l, int, JSONObject params, Map headers, ArrayList, n, String taskId, String apiName}
    public Method backupXf1QQ;
    // args = {thiz, ...params...}  param count varies by WeChat version (>=6)
    // taskId is args[args.length-2], apiName is args[args.length-1]
    public Object hookXf1QQ(Object[] args) {
        if (backupXf1QQ != null) {
            try {
                Object[] reflArgs = java.util.Arrays.copyOfRange(args, 1, args.length);
                backupXf1QQ.invoke(args[0], reflArgs);
            } catch (Exception e) { Log.e(TAG, "backup invoke object failed: " + e); }
        }
        try {
            int n = args.length;
            String apiName = n >= 2 && args[n-1] != null ? args[n-1].toString() : "";
            String taskId  = n >= 3 && args[n-2] != null ? args[n-2].toString() : "";
            // Always log: confirms hook fires + shows actual arg structure
            Log.i(TAG, "hookXf1QQ: args=" + n + " apiName=" + apiName + " taskId=" + taskId);
            if ("createRequestTask".equals(apiName) && !taskId.isEmpty()) {
                String params  = n >= 4 ? safeJson(args[3]) : "";
                String headers = n >= 5 ? safeJson(args[4]) : "";
                wxPendingRequests.put(taskId, new String[]{params, headers});
                String url = extractJsonField(params, "url");
                Log.i(TAG, "hookXf1QQ: pending taskId=" + taskId + " url=" + url);
            }
        } catch (Exception e) {
            Log.w(TAG, "hookXf1QQ failed: " + e);
        }
        return null;
    }

    // Called by C++ LSPlant for xf1.q.d (response callback).
    // args = {thiz, n, String status, Object body, int statusCode, JSONObject, String taskId, HttpURLConnection, Map reqHdrs, Map respHdrs}
    public Method backupXf1QD;
    public Object hookXf1QD(Object[] args) {
        if (backupXf1QD != null)
            safeInvokeObject(backupXf1QD, args[0], args[1], args[2],
                              args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
        try {
            int n = args.length;
            String taskId = n > 6 && args[6] != null ? args[6].toString() : "";
            String[] req  = wxPendingRequests.remove(taskId);
            int code      = n > 4 && args[4] != null ? ((Number) args[4]).intValue() : -1;
            String body   = n > 3 && args[3] != null ? args[3].toString() : "";
            // Always log: confirms hook fires + shows whether pending matched
            Log.i(TAG, "hookXf1QD: args=" + n + " taskId=" + taskId
                    + " code=" + code + " bodyLen=" + body.length()
                    + " pendingMatch=" + (req != null));
            if (req != null) {
                String params  = req[0];
                // Extract url / method from params JSON
                String url    = extractJsonField(params, "url");
                String method = extractJsonField(params, "method");
                if (url.isEmpty()) url = extractJsonField(params, "host");

                String json = "{\"type\":\"network\""
                    + ",\"method\":\""     + jsonEscape(method.isEmpty() ? "GET" : method) + "\""
                    + ",\"url\":\""        + jsonEscape(url)   + "\""
                    + ",\"statusCode\":"   + code
                    + ",\"requestBody\":\"" + jsonEscape(extractJsonField(params, "data")) + "\""
                    + ",\"responseBody\":\"" + jsonEscape(body.length() > 4096 ? body.substring(0, 4096) : body) + "\""
                    + ",\"timestamp\":"    + System.currentTimeMillis()
                    + "}";
                Log.i(TAG, json);
                SocketChannel.send(json);
            }
        } catch (Exception e) {
            Log.w(TAG, "hookXf1QD failed: " + e);
        }
        return null;
    }

    // ---- Helpers for WeChat mini-program hooks ----

    private static String fieldStr(Class<?> cls, Object obj, String fieldName) {
        try {
            java.lang.reflect.Field f = cls.getDeclaredField(fieldName);
            f.setAccessible(true);
            Object v = f.get(obj);
            return v != null ? v.toString() : "";
        } catch (Exception e) { return ""; }
    }

    private static String safeJson(Object o) {
        if (o == null) return "";
        try {
            // Use Gson if available in the app's classloader
            Class<?> gsonCls = o.getClass().getClassLoader()
                .loadClass("com.google.gson.Gson");
            Object gson = gsonCls.newInstance();
            return (String) gsonCls.getMethod("toJson", Object.class).invoke(gson, o);
        } catch (Exception e) { return o.toString(); }
    }

    /** Naive JSON field extractor — works for flat string fields only. */
    private static String extractJsonField(String json, String key) {
        if (json == null || json.isEmpty()) return "";
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) return "";
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end < 0) end = json.length();
        return json.substring(start, end);
    }
}
