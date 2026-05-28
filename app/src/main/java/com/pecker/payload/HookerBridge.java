package com.pecker.payload;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
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
    private static final class SocketChannel {
        private static final String SOCKET_NAME = "pecker";
        private static volatile OutputStream activeOut = null;
        private static final Object LOCK = new Object();

        static {
            Thread t = new Thread(() -> {
                try (LocalServerSocket srv = new LocalServerSocket(SOCKET_NAME)) {
                    Log.i(TAG, "socket_channel: listening @" + SOCKET_NAME);
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
        String json = "{\"type\":\"network\""
                + ",\"method\":\"" + jsonEscape(httpMethod) + "\""
                + ",\"url\":\"" + jsonEscape(url) + "\""
                + ",\"statusCode\":" + statusCode
                + ",\"timestamp\":" + System.currentTimeMillis() + "}";
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
            logNetwork(httpMethod != null ? httpMethod : "?", url, code);
        } catch (Exception e) {
            logNetwork("?", "?", -1);
        }
        return response;
    }

    // RealCall.enqueue(Callback)  instance: args={thiz, callback}
    // Wraps the original Callback in a java.lang.reflect.Proxy to intercept
    // onResponse/onFailure so we can log URL + response code asynchronously.
    public Object hookRealCallEnqueue(Object[] args) {
        Object realCall = args[0];
        Object origCallback = args[1];
        String url;
        String httpMethod;
        try {
            Object request = realCall.getClass().getMethod("request").invoke(realCall);
            url = request.getClass().getMethod("url").invoke(request).toString();
            httpMethod = (String) request.getClass().getMethod("method").invoke(request);
            if (httpMethod == null) httpMethod = "?";
        } catch (Exception e) {
            url = "?";
            httpMethod = "?";
        }
        final String capturedUrl = url;
        final String capturedMethod = httpMethod;

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
                                    logNetwork(capturedMethod, capturedUrl, code);
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
}
