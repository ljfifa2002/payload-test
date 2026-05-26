package com.pecker.payload;

import android.util.Log;
import java.lang.reflect.Method;

public class HookerBridge {

    private static final String TAG = "payload";

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
    public Method backupLocationGetLongitude;
    // Phase 4
    public Method backupContentResolverQuery;
    public Method backupCameraManagerOpenCamera;
    public Method backupMediaRecorderSetAudioSource;
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
    public Method backupCheckSelfPermission;
    public Method backupActivityCompatRequestPermissions;

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
            // Skip VM internals, reflection, and our own bridge frames
            if (cls.startsWith("com.pecker.payload.")
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
        return sb.toString();
    }

    private static void log(String method, String data) {
        String stack = captureStack();
        Log.i(TAG, "{\"type\":\"behavior\",\"method\":\"" + method
                + "\",\"data\":\"" + data
                + "\",\"stack\":\"" + stack
                + "\",\"timestamp\":" + System.currentTimeMillis() + "}");
    }

    // ---- Instance hook callbacks ([Ljava/lang/Object;)Ljava/lang/Object; ----

    // TelephonyManager.getDeviceId()  instance: args={thiz}
    public Object hookGetDeviceId(Object[] args) {
        Object thiz = args[0];
        String v = backupGetDeviceId != null ? safeInvoke(backupGetDeviceId, thiz) : null;
        log("TelephonyManager.getDeviceId", v != null ? v : "");
        return v;
    }

    public Object hookGetSubscriberId(Object[] args) {
        Object thiz = args[0];
        String v = backupGetSubscriberId != null ? safeInvoke(backupGetSubscriberId, thiz) : null;
        log("TelephonyManager.getSubscriberId", v != null ? v : "");
        return v;
    }

    public Object hookGetSimSerialNumber(Object[] args) {
        Object thiz = args[0];
        String v = backupGetSimSerialNumber != null ? safeInvoke(backupGetSimSerialNumber, thiz) : null;
        log("TelephonyManager.getSimSerialNumber", v != null ? v : "");
        return v;
    }

    public Object hookGetLine1Number(Object[] args) {
        Object thiz = args[0];
        String v = backupGetLine1Number != null ? safeInvoke(backupGetLine1Number, thiz) : null;
        log("TelephonyManager.getLine1Number", v != null ? v : "");
        return v;
    }

    // Settings.Secure.getString(ContentResolver, String)  static: args={cr, name}
    public Object hookSettingsSecureGetString(Object[] args) {
        Object cr   = args[0];
        String name = (String) args[1];
        String v = backupSettingsSecureGetString != null
                ? safeInvoke(backupSettingsSecureGetString, null, cr, name)
                : null;
        log("Settings.Secure.getString[" + name + "]", v != null ? v : "");
        return v;
    }

    public Object hookGetMacAddress(Object[] args) {
        Object thiz = args[0];
        String v = backupWifiGetMacAddress != null ? safeInvoke(backupWifiGetMacAddress, thiz) : null;
        log("WifiInfo.getMacAddress", v != null ? v : "");
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
            log("NetworkInterface.getHardwareAddress", sb.toString());
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
                log("LocationManager.getLastKnownLocation[" + provider + "]",
                    lat + "," + lon);
            } catch (Exception e) {
                log("LocationManager.getLastKnownLocation[" + provider + "]", "err:" + e);
            }
        } else {
            log("LocationManager.getLastKnownLocation[" + provider + "]", "null");
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
        // only log URIs that contain sensitive authority keywords
        boolean sensitive = uriStr.contains("contact") || uriStr.contains("sms")
                || uriStr.contains("mms") || uriStr.contains("call_log")
                || uriStr.contains("calendar") || uriStr.contains("media");
        Object cursor = backupContentResolverQuery != null
                ? safeInvokeObject(backupContentResolverQuery, thiz, args[1], args[2], args[3], args[4])
                : null;
        if (sensitive) log("ContentResolver.query", uriStr);
        return cursor;
    }

    // CameraManager.openCamera(String, StateCallback, Handler)  instance: args={thiz, cameraId, cb, handler}
    public Object hookCameraManagerOpenCamera(Object[] args) {
        String cameraId = args[1] != null ? args[1].toString() : "";
        log("CameraManager.openCamera", cameraId);
        if (backupCameraManagerOpenCamera != null)
            safeInvokeObject(backupCameraManagerOpenCamera, args[0], args[1], args[2], args[3]);
        return null;
    }

    // MediaRecorder.setAudioSource(int)  instance: args={thiz, audioSource}
    public Object hookMediaRecorderSetAudioSource(Object[] args) {
        int src = args[1] != null ? ((Number) args[1]).intValue() : -1;
        log("MediaRecorder.setAudioSource", String.valueOf(src));
        if (backupMediaRecorderSetAudioSource != null)
            safeInvokeObject(backupMediaRecorderSetAudioSource, args[0], args[1]);
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
        log("Runtime.exec[]", cmd);
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
        String action = "";
        if (args[1] != null) {
            try { action = (String) args[1].getClass().getMethod("getAction").invoke(args[1]); }
            catch (Exception ignored) {}
            if (action == null) action = args[1].toString();
        }
        log("Activity.startActivity", action != null ? action : "");
        if (backupStartActivity != null)
            safeInvokeObject(backupStartActivity, args[0], args[1]);
        return null;
    }

    // Activity.startActivityForResult(Intent, int)  instance: args={thiz, intent, requestCode}
    public Object hookStartActivityForResult(Object[] args) {
        String action = "";
        if (args[1] != null) {
            try { action = (String) args[1].getClass().getMethod("getAction").invoke(args[1]); }
            catch (Exception ignored) {}
            if (action == null) action = args[1].toString();
        }
        int code = args[2] != null ? ((Number) args[2]).intValue() : -1;
        log("Activity.startActivityForResult", (action != null ? action : "") + " requestCode=" + code);
        if (backupStartActivityForResult != null)
            safeInvokeObject(backupStartActivityForResult, args[0], args[1], args[2]);
        return null;
    }

    // MediaRecorder.start()  instance: args={thiz}
    public Object hookMediaRecorderStart(Object[] args) {
        log("MediaRecorder.start", "");
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
        log("BroadcastReceiver.onReceive", action != null ? action : "");
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
            int code = response != null
                    ? (Integer) response.getClass().getMethod("code").invoke(response)
                    : -1;
            log("OkHttp3.RealCall.execute", url + " code=" + code);
        } catch (Exception e) {
            log("OkHttp3.RealCall.execute", "?");
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
        try {
            Object request = realCall.getClass().getMethod("request").invoke(realCall);
            url = request.getClass().getMethod("url").invoke(request).toString();
        } catch (Exception e) {
            url = "?";
        }
        final String capturedUrl = url;

        // Build a proxy that implements okhttp3.Callback
        Object wrappedCallback = origCallback;
        if (origCallback != null) {
            try {
                Class<?>[] ifaces = { origCallback.getClass().getInterfaces()[0] };
                // Walk up to find okhttp3.Callback interface
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
                                    log("OkHttp3.RealCall.enqueue", capturedUrl + " code=" + code);
                                } catch (Exception ignored) {
                                    log("OkHttp3.RealCall.enqueue", capturedUrl + " onResponse");
                                }
                            } else if ("onFailure".equals(mname)) {
                                log("OkHttp3.RealCall.enqueue", capturedUrl + " onFailure");
                            }
                            return method.invoke(finalOrig, methodArgs);
                        });
                }
            } catch (Exception e) {
                log("OkHttp3.RealCall.enqueue", capturedUrl + " proxy-wrap-failed");
            }
        }

        if (backupRealCallEnqueue != null)
            safeInvokeObject(backupRealCallEnqueue, realCall, wrappedCallback);
        return null;
    }

    // Volley StringRequest.deliverResponse(String)  instance: args={thiz, response}
    private static final int VOLLEY_PREVIEW = 256;
    public Object hookVolleyDeliverResponse(Object[] args) {
        String body = args[1] != null ? args[1].toString() : "";
        if (body.length() > VOLLEY_PREVIEW) body = body.substring(0, VOLLEY_PREVIEW) + "...";
        // Escape JSON special chars minimally
        body = body.replace("\\", "\\\\").replace("\"", "\\\"")
                   .replace("\r", " ").replace("\n", " ").replace("\t", " ");
        log("Volley.StringRequest.deliverResponse", body);
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

    private static String permissionCategory(String perm) {
        if (perm == null) return "UNKNOWN";
        // Camera
        if (perm.equals("android.permission.CAMERA")) return "CAMERA";
        // Microphone / Audio
        if (perm.equals("android.permission.RECORD_AUDIO")) return "MICROPHONE";
        // Location
        if (perm.equals("android.permission.ACCESS_FINE_LOCATION"))   return "LOCATION_FINE";
        if (perm.equals("android.permission.ACCESS_COARSE_LOCATION")) return "LOCATION_COARSE";
        if (perm.equals("android.permission.ACCESS_BACKGROUND_LOCATION")) return "LOCATION_BACKGROUND";
        // Contacts
        if (perm.equals("android.permission.READ_CONTACTS"))   return "CONTACTS_READ";
        if (perm.equals("android.permission.WRITE_CONTACTS"))  return "CONTACTS_WRITE";
        // Telephony / SMS
        if (perm.equals("android.permission.READ_PHONE_STATE"))  return "PHONE_STATE";
        if (perm.equals("android.permission.CALL_PHONE"))         return "PHONE_CALL";
        if (perm.equals("android.permission.READ_CALL_LOG"))      return "CALL_LOG_READ";
        if (perm.equals("android.permission.WRITE_CALL_LOG"))     return "CALL_LOG_WRITE";
        if (perm.equals("android.permission.SEND_SMS"))    return "SMS_SEND";
        if (perm.equals("android.permission.RECEIVE_SMS")) return "SMS_RECEIVE";
        if (perm.equals("android.permission.READ_SMS"))    return "SMS_READ";
        // Storage / Media
        if (perm.equals("android.permission.READ_EXTERNAL_STORAGE"))    return "STORAGE_READ";
        if (perm.equals("android.permission.WRITE_EXTERNAL_STORAGE"))   return "STORAGE_WRITE";
        if (perm.equals("android.permission.READ_MEDIA_IMAGES"))  return "MEDIA_IMAGES";
        if (perm.equals("android.permission.READ_MEDIA_VIDEO"))   return "MEDIA_VIDEO";
        if (perm.equals("android.permission.READ_MEDIA_AUDIO"))   return "MEDIA_AUDIO";
        // Calendar
        if (perm.equals("android.permission.READ_CALENDAR"))  return "CALENDAR_READ";
        if (perm.equals("android.permission.WRITE_CALENDAR")) return "CALENDAR_WRITE";
        // Body sensors
        if (perm.equals("android.permission.BODY_SENSORS")) return "BODY_SENSORS";
        // Activity recognition
        if (perm.equals("android.permission.ACTIVITY_RECOGNITION")) return "ACTIVITY_RECOGNITION";
        // Nearby / Bluetooth
        if (perm.equals("android.permission.BLUETOOTH_SCAN"))    return "BLUETOOTH_SCAN";
        if (perm.equals("android.permission.BLUETOOTH_CONNECT")) return "BLUETOOTH_CONNECT";
        if (perm.equals("android.permission.NEARBY_WIFI_DEVICES")) return "NEARBY_WIFI";
        // Notifications
        if (perm.equals("android.permission.POST_NOTIFICATIONS")) return "NOTIFICATIONS";
        // Fall back to the suffix after last dot
        int dot = perm.lastIndexOf('.');
        return dot >= 0 ? perm.substring(dot + 1) : perm;
    }

    private static void logPermission(String method, Object[] permArray) {
        if (permArray == null) return;
        for (Object p : permArray) {
            String perm = p != null ? p.toString() : "";
            String cat  = permissionCategory(perm);
            log(method, cat + "(" + perm + ")");
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

    // Activity.checkSelfPermission(String permission)  instance: args={thiz, permission}
    public Object hookCheckSelfPermission(Object[] args) {
        String perm = args[1] != null ? args[1].toString() : "";
        Integer result = null;
        if (backupCheckSelfPermission != null) {
            try { result = (Integer) backupCheckSelfPermission.invoke(args[0], perm); }
            catch (Exception e) { Log.e(TAG, "backup checkSelfPermission failed: " + e); }
        }
        int r = result != null ? result : -1;
        if (r != 0) log("Activity.checkSelfPermission",
                        permissionCategory(perm) + "(" + perm + ")=DENIED");
        return result != null ? result : -1;
    }

    // ActivityCompat.requestPermissions(Activity, String[], int)  static: args={activity, perms, code}
    public Object hookActivityCompatRequestPermissions(Object[] args) {
        try { logPermission("ActivityCompat.requestPermissions", (Object[]) args[1]); }
        catch (Exception e) { log("ActivityCompat.requestPermissions", "?"); }
        if (backupActivityCompatRequestPermissions != null)
            safeInvokeObject(backupActivityCompatRequestPermissions, null, args[0], args[1], args[2]);
        return null;
    }
}
