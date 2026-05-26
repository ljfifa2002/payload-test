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
    // Phase 4
    public Method backupContentResolverQuery;
    public Method backupCameraManagerOpenCamera;
    public Method backupMediaRecorderSetAudioSource;
    // Phase 5
    public Method backupUrlOpenConnection;
    public Method backupOkHttpNewCall;
    // Phase 6: sensors
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

    private static void log(String method, String data) {
        Log.i(TAG, "{\"type\":\"behavior\",\"method\":\"" + method + "\",\"data\":\"" + data + "\",\"timestamp\":" + System.currentTimeMillis() + "}");
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

    // ---- Phase 4: sensitive data ----

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

    // ---- Phase 6: sensors ----

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

    // Activity.requestPermissions(String[] perms, int requestCode)  instance: args={thiz, perms, code}
    public Object hookRequestPermissions(Object[] args) {
        try {
            Object[] perms = (Object[]) args[1];
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < perms.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(perms[i]);
            }
            log("Activity.requestPermissions", sb.toString());
        } catch (Exception e) { log("Activity.requestPermissions", "?"); }
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
        // Only log denials (result != 0) to reduce noise
        int r = result != null ? result : -1;
        if (r != 0) log("Activity.checkSelfPermission", perm + "=DENIED");
        return result != null ? result : -1;
    }

    // ActivityCompat.requestPermissions(Activity, String[], int)  static: args={activity, perms, code}
    public Object hookActivityCompatRequestPermissions(Object[] args) {
        try {
            Object[] perms = (Object[]) args[1];
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < perms.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(perms[i]);
            }
            log("ActivityCompat.requestPermissions", sb.toString());
        } catch (Exception e) { log("ActivityCompat.requestPermissions", "?"); }
        if (backupActivityCompatRequestPermissions != null)
            safeInvokeObject(backupActivityCompatRequestPermissions, null, args[0], args[1], args[2]);
        return null;
    }
}
