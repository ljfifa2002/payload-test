package com.pecker.payload;

import android.util.Log;
import java.lang.reflect.Method;

public class HookerBridge {

    private static final String TAG = "payload";

    // backup methods set from C++ after lsplant::Hook()
    public Method backupGetDeviceId;
    public Method backupGetSubscriberId;
    public Method backupGetSimSerialNumber;
    public Method backupGetLine1Number;
    public Method backupSettingsSecureGetString;
    public Method backupWifiGetMacAddress;
    public Method backupNetworkInterfaceGetHardwareAddress;
    public Method backupActivityOnCreate;

    // LSPlant 6.4 dispatch convention:
    //   callback(Object[] args) -> Object
    //   args[0] = hooker instance (HookerBridge)
    //   args[1] = thiz  (null for static target methods)
    //   args[2..] = method parameters (for static: args[1..] = parameters)
    //
    // Instance target:  args = [hooker, thiz, param1, param2, ...]
    // Static target:    args = [hooker, param1, param2, ...]

    // ---- helpers ----

    private static String safeInvoke(Method m, Object thiz, Object... params) {
        try {
            return (String) m.invoke(thiz, params);
        } catch (Exception e) {
            Log.e(TAG, "backup invoke failed: " + e);
            return null;
        }
    }

    private static byte[] safeInvokeBytes(Method m, Object thiz) {
        try {
            return (byte[]) m.invoke(thiz);
        } catch (Exception e) {
            Log.e(TAG, "backup invoke bytes failed: " + e);
            return null;
        }
    }

    private static void log(String method, String data) {
        Log.i(TAG, "{\"type\":\"behavior\",\"method\":\"" + method + "\",\"data\":\"" + data + "\",\"timestamp\":" + System.currentTimeMillis() + "}");
    }

    // ---- Static callbacks: all use ([Ljava/lang/Object;)Ljava/lang/Object; ----

    // TelephonyManager.getDeviceId()  [instance: args={hooker, thiz}]
    public static Object hookGetDeviceId(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object thiz = args[1];
        String v = h.backupGetDeviceId != null ? safeInvoke(h.backupGetDeviceId, thiz) : null;
        log("TelephonyManager.getDeviceId", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getSubscriberId()
    public static Object hookGetSubscriberId(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object thiz = args[1];
        String v = h.backupGetSubscriberId != null ? safeInvoke(h.backupGetSubscriberId, thiz) : null;
        log("TelephonyManager.getSubscriberId", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getSimSerialNumber()
    public static Object hookGetSimSerialNumber(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object thiz = args[1];
        String v = h.backupGetSimSerialNumber != null ? safeInvoke(h.backupGetSimSerialNumber, thiz) : null;
        log("TelephonyManager.getSimSerialNumber", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getLine1Number()
    public static Object hookGetLine1Number(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object thiz = args[1];
        String v = h.backupGetLine1Number != null ? safeInvoke(h.backupGetLine1Number, thiz) : null;
        log("TelephonyManager.getLine1Number", v != null ? v : "");
        return v;
    }

    // Settings.Secure.getString(ContentResolver, String)  [static: args={hooker, cr, name}]
    public static Object hookSettingsSecureGetString(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object cr   = args[1];
        String name = (String) args[2];
        String v = h.backupSettingsSecureGetString != null
                ? safeInvoke(h.backupSettingsSecureGetString, null, cr, name)
                : null;
        log("Settings.Secure.getString[" + name + "]", v != null ? v : "");
        return v;
    }

    // WifiInfo.getMacAddress()
    public static Object hookGetMacAddress(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object thiz = args[1];
        String v = h.backupWifiGetMacAddress != null ? safeInvoke(h.backupWifiGetMacAddress, thiz) : null;
        log("WifiInfo.getMacAddress", v != null ? v : "");
        return v;
    }

    // NetworkInterface.getHardwareAddress()  -> byte[]
    public static Object hookGetHardwareAddress(Object[] args) {
        HookerBridge h = (HookerBridge) args[0];
        Object thiz = args[1];
        byte[] v = h.backupNetworkInterfaceGetHardwareAddress != null
                ? safeInvokeBytes(h.backupNetworkInterfaceGetHardwareAddress, thiz)
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

    // Activity.onCreate(Bundle)  [instance: args={hooker, thiz, bundle}]
    public static Object hookActivityOnCreate(Object[] args) {
        Log.i(TAG, "[probe] Activity.onCreate fired in pid=" + android.os.Process.myPid());
        HookerBridge h = (HookerBridge) args[0];
        Object thiz   = args[1];
        Object bundle = args[2];
        if (h.backupActivityOnCreate != null) {
            try { h.backupActivityOnCreate.invoke(thiz, bundle); }
            catch (Exception e) { Log.e(TAG, "backup Activity.onCreate failed: " + e); }
        }
        return null;
    }
}
