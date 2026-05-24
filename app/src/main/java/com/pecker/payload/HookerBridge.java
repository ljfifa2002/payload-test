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
    public Method backupActivityOnCreate;  // diagnostic

    // ---- diagnostic: Activity.onCreate ----
    public static void hookActivityOnCreate(Object hooker, Object thiz, Object bundle) {
        Log.i(TAG, "[probe] Activity.onCreate fired in pid=" + android.os.Process.myPid());
        HookerBridge h = (HookerBridge) hooker;
        if (h.backupActivityOnCreate != null) {
            try { h.backupActivityOnCreate.invoke(thiz, bundle); }
            catch (Exception e) { Log.e(TAG, "backup Activity.onCreate failed: " + e); }
        }
    }

    // ---- helpers ----

    private static String safeInvoke(Method m, Object thiz, Object... args) {
        try {
            return (String) m.invoke(thiz, args);
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

    // ---- Static callbacks (LSPlant requires static: first param = hooker object) ----

    // TelephonyManager.getDeviceId()
    public static String hookGetDeviceId(Object hooker, Object thiz) {
        Log.d(TAG, "[probe] hookGetDeviceId called");
        HookerBridge h = (HookerBridge) hooker;
        String v = h.backupGetDeviceId != null ? safeInvoke(h.backupGetDeviceId, thiz) : null;
        log("TelephonyManager.getDeviceId", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getSubscriberId()
    public static String hookGetSubscriberId(Object hooker, Object thiz) {
        Log.d(TAG, "[probe] hookGetSubscriberId called");
        HookerBridge h = (HookerBridge) hooker;
        String v = h.backupGetSubscriberId != null ? safeInvoke(h.backupGetSubscriberId, thiz) : null;
        log("TelephonyManager.getSubscriberId", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getSimSerialNumber()
    public static String hookGetSimSerialNumber(Object hooker, Object thiz) {
        Log.d(TAG, "[probe] hookGetSimSerialNumber called");
        HookerBridge h = (HookerBridge) hooker;
        String v = h.backupGetSimSerialNumber != null ? safeInvoke(h.backupGetSimSerialNumber, thiz) : null;
        log("TelephonyManager.getSimSerialNumber", v != null ? v : "");
        return v;
    }

    // TelephonyManager.getLine1Number()
    public static String hookGetLine1Number(Object hooker, Object thiz) {
        Log.d(TAG, "[probe] hookGetLine1Number called");
        HookerBridge h = (HookerBridge) hooker;
        String v = h.backupGetLine1Number != null ? safeInvoke(h.backupGetLine1Number, thiz) : null;
        log("TelephonyManager.getLine1Number", v != null ? v : "");
        return v;
    }

    // Settings.Secure.getString(ContentResolver, String)  [static target]
    public static String hookSettingsSecureGetString(Object hooker, Object cr, String name) {
        Log.d(TAG, "[probe] hookSettingsSecureGetString key=" + name);
        HookerBridge h = (HookerBridge) hooker;
        String v = h.backupSettingsSecureGetString != null
                ? safeInvoke(h.backupSettingsSecureGetString, null, cr, name)
                : null;
        log("Settings.Secure.getString[" + name + "]", v != null ? v : "");
        return v;
    }

    // WifiInfo.getMacAddress()
    public static String hookGetMacAddress(Object hooker, Object thiz) {
        Log.d(TAG, "[probe] hookGetMacAddress called");
        HookerBridge h = (HookerBridge) hooker;
        String v = h.backupWifiGetMacAddress != null ? safeInvoke(h.backupWifiGetMacAddress, thiz) : null;
        log("WifiInfo.getMacAddress", v != null ? v : "");
        return v;
    }

    // NetworkInterface.getHardwareAddress()
    public static byte[] hookGetHardwareAddress(Object hooker, Object thiz) {
        Log.d(TAG, "[probe] hookGetHardwareAddress called");
        HookerBridge h = (HookerBridge) hooker;
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
}
