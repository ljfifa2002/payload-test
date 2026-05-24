package com.pecker.payload;

import android.util.Log;
import java.lang.reflect.Method;

/**
 * LSPlant hook callback container.
 *
 * Callback signature rule (LSPlant v5):
 *   - First param: hooker object (this class instance, passed by LSPlant)
 *   - For instance methods: second param is the target "this"
 *   - For static methods: no extra "this" param
 *   - Return type must match the target method
 *
 * backup_* fields are set from C++ after lsplant::Hook() returns.
 */
public class HookerBridge {

    private static final String TAG = "payload";

    // ---- backup methods (set from C++ via reflection) ----
    public Method backupGetDeviceId;
    public Method backupGetSubscriberId;
    public Method backupGetSimSerialNumber;
    public Method backupGetLine1Number;
    public Method backupSettingsSecureGetString;
    public Method backupWifiGetMacAddress;
    public Method backupNetworkInterfaceGetHardwareAddress;

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

    // ---- TelephonyManager.getDeviceId() ----
    public String hookGetDeviceId(Object thiz) {
        String v = backupGetDeviceId != null ? safeInvoke(backupGetDeviceId, thiz) : null;
        log("TelephonyManager.getDeviceId", v != null ? v : "");
        return v;
    }

    // ---- TelephonyManager.getSubscriberId() ----
    public String hookGetSubscriberId(Object thiz) {
        String v = backupGetSubscriberId != null ? safeInvoke(backupGetSubscriberId, thiz) : null;
        log("TelephonyManager.getSubscriberId", v != null ? v : "");
        return v;
    }

    // ---- TelephonyManager.getSimSerialNumber() ----
    public String hookGetSimSerialNumber(Object thiz) {
        String v = backupGetSimSerialNumber != null ? safeInvoke(backupGetSimSerialNumber, thiz) : null;
        log("TelephonyManager.getSimSerialNumber", v != null ? v : "");
        return v;
    }

    // ---- TelephonyManager.getLine1Number() ----
    public String hookGetLine1Number(Object thiz) {
        String v = backupGetLine1Number != null ? safeInvoke(backupGetLine1Number, thiz) : null;
        log("TelephonyManager.getLine1Number", v != null ? v : "");
        return v;
    }

    // ---- Settings.Secure.getString(ContentResolver, String) ----
    // Static target: first param after hooker is ContentResolver, second is name
    public String hookSettingsSecureGetString(Object cr, String name) {
        String v = backupSettingsSecureGetString != null
                ? safeInvoke(backupSettingsSecureGetString, null, cr, name)
                : null;
        if ("android_id".equals(name)) {
            log("Settings.Secure.getString[android_id]", v != null ? v : "");
        }
        return v;
    }

    // ---- WifiInfo.getMacAddress() ----
    public String hookGetMacAddress(Object thiz) {
        String v = backupWifiGetMacAddress != null ? safeInvoke(backupWifiGetMacAddress, thiz) : null;
        log("WifiInfo.getMacAddress", v != null ? v : "");
        return v;
    }

    // ---- NetworkInterface.getHardwareAddress() ----
    public byte[] hookGetHardwareAddress(Object thiz) {
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
}
