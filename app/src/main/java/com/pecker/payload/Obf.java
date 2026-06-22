package com.pecker.payload;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime decoder for build-time-encoded sensitive string literals.
 *
 * <p>Wrap a sensitive literal as {@code Obf.s("隐私政策")}. The buildSrc ASM
 * transform {@code com.pecker.build.StringObfFactory} rewrites the constant in
 * the .class to {@code MARK + base64(xor(utf8))} at compile time; at runtime
 * {@code s()} reverses it. A string that was NOT rewritten (dev builds without
 * the transform, unit tests, or values passed as a variable) has no MARK prefix
 * and is returned unchanged — so wrapping is always safe.
 *
 * <p>Threat-model note (consistent with the rest of the protection plan): the
 * key below ships inside the dex and can be extracted; its job is to keep the
 * detection vocabulary out of a plain {@code strings}/jadx dump, not to be a
 * real secret. Rotate per release. This is the post-dump "decor" layer — it does
 * NOT replace the dex AES wall, which is what hides the ~120 method names.
 *
 * <p>Rules for callers: only wrap direct string literals (not concatenations —
 * write {@code Obf.s("a") + b}, not {@code Obf.s("a" + b)}); never compare an
 * encoded literal with {@code ==} (use {@code .equals()}); skip reflection
 * target strings (public API, low value / high risk).
 */
public final class Obf {
    private Obf() {}

    // These 32 bytes MUST match tools/ObfTransform.java's KEY byte-for-byte.
    // Rotate both together via pecker-agent/tools/rotate-keys.cmd.
    private static final byte[] KEY = {
        (byte)0xFB, (byte)0x5B, (byte)0xA3, (byte)0x43, (byte)0x55, (byte)0xDF, (byte)0xD8, (byte)0x13,
        (byte)0x54, (byte)0xA3, (byte)0xA9, (byte)0x09, (byte)0x56, (byte)0xFD, (byte)0x41, (byte)0x11,
        (byte)0xEB, (byte)0x1A, (byte)0xF6, (byte)0x13, (byte)0x13, (byte)0x18, (byte)0xE9, (byte)0x62,
        (byte)0x32, (byte)0x59, (byte)0x26, (byte)0x53, (byte)0x78, (byte)0x56, (byte)0xAE, (byte)0xA8,
    };

    // Sentinel = U+0001 (written as (char)1 to avoid an invisible control char in
    // source). It never starts a normal literal, so non-encoded values pass through.
    private static final char MARK = (char) 1;

    private static final ConcurrentHashMap<String, String> CACHE = new ConcurrentHashMap<>();

    /** Decode a build-time-encoded literal; pass through anything without MARK. */
    public static String s(String v) {
        if (v == null || v.isEmpty() || v.charAt(0) != MARK) return v;
        String hit = CACHE.get(v);
        if (hit != null) return hit;
        byte[] b = Base64.decode(v.substring(1), Base64.NO_WRAP);
        for (int i = 0; i < b.length; i++) b[i] ^= KEY[i & 31];
        String r = new String(b, StandardCharsets.UTF_8);
        CACHE.put(v, r);
        return r;
    }
}
