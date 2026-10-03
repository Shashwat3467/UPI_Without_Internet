package com.demo.upimesh.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Strict, canonical handling of the wire ciphertext.
 *
 * WHY THIS EXISTS (security fix):
 * Java's Base64 decoder is lenient: it accepts a missing '=' padding and
 * non-zero "unused" trailing bits. That means several DIFFERENT strings can
 * decode to the SAME bytes. If the idempotency key is a hash of the *string*,
 * a malicious relay can mint variants of a packet that each get a different
 * hash, slip past the duplicate check and settle the same payment again.
 *
 * Fix: (1) reject any string that is not the canonical encoding of its bytes,
 * and (2) hash the decoded BYTES, never the string.
 */
public final class PacketCodec {

    /** Upper bound on the Base64 string (≈3 KB of raw bytes). Real packets are ~1 KB. */
    public static final int MAX_BASE64_CHARS = 4096;

    private PacketCodec() {}

    /**
     * Decode base64 and require that re-encoding yields the exact same string.
     * Throws IllegalArgumentException whose message is a short reason code.
     */
    public static byte[] decodeCanonical(String base64) {
        if (base64 == null || base64.isEmpty()) {
            throw new IllegalArgumentException("empty_ciphertext");
        }
        if (base64.length() > MAX_BASE64_CHARS) {
            throw new IllegalArgumentException("ciphertext_too_large");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("bad_base64");
        }
        if (!Base64.getEncoder().encodeToString(raw).equals(base64)) {
            throw new IllegalArgumentException("non_canonical_base64");
        }
        return raw;
    }

    /** SHA-256 of raw bytes as lowercase hex. This is the idempotency key. */
    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 is mandatory on every JVM
        }
    }
}
