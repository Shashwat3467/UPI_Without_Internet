package com.demo.upimesh.crypto;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies the sender-device signature (ECDSA P-256 / SHA-256).
 *
 * Encryption to the server's public key gives CONFIDENTIALITY only: anyone can
 * encrypt to a public key. Authenticity comes from this signature, made by a
 * private key that never leaves the sender's device and is checked against the
 * public key registered on the sender's account.
 */
@Service
public class SignatureService {

    public static final String ALGORITHM = "SHA256withECDSA";

    /** Never throws: any malformed key/signature simply means "not verified". */
    public boolean verify(String devicePublicKeyBase64, String message, String signatureBase64) {
        if (devicePublicKeyBase64 == null || signatureBase64 == null || message == null) {
            return false;
        }
        try {
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(devicePublicKeyBase64)));
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initVerify(key);
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
}
