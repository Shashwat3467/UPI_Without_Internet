package com.demo.upimesh.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stands in for the phone's secure element / Android Keystore.
 *
 * Each simulated device owns an EC key pair. The private key never leaves this
 * class; it can only be used to sign after the correct PIN is supplied (just
 * like a real device unlocks its key with the user's PIN/biometric). The server
 * only ever learns the PUBLIC key, which is stored on the Account.
 *
 * In the real system this logic lives on Android (hardware-backed Keystore).
 */
@Service
public class SimulatedDeviceKeystore {

    private record Device(KeyPair keyPair, byte[] salt, byte[] pinDigest) {}

    @org.springframework.beans.factory.annotation.Autowired private com.demo.upimesh.crypto.PersistentKeyStore store;

    private final Map<String, Device> devices = new ConcurrentHashMap<>();
    private final SecureRandom rng = new SecureRandom();

    /** "Provision" a device for a VPA. Returns the Base64 X.509 public key to register on the account. */
    public String register(String vpa, String pin) throws Exception {
        KeyPair kp = store.loadOrCreate("device-" + com.demo.upimesh.crypto.PacketCodec.sha256Hex(vpa.getBytes(StandardCharsets.UTF_8)), "EC");
        byte[] salt = new byte[16];
        rng.nextBytes(salt);
        devices.put(vpa, new Device(kp, salt, digest(salt, pin)));
        return Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
    }

    /** Sign on the device. Throws SecurityException on a wrong PIN. */
    public String sign(String vpa, String pin, String message) throws GeneralSecurityException {
        Device d = devices.get(vpa);
        if (d == null) {
            throw new IllegalArgumentException("No device registered for " + vpa);
        }
        if (!MessageDigest.isEqual(d.pinDigest(), digest(d.salt(), pin))) {
            throw new SecurityException("Wrong PIN: device refused to sign");
        }
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(d.keyPair().getPrivate());
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    private static byte[] digest(byte[] salt, String pin) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        return md.digest((pin == null ? "" : pin).getBytes(StandardCharsets.UTF_8));
    }
}
