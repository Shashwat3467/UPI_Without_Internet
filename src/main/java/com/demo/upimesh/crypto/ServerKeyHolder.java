package com.demo.upimesh.crypto;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Holds the server's RSA keypair.
 *
 * In production, the private key would live in an HSM (Hardware Security Module)
 * or a managed key service. Private keys must not be committed to source control.
 *
 * For this demo we persist the keypair in the configured key directory. The public key is
 * exposed via /api/server-key so the (simulated) sender devices can use it to
 * encrypt payloads.
 */
@Component
public class ServerKeyHolder {

    private static final Logger log = LoggerFactory.getLogger(ServerKeyHolder.class);

    @org.springframework.beans.factory.annotation.Autowired private PersistentKeyStore store;
    private KeyPair keyPair;

    @PostConstruct
    public void init() throws Exception {
        this.keyPair = store.loadOrCreate("server", "RSA");
        log.info("Server RSA keypair loaded (2048-bit). Public key fingerprint: {}",
                getPublicKeyBase64().substring(0, 32) + "...");
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }
}
