package com.demo.upimesh.service;

import com.demo.upimesh.crypto.HybridCryptoService;
import com.demo.upimesh.crypto.ServerKeyHolder;
import com.demo.upimesh.model.Account;
import com.demo.upimesh.model.AccountRepository;
import com.demo.upimesh.model.MeshPacket;
import com.demo.upimesh.model.PaymentInstruction;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Helper service that:
 *   - seeds demo accounts on startup
 *   - simulates "sender phone creates an encrypted packet" flow
 */
@Service
public class DemoService {

    private static final Logger log = LoggerFactory.getLogger(DemoService.class);

    @Autowired private AccountRepository accounts;
    @Autowired private HybridCryptoService crypto;
    @Autowired private ServerKeyHolder serverKey;
    @Autowired private SimulatedDeviceKeystore deviceKeystore;

    /** Every demo phone is provisioned with this PIN. */
    static final String DEMO_PIN = "1234";

    private void seed(String vpa, String name, String balance) {
        Account a = new Account(vpa, name, new BigDecimal(balance));
        try {
            // Provision the (simulated) phone; only the PUBLIC key reaches the server.
            a.setDevicePublicKey(deviceKeystore.register(vpa, DEMO_PIN));
        } catch (Exception e) {
            throw new IllegalStateException("Could not provision device for " + vpa, e);
        }
        accounts.save(a);
    }

    @PostConstruct
    public void seedAccounts() {
        if (accounts.count() == 0) {
            seed("alice@demo", "Alice", "5000.00");
            seed("bob@demo",   "Bob",   "1000.00");
            seed("carol@demo", "Carol", "2500.00");
            seed("dave@demo",  "Dave",  "500.00");
            log.info("Seeded 4 demo accounts, each with a provisioned device key");
        }
    }

    /**
     * Simulates the sender's phone:
     *   1. Build a PaymentInstruction with a fresh nonce + signedAt timestamp.
     *   2. Encrypt with the server's public key (hybrid RSA+AES).
     *   3. Wrap in a MeshPacket with TTL.
     *
     * In a real Android app, this exact code (minus the server-side reference)
     * would run on the phone. The phone would have already cached the server's
     * public key during a previous online session.
     */
    public MeshPacket createPacket(String senderVpa, String receiverVpa,
                                   BigDecimal amount, String pin, int ttl) throws Exception {
        PaymentInstruction instruction = new PaymentInstruction(
                senderVpa,
                receiverVpa,
                amount,
                UUID.randomUUID().toString(),       // nonce: server enforces uniqueness per sender
                Instant.now().toEpochMilli()        // signedAt: for the freshness check
        );
        // "On the phone": the PIN unlocks the device key, which signs the instruction.
        // A wrong PIN makes the device refuse (SecurityException). The PIN is never sent.
        instruction.setSignature(deviceKeystore.sign(senderVpa, pin, instruction.signingString()));

        String ciphertext = crypto.encrypt(instruction, serverKey.getPublicKey());

        MeshPacket packet = new MeshPacket();
        packet.setPacketId(UUID.randomUUID().toString());
        packet.setTtl(ttl);
        packet.setCreatedAt(Instant.now().toEpochMilli());
        packet.setCiphertext(ciphertext);
        return packet;
    }
}
