package com.demo.upimesh;

import com.demo.upimesh.crypto.HybridCryptoService;
import com.demo.upimesh.crypto.ServerKeyHolder;
import com.demo.upimesh.model.AccountRepository;
import com.demo.upimesh.model.MeshPacket;
import com.demo.upimesh.model.PaymentInstruction;
import com.demo.upimesh.service.BridgeIngestionService;
import com.demo.upimesh.service.BridgeIngestionService.IngestResult;
import com.demo.upimesh.service.DemoService;
import com.demo.upimesh.service.IdempotencyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for packet validation, sender authentication, and retries.
 */
@SpringBootTest
class HardeningTest {

    @Autowired private DemoService demo;
    @Autowired private BridgeIngestionService bridge;
    @Autowired private IdempotencyService idempotency;
    @Autowired private AccountRepository accounts;
    @Autowired private HybridCryptoService crypto;
    @Autowired private ServerKeyHolder serverKey;

    @BeforeEach
    void clear() {
        idempotency.clear();
    }

    private BigDecimal balance(String vpa) {
        return accounts.findById(vpa).orElseThrow().getBalance();
    }

    private MeshPacket wrap(String ciphertext) {
        MeshPacket p = new MeshPacket();
        p.setPacketId(UUID.randomUUID().toString());
        p.setTtl(5);
        p.setCreatedAt(System.currentTimeMillis());
        p.setCiphertext(ciphertext);
        return p;
    }

    // ------------------------------------------------------------------
    // Canonical encoding and replay protection
    // ------------------------------------------------------------------

    @Test
    void base64PaddingVariantCannotBypassIdempotency() throws Exception {
        // Need a ciphertext whose length is not a multiple of 3 so it ends in '='.
        MeshPacket packet = null;
        for (int i = 0; i < 100; i++) {
            MeshPacket candidate = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("10.00"), "1234", 5);
            if (candidate.getCiphertext().endsWith("=")) { packet = candidate; break; }
        }
        assertNotNull(packet, "could not produce a padded ciphertext");

        BigDecimal rahulBefore = balance("rahul@demo");

        assertEquals("SETTLED", bridge.ingest(packet, "bridge-1", 1).outcome());

        // Same bytes, different spelling: padding stripped.
        MeshPacket stripped = wrap(packet.getCiphertext().replace("=", ""));
        IngestResult r = bridge.ingest(stripped, "bridge-evil", 1);
        assertNotEquals("SETTLED", r.outcome(), "padding variant must not settle again");
        assertEquals("non_canonical_base64", r.reason());

        // Same bytes, different spelling: flip an unused trailing bit.
        String ct = packet.getCiphertext();
        int last = ct.indexOf('=') - 1;
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char flipped = alphabet.charAt(alphabet.indexOf(ct.charAt(last)) ^ 1);
        String bitVariant = ct.substring(0, last) + flipped + ct.substring(last + 1);
        IngestResult r2 = bridge.ingest(wrap(bitVariant), "bridge-evil", 1);
        assertNotEquals("SETTLED", r2.outcome(), "trailing-bit variant must not settle again");

        assertEquals(rahulBefore.subtract(new BigDecimal("10.00")), balance("rahul@demo"),
                "sender must be debited exactly once");
    }

    @Test
    void hashIsOverDecodedBytesNotTheString() throws Exception {
        MeshPacket p = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("1.00"), "1234", 5);
        assertEquals(crypto.hashCiphertext(p.getCiphertext()), crypto.hashCiphertext(p.getCiphertext()));
        // A non-canonical spelling is refused outright rather than hashed to a different key.
        if (p.getCiphertext().endsWith("=")) {
            assertThrows(IllegalArgumentException.class,
                    () -> crypto.hashCiphertext(p.getCiphertext().replace("=", "")));
        }
    }

    @Test
    void reEncryptedCopyOfSamePaymentIsStoppedByNonceConstraint() throws Exception {
        // Second line of defence: even a completely different ciphertext carrying the
        // SAME signed instruction (same nonce) must not settle twice.
        MeshPacket original = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("20.00"), "1234", 5);
        PaymentInstruction inner = crypto.decrypt(original.getCiphertext());
        MeshPacket reWrapped = wrap(crypto.encrypt(inner, serverKey.getPublicKey()));
        assertNotEquals(original.getCiphertext(), reWrapped.getCiphertext());

        BigDecimal rahulBefore = balance("rahul@demo");
        assertEquals("SETTLED", bridge.ingest(original, "b1", 1).outcome());
        assertEquals("DUPLICATE_DROPPED", bridge.ingest(reWrapped, "b2", 1).outcome());
        assertEquals(rahulBefore.subtract(new BigDecimal("20.00")), balance("rahul@demo"));
    }

    // ------------------------------------------------------------------
    // Sender authentication
    // ------------------------------------------------------------------

    private String signWithAttackerKey(PaymentInstruction ins) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair attacker = g.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(attacker.getPrivate());
        s.update(ins.signingString().getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    private PaymentInstruction instruction(String amount) {
        return new PaymentInstruction("rahul@demo", "priya@demo", new BigDecimal(amount),
                UUID.randomUUID().toString(), System.currentTimeMillis());
    }

    @Test
    void forgedPacketSignedWithWrongKeyIsRejected() throws Exception {
        PaymentInstruction forged = instruction("500.00");
        forged.setSignature(signWithAttackerKey(forged));
        MeshPacket packet = wrap(crypto.encrypt(forged, serverKey.getPublicKey())); // anyone can encrypt

        BigDecimal rahulBefore = balance("rahul@demo");
        IngestResult r = bridge.ingest(packet, "attacker", 1);
        assertEquals("INVALID", r.outcome());
        assertEquals("bad_signature", r.reason());
        assertEquals(rahulBefore, balance("rahul@demo"));
    }

    @Test
    void unsignedPacketIsRejected() throws Exception {
        PaymentInstruction unsigned = instruction("500.00"); // no signature at all
        IngestResult r = bridge.ingest(wrap(crypto.encrypt(unsigned, serverKey.getPublicKey())), "attacker", 1);
        assertEquals("INVALID", r.outcome());
        assertEquals("missing_signature", r.reason());
    }

    @Test
    void alteringAmountAfterSigningInvalidatesSignature() throws Exception {
        MeshPacket original = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("10.00"), "1234", 5);
        PaymentInstruction inner = crypto.decrypt(original.getCiphertext());
        inner.setAmount(new BigDecimal("4000.00")); // attacker who somehow holds plaintext changes the amount

        IngestResult r = bridge.ingest(wrap(crypto.encrypt(inner, serverKey.getPublicKey())), "attacker", 1);
        assertEquals("INVALID", r.outcome());
        assertEquals("bad_signature", r.reason());
    }

    @Test
    void wrongPinMeansTheDeviceWillNotSign() {
        assertThrows(SecurityException.class,
                () -> demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("10.00"), "0000", 5));
    }

    // ------------------------------------------------------------------
    // Concurrent settlement and retries
    // ------------------------------------------------------------------

    @Test
    void concurrentDistinctPaymentsFromSameSenderAllSettle() throws Exception {
        int n = 8;
        BigDecimal rahulBefore = balance("rahul@demo");
        BigDecimal priyaBefore = balance("priya@demo");

        List<MeshPacket> packets = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            packets.add(demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("10.00"), "1234", 5));
        }

        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<IngestResult>> futures = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final MeshPacket p = packets.get(i);
            final String node = "bridge-" + i;
            futures.add(pool.submit(() -> {
                start.await();
                return bridge.ingest(p, node, 2);
            }));
        }
        start.countDown();

        for (Future<IngestResult> f : futures) {
            IngestResult r = f.get(30, TimeUnit.SECONDS);
            assertEquals("SETTLED", r.outcome(),
                    "legitimate payment lost to lock contention: " + r.reason());
        }
        pool.shutdown();

        BigDecimal total = new BigDecimal("10.00").multiply(BigDecimal.valueOf(n));
        assertEquals(rahulBefore.subtract(total), balance("rahul@demo"));
        assertEquals(priyaBefore.add(total), balance("priya@demo"));
    }

    @Test
    void claimIsReleasedSoARetryIsNotDroppedAsDuplicate() {
        // Unit-level check of the primitive the retry path relies on.
        assertTrue(idempotency.claim("hash-x"));
        assertFalse(idempotency.claim("hash-x"));
        idempotency.release("hash-x");
        assertTrue(idempotency.claim("hash-x"));
    }

    // ------------------------------------------------------------------
    // Input validation
    // ------------------------------------------------------------------

    @Test
    void oversizedCiphertextIsRejectedBeforeAnyCrypto() {
        IngestResult r = bridge.ingest(wrap("A".repeat(10_000)), "bridge-x", 1);
        assertEquals("INVALID", r.outcome());
        assertEquals("ciphertext_too_large", r.reason());
    }

    @Test
    void amountAboveLimitAndSelfPaymentAreRejected() throws Exception {
        MeshPacket big = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("10000.01"), "1234", 5);
        assertEquals("amount_exceeds_limit", bridge.ingest(big, "b", 1).reason());

        MeshPacket self = demo.createPacket("rahul@demo", "rahul@demo", new BigDecimal("1.00"), "1234", 5);
        assertEquals("self_payment", bridge.ingest(self, "b", 1).reason());
    }
}
