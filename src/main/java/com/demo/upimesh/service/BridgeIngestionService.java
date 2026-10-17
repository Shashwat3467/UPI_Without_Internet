package com.demo.upimesh.service;

import com.demo.upimesh.crypto.HybridCryptoService;
import com.demo.upimesh.crypto.PacketCodec;
import com.demo.upimesh.crypto.SignatureService;
import com.demo.upimesh.model.Account;
import com.demo.upimesh.model.AccountRepository;
import com.demo.upimesh.model.MeshPacket;
import com.demo.upimesh.model.PaymentInstruction;
import com.demo.upimesh.model.Transaction;
import com.demo.upimesh.model.TransactionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;

/**
 * Orchestrates the full server-side pipeline for one inbound packet from a
 * bridge node:
 *
 *   1. Strictly decode the Base64 (reject non-canonical spellings, oversize input)
 *      and hash the decoded BYTES.
 *   2. Try to claim that hash via the idempotency cache. Duplicate => drop.
 *   3. Decrypt with the server's private key (GCM tag detects tampering).
 *   4. Validate the instruction's fields.
 *   5. Freshness check (replay window).
 *   6. Verify the sender DEVICE's signature (authenticity).
 *   7. Settle in a DB transaction. Transient contention is retried; if it still
 *      fails, the bridge can retry (outcome RETRY_LATER). Claims release in finally.
 *
 * Defence in depth against double settlement: in-memory claim, then DB unique
 * constraints on packetHash and on (senderVpa, nonce).
 */
@Service
public class BridgeIngestionService {

    private static final Logger log = LoggerFactory.getLogger(BridgeIngestionService.class);

    /** hopCount arrives in an untrusted header; clamp it so it can't poison the ledger/analytics. */
    private static final int MAX_HOPS = 32;

    private static final Pattern VPA = Pattern.compile("^[a-z0-9._-]{1,64}@[a-z0-9]{1,32}$");
    private static final Pattern NONCE = Pattern.compile("^[A-Za-z0-9-]{8,64}$");

    @Autowired private HybridCryptoService crypto;
    @Autowired private IdempotencyService idempotency;
    @Autowired private SettlementService settlement;
    @Autowired private SignatureService signatures;
    @Autowired private AccountRepository accounts;
    @Autowired private TransactionRepository transactions;

    @Value("${upi.mesh.packet-max-age-seconds:86400}")
    private long maxAgeSeconds;

    @Value("${upi.mesh.max-amount:10000.00}")
    private BigDecimal maxAmount;

    @Value("${upi.mesh.settle-max-retries:10}")
    private int maxRetries;

    public IngestResult ingest(MeshPacket packet, String bridgeNodeId, int hopCount) {
        if (packet == null) return IngestResult.invalid("?", "missing_packet");
        if (bridgeNodeId == null || !bridgeNodeId.matches("[A-Za-z0-9._-]{1,64}"))
            return IngestResult.invalid("?", "bad_bridge_id");
        int hops = Math.max(0, Math.min(hopCount, MAX_HOPS));
        String packetHash = "?";
        boolean claimed = false;
        try {
            // ---- 1. Canonical decode + hash of the decoded bytes ----
            byte[] raw;
            try {
                raw = PacketCodec.decodeCanonical(packet.getCiphertext());
            } catch (IllegalArgumentException e) {
                log.warn("Rejected malformed packet from bridge {}: {}", bridgeNodeId, e.getMessage());
                return IngestResult.invalid("?", e.getMessage());
            }
            packetHash = PacketCodec.sha256Hex(raw);
            String shortHash = packetHash.substring(0, 12) + "...";

            // ---- 2. Idempotency gate ----
            if (transactions.existsByPacketHash(packetHash)) return IngestResult.duplicate(packetHash);
            if (!idempotency.claim(packetHash)) {
                log.info("IN-FLIGHT packet {} from bridge {} - retry required", shortHash, bridgeNodeId);
                return IngestResult.retryLater(packetHash, "processing");
            }
            claimed = true;

            // ---- 3. Decrypt ----
            PaymentInstruction instruction;
            try {
                instruction = crypto.decryptBytes(raw);
            } catch (Exception e) {
                log.warn("Decryption failed for packet {}: {}", shortHash, e.getMessage());
                return IngestResult.invalid(packetHash, "decryption_failed");
            }

            // ---- 4. Field validation ----
            String problem = validate(instruction);
            if (problem != null) {
                log.warn("Packet {} invalid: {}", shortHash, problem);
                return IngestResult.invalid(packetHash, problem);
            }

            // ---- 5. Freshness (replay window) ----
            Instant now = Instant.now();
            Instant signedAt = Instant.ofEpochMilli(instruction.getSignedAt());
            if (signedAt.isBefore(now.minusSeconds(maxAgeSeconds)))
                return IngestResult.invalid(packetHash, "stale_packet");
            if (signedAt.isAfter(now.plusSeconds(300)))
                return IngestResult.invalid(packetHash, "future_dated");

            // ---- 6. Sender authenticity: device signature ----
            Account sender = accounts.findById(instruction.getSenderVpa()).orElse(null);
            if (sender == null) {
                return IngestResult.invalid(packetHash, "unknown_sender");
            }
            if (!signatures.verify(sender.getDevicePublicKey(),
                    instruction.signingString(), instruction.getSignature())) {
                log.warn("Packet {} has an INVALID SIGNATURE for {} (bridge {})",
                        shortHash, instruction.getSenderVpa(), bridgeNodeId);
                return IngestResult.invalid(packetHash, "bad_signature");
            }

            // ---- 7. Settle (with retry on transient contention) ----
            return settleWithRetry(instruction, packetHash, bridgeNodeId, hops);

        } catch (Exception e) {
            // Unknown failure: we can't be sure what state we are in. Give the claim back so the
            // payment isn't lost; the DB unique constraints still make double-settlement impossible.
            log.error("Ingestion error: {}", e.getMessage(), e);
            return IngestResult.retryLater(packetHash, "internal_error");
        } finally {
            if (claimed) idempotency.release(packetHash);
        }
    }

    private IngestResult settleWithRetry(PaymentInstruction instruction, String packetHash,
                                         String bridgeNodeId, int hops) {
        for (int attempt = 0; ; attempt++) {
            try {
                Transaction tx = settlement.settle(instruction, packetHash, bridgeNodeId, hops);
                return IngestResult.settled(packetHash, tx);

            } catch (InvalidInstructionException e) {
                return IngestResult.invalid(packetHash, e.getMessage()); // permanent invalid instruction

            } catch (DataIntegrityViolationException e) {
                // Either the same bytes or the same (sender, nonce) already settled. Confirm it's
                // really a duplicate before calling it one, so real bugs are not masked.
                if (transactions.existsByPacketHash(packetHash)
                        || transactions.existsBySenderVpaAndNonce(instruction.getSenderVpa(), instruction.getNonce())) {
                    log.info("DUPLICATE (db constraint) packet {} nonce {}",
                            packetHash.substring(0, 12) + "...", instruction.getNonce());
                    return IngestResult.duplicate(packetHash);
                }
                throw e;

            } catch (TransientDataAccessException e) {
                // Includes optimistic-lock conflicts: two legit payments touching the same account.
                if (attempt >= maxRetries) {
                    log.warn("Settlement still failing after {} retries; releasing claim", attempt);
                    return IngestResult.retryLater(packetHash, "contention");
                }
                try {
                    Thread.sleep(ThreadLocalRandom.current().nextLong(5, 25) * (attempt + 1));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return IngestResult.retryLater(packetHash, "interrupted");
                }
            }
        }
    }

    /** Returns a short reason code if the instruction is unacceptable, else null. */
    private String validate(PaymentInstruction p) {
        if (p == null || p.getSenderVpa() == null || p.getReceiverVpa() == null
                || p.getAmount() == null || p.getNonce() == null || p.getSignedAt() == null) {
            return "malformed_instruction";
        }
        if (!VPA.matcher(p.getSenderVpa()).matches() || !VPA.matcher(p.getReceiverVpa()).matches()) {
            return "bad_vpa";
        }
        if (p.getSenderVpa().equals(p.getReceiverVpa())) {
            return "self_payment";
        }
        if (!NONCE.matcher(p.getNonce()).matches()) {
            return "bad_nonce";
        }
        BigDecimal a = p.getAmount();
        if (a.signum() <= 0) return "bad_amount";
        if (a.stripTrailingZeros().scale() > 2) return "bad_amount_precision";
        if (a.compareTo(maxAmount) > 0) return "amount_exceeds_limit";
        if (p.getSignature() == null || p.getSignature().isBlank()) return "missing_signature";
        return null;
    }

    public record IngestResult(String outcome, String packetHash, String reason, Long transactionId) {
        public static IngestResult settled(String hash, Transaction tx) {
            return tx.getStatus() == Transaction.Status.REJECTED
                    ? new IngestResult("REJECTED", hash, "insufficient_funds", tx.getId())
                    : new IngestResult("SETTLED", hash, null, tx.getId());
        }
        public static IngestResult duplicate(String hash) {
            return new IngestResult("DUPLICATE_DROPPED", hash, null, null);
        }
        public static IngestResult invalid(String hash, String reason) {
            return new IngestResult("INVALID", hash, reason, null);
        }
        /** Transient failure; nothing was settled and the claim was released. Bridge should retry. */
        public static IngestResult retryLater(String hash, String reason) {
            return new IngestResult("RETRY_LATER", hash, reason, null);
        }
    }
}
