package com.demo.upimesh.model;

import java.math.BigDecimal;
import java.math.RoundingMode;

/**
 * The payment instruction. After the server decrypts MeshPacket.ciphertext,
 * it gets one of these.
 *
 * Security-relevant fields:
 *   - nonce:     unique per payment intent. The server enforces uniqueness per
 *                sender in the DB, so a payment can never settle twice, even if
 *                an attacker produces a different ciphertext for it.
 *   - signedAt:  lets the server reject stale packets (freshness window).
 *   - signature: ECDSA signature by the sender's DEVICE key over signingString().
 *                Proves the instruction came from the account's registered device
 *                and was not altered. (Encryption alone proves nothing about who
 *                sent it: anyone can encrypt to the server's public key.)
 *
 * The UPI PIN is NOT sent. It only unlocks the device key on the phone.
 */
public class PaymentInstruction {

    private String senderVpa;
    private String receiverVpa;
    private BigDecimal amount;
    private String nonce;
    private Long signedAt;
    private String signature; // Base64 ECDSA over signingString()

    public PaymentInstruction() {}

    public PaymentInstruction(String senderVpa, String receiverVpa, BigDecimal amount,
                              String nonce, Long signedAt) {
        this.senderVpa = senderVpa;
        this.receiverVpa = receiverVpa;
        this.amount = amount;
        this.nonce = nonce;
        this.signedAt = signedAt;
    }

    /**
     * Canonical byte-for-byte string that is signed and verified. Fields are
     * '|' separated; the server validates VPAs/nonce contain no '|' so the
     * encoding is unambiguous. Amount is normalised to 2 decimals.
     * (Not a getter, so Jackson does not serialise it.)
     */
    public String signingString() {
        return "UPIMESH1|" + senderVpa + "|" + receiverVpa + "|"
                + amount.setScale(2, RoundingMode.UNNECESSARY).toPlainString()
                + "|" + nonce + "|" + signedAt;
    }

    public String getSenderVpa() { return senderVpa; }
    public void setSenderVpa(String senderVpa) { this.senderVpa = senderVpa; }

    public String getReceiverVpa() { return receiverVpa; }
    public void setReceiverVpa(String receiverVpa) { this.receiverVpa = receiverVpa; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public String getNonce() { return nonce; }
    public void setNonce(String nonce) { this.nonce = nonce; }

    public Long getSignedAt() { return signedAt; }
    public void setSignedAt(Long signedAt) { this.signedAt = signedAt; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
}
