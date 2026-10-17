package com.demo.upimesh;
import com.demo.upimesh.crypto.PersistentKeyStore;
import com.demo.upimesh.model.*;
import com.demo.upimesh.service.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.test.util.ReflectionTestUtils;
import java.nio.file.Path;
import java.math.BigDecimal;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
@SpringBootTest
class SettlementReliabilityTest {
 @Autowired DemoService demo;
 @Autowired BridgeIngestionService bridge;
 @Autowired AccountRepository accounts;
 @Autowired TransactionRepository transactions;
 @Autowired IdempotencyService gate;
 @SpyBean SettlementService settlement;
 @Test void insufficientFundsAreRejectedWithoutMovingMoney() throws Exception {
   BigDecimal before = accounts.findById("amit@demo").orElseThrow().getBalance();
   BigDecimal receiver = accounts.findById("priya@demo").orElseThrow().getBalance();
   MeshPacket packet = demo.createPacket("amit@demo", "priya@demo", new BigDecimal("10000"), "1234", 5);
   var result = bridge.ingest(packet, "test", 1);
   assertEquals("REJECTED", result.outcome());
   assertEquals("insufficient_funds", result.reason());
   assertEquals(Transaction.Status.REJECTED, transactions.findById(result.transactionId()).orElseThrow().getStatus());
   assertEquals(before, accounts.findById("amit@demo").orElseThrow().getBalance());
   assertEquals(receiver, accounts.findById("priya@demo").orElseThrow().getBalance());
   gate.clear();
   assertEquals("DUPLICATE_DROPPED", bridge.ingest(packet, "test", 1).outcome());
 }
 @Test void transientSettlementFailureRetriesAndDebitsOnce() throws Exception {
   BigDecimal before = accounts.findById("rahul@demo").orElseThrow().getBalance();
   MeshPacket packet = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("1"), "1234", 5);
   doThrow(new TransientDataAccessResourceException("temporary")).doCallRealMethod()
      .when(settlement).settle(any(), anyString(), anyString(), anyInt());
   assertEquals("SETTLED", bridge.ingest(packet, "test", 1).outcome());
   assertEquals(before.subtract(new BigDecimal("1.00")), accounts.findById("rahul@demo").orElseThrow().getBalance());
   assertEquals(0, gate.size());
 }
 @Test void inFlightDeliveryMustBeRetriedNotDiscarded() throws Exception {
   MeshPacket packet = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("1"), "1234", 5);
   String hash = com.demo.upimesh.crypto.PacketCodec.sha256Hex(java.util.Base64.getDecoder().decode(packet.getCiphertext()));
   assertTrue(gate.claim(hash));
   try { assertEquals("RETRY_LATER", bridge.ingest(packet, "test", 1).outcome()); }
   finally { gate.release(hash); }
   assertEquals("SETTLED", bridge.ingest(packet, "test", 1).outcome());
 }
 @Test void exhaustedRetriesReleaseClaimAndLaterDeliverySettles() throws Exception {
   MeshPacket packet = demo.createPacket("rahul@demo", "priya@demo", new BigDecimal("1"), "1234", 5);
   Object previous = ReflectionTestUtils.getField(bridge, "maxRetries");
   ReflectionTestUtils.setField(bridge, "maxRetries", 0);
   doThrow(new TransientDataAccessResourceException("temporary"))
      .when(settlement).settle(any(), anyString(), anyString(), anyInt());
   try {
      assertEquals("RETRY_LATER", bridge.ingest(packet, "test", 1).outcome());
      assertEquals(0, gate.size());
   } finally {
      ReflectionTestUtils.setField(bridge, "maxRetries", previous);
      reset(settlement);
   }
   assertEquals("SETTLED", bridge.ingest(packet, "test", 1).outcome());
 }
 @Test void unknownReceiverDoesNotDebitSender() throws Exception {
   BigDecimal before = accounts.findById("rahul@demo").orElseThrow().getBalance();
   MeshPacket packet = demo.createPacket("rahul@demo", "missing@demo", new BigDecimal("1"), "1234", 5);
   assertEquals("unknown_receiver", bridge.ingest(packet, "test", 1).reason());
   assertEquals(before, accounts.findById("rahul@demo").orElseThrow().getBalance());
 }
 @Test void keysSurviveNewStoreInstance(@TempDir Path directory) throws Exception {
   PersistentKeyStore first = new PersistentKeyStore(), second = new PersistentKeyStore();
   ReflectionTestUtils.setField(first, "directory", directory.toString());
   ReflectionTestUtils.setField(second, "directory", directory.toString());
   for (String algorithm : new String[]{"RSA", "EC"}) {
     var original = first.loadOrCreate(algorithm, algorithm);
     var restored = second.loadOrCreate(algorithm, algorithm);
     assertArrayEquals(original.getPrivate().getEncoded(), restored.getPrivate().getEncoded());
     assertArrayEquals(original.getPublic().getEncoded(), restored.getPublic().getEncoded());
   }
 }
}
