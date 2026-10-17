package com.demo.upimesh;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import java.sql.DriverManager;
import static org.junit.jupiter.api.Assertions.*;
class DemoAccountMigrationTest {
 @Test void renamePreservesBalancesAndLedgerReferences() throws Exception {
  try (var connection = DriverManager.getConnection("jdbc:h2:mem:rename-check", "sa", "")) {
   var source = new SingleConnectionDataSource(connection, true);
   new ResourceDatabasePopulator(new ClassPathResource("db/migration/V1__initial_ledger.sql")).execute(source);
   try (var statement = connection.createStatement()) {
    statement.executeUpdate("INSERT INTO accounts VALUES ('alice@demo','Alice',4900,'old-key',1),('bob@demo','Bob',1100,'old-key',1)");
    statement.executeUpdate("INSERT INTO transactions (packet_hash,sender_vpa,receiver_vpa,nonce,amount,signed_at,settled_at,bridge_node_id,hop_count,status) VALUES ('hash','alice@demo','bob@demo','nonce',100,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'bridge',1,'SETTLED')");
    new ResourceDatabasePopulator(new ClassPathResource("db/migration/V2__rename_demo_accounts.sql")).execute(source);
    try (var rows = statement.executeQuery("SELECT holder_name,balance,device_public_key FROM accounts WHERE vpa='rahul@demo'")) {
     assertTrue(rows.next()); assertEquals("Rahul", rows.getString(1));
     assertEquals(0, new java.math.BigDecimal("4900").compareTo(rows.getBigDecimal(2)));
     assertNull(rows.getString(3));
    }
    try (var rows = statement.executeQuery("SELECT sender_vpa,receiver_vpa FROM transactions")) {
     assertTrue(rows.next()); assertEquals("rahul@demo",rows.getString(1)); assertEquals("priya@demo",rows.getString(2));
    }
    try (var rows = statement.executeQuery("SELECT COUNT(*) FROM accounts")) { rows.next(); assertEquals(2,rows.getInt(1)); }
   }
  }
 }
}
