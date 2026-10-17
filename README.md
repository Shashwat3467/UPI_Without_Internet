# Secure Offline Payment Relay and Deferred Settlement Simulator

A Java 17 / Spring Boot backend that accepts encrypted, device-signed payment instructions delivered through a simulated mesh. The ledger settles once connectivity returns. Phones, Bluetooth, accounts, and money are simulated; there is no real UPI or bank integration.

## Features

- RSA-OAEP + AES-256-GCM envelope encryption; ECDSA P-256 sender signatures.
- Canonical Base64 decoding, packet size limits, amount/precision validation, and signed timestamp checks.
- Transactional debit, credit, and ledger writes using BigDecimal and optimistic locking.
- Durable unique constraints on ciphertext hash and (sender, nonce), including rejected payments.
- In-flight requests return RETRY_LATER rather than claiming successful deduplication before a commit.
- Retry on transient database contention; claims released after processing. Invalid packets do not accumulate in a TTL cache.
- PostgreSQL profile and Flyway migrations. Default local H2 file database also survives restarts.
- Persistent server and simulated device keys; account provisioning checks existing keys without resetting balances.
- Dashboard, health endpoint, Docker Compose, GitHub Actions, regression tests, and a concurrent bridge benchmark.

## Measured PostgreSQL benchmark

A local run with 8 concurrent workers delivered 100 unique payments three times each:

| Metric | Result |
|---|---:|
| Bridge deliveries | 300 |
| Settled payments | 100 |
| Duplicate deliveries dropped | 200 |
| Total delivery time | 6.442 seconds |
| Delivery throughput | 46.57 requests/second |
| Median latency | 103.69 ms |
| p95 latency | 607.38 ms |
| Sender and receiver balance checks | Passed |

[Raw benchmark results](docs/postgres-load-results.json). Packet creation is excluded; retry time is included. These are measurements from one local run, not production capacity or unique-payment throughput.

## Run locally

Install JDK 17+ and use Maven or the wrapper:

```powershell
.\mvnw.cmd spring-boot:run
```

With Maven installed: `mvn spring-boot:run`. On Unix: `sh mvnw spring-boot:run`.
Open http://localhost:8080. Demo PIN: `1234`. Inject a payment, run gossip, then flush bridges. Balances and ledger entries persist in `data/`; the mesh packet buffers remain in memory.

## PostgreSQL with Docker

```powershell
Copy-Item .env.example .env
# Set DATABASE_PASSWORD in .env, then:
docker compose up --build -d
```

Open http://localhost:8080. Compose binds the app to localhost. PostgreSQL and keys have separate named volumes. `docker compose down` preserves them. Back up both volumes together; losing keys makes outstanding packets undecryptable. Do not use `down -v` unless intentionally destroying the demo data.

For an existing PostgreSQL server, set SPRING_PROFILES_ACTIVE=postgres, DATABASE_URL (a JDBC URL), DATABASE_USER, DATABASE_PASSWORD, and KEY_DIRECTORY. Flyway applies migrations and Hibernate validates the resulting schema.

## Validate

```powershell
mvn verify
python scripts/verify_restart.py
python scripts/load_test.py --payments 100 --workers 8 --copies 3
```

The restart script launches the packaged JAR on port 18080 with isolated data under target/restart-check. It checks key restoration, retained balances, deduplication after restart, delivery of a packet encrypted before restart, and signing after restart. It then runs 300 bridge deliveries for 100 unique payments and writes docs/local-verification.json.

The load test targets a running local demo, sends 0.01 per unique payment, retries HTTP 503, reports p50/p95 latency and throughput, and asserts that both account balances moved exactly once. Packet creation is excluded from timings. This is an application benchmark, not a hardware-independent performance guarantee.

CI runs the suite on H2 and PostgreSQL, then builds the container. CI results become available after pushing this folder to GitHub.

## API outcomes

POST /api/bridge/ingest accepts a MeshPacket. X-Bridge-Node-Id allows 1–64 letters, digits, dots, underscores, or hyphens; X-Hop-Count is clamped to 0–32.

| Outcome | Meaning | Bridge action |
|---|---|---|
| SETTLED | Debit, credit, and ledger committed | Stop retrying |
| REJECTED | Insufficient funds; rejected ledger entry committed | Stop retrying |
| DUPLICATE_DROPPED | A ledger entry already exists | Stop retrying |
| INVALID | Malformed, expired, forged, or unacceptable instruction | Stop retrying |
| RETRY_LATER (HTTP 503) | Still processing or transient/internal failure | Retain packet and retry |

GET /api/accounts and /api/transactions drive the dashboard. POST /api/demo/send creates a simulated signed packet and returns it for reproducible bridge tests. POST /api/mesh/reset clears mesh buffers without touching balances, durable deduplication, or in-flight requests. GET /actuator/health provides a health check.

## Architecture and limits

Simulated sender → signed/encrypted instruction → simulated mesh → bridge ingestion → validation/signature check → transactional settlement → persistent ledger.

Database uniqueness is the final deduplication authority across restarts and instances. The in-flight gate only reduces duplicate work within one JVM. A second replica may attempt settlement concurrently; unique constraints and transaction rollback prevent a second committed debit.

A queued instruction is pending until settlement. This design does not guarantee available funds offline or prevent a sender from composing more payments than their balance. The first acceptable settlements win; subsequent payments may be rejected. The simulator retains a simple all-to-all network.

Private keys are prototype files, not hardware-backed device keys. POSIX permissions restrict access where supported; use an appropriate Windows ACL for data/keys. Do not commit keys. Run one app instance per key directory; shared key provisioning and key rotation are outside this prototype.

## Deployment

See [deployment guide](docs/DEPLOYMENT.md). The application runs locally by default.
