package com.demo.upimesh.service;
import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
/** JVM-local in-flight gate. Durable deduplication is enforced by the database.
 * Claims must not expire during processing; ingestion releases them in finally. */
@Service
public class IdempotencyService {
    private final Set<String> processing = ConcurrentHashMap.newKeySet();
    public boolean claim(String hash) { return processing.add(hash); }
    public void release(String hash) { processing.remove(hash); }
    public int size() { return processing.size(); }
    /** Test helper; never clear while requests are running. */
    public void clear() { processing.clear(); }
}
