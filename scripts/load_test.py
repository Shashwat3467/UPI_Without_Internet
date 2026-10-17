"""Concurrent bridge benchmark against a local demo. Mutates the demo ledger."""
import argparse, concurrent.futures, json, time, urllib.request, urllib.error, statistics

def request(base, route, body=None):
    req = urllib.request.Request(base + route, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-Bridge-Node-Id": "load-test"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response: return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 503: return json.load(error)
        raise

def run(base, count, workers, copies):
    before = {a["vpa"]: a["balance"] for a in request(base, "/api/accounts")}
    packets = [request(base, "/api/demo/send", {"senderVpa": "rahul@demo", "receiverVpa": "priya@demo",
        "amount": "0.01", "pin": "1234", "ttl": 5})["packet"] for _ in range(count)]
    def deliver(packet):
        start = time.perf_counter()
        for attempt in range(100):
            result = request(base, "/api/bridge/ingest", packet)
            if result["outcome"] != "RETRY_LATER": break
            time.sleep(0.02)
        return result["outcome"], (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(deliver, [packet for packet in packets for _ in range(copies)]))
    elapsed = time.perf_counter() - start
    outcomes = {name: sum(r[0] == name for r in results) for name in set(r[0] for r in results)}
    after = {a["vpa"]: a["balance"] for a in request(base, "/api/accounts")}
    from decimal import Decimal
    assert outcomes.get("SETTLED", 0) == count, outcomes
    assert outcomes.get("DUPLICATE_DROPPED", 0) == count * (copies - 1), outcomes
    assert Decimal(str(before["rahul@demo"])) - Decimal(str(after["rahul@demo"])) == Decimal("0.01") * count
    assert Decimal(str(after["priya@demo"])) - Decimal(str(before["priya@demo"])) == Decimal("0.01") * count
    latencies = sorted(r[1] for r in results)
    return {"payments": count, "deliveries": len(results), "workers": workers, "seconds": round(elapsed, 3),
        "deliveries_per_second": round(len(results) / elapsed, 2), "latency_p50_ms": round(statistics.median(latencies), 2),
        "latency_p95_ms": round(latencies[min(len(latencies)-1, int(len(latencies)*.95))], 2), "outcomes": outcomes,
        "balance_checks_passed": True, "note": "Local demo measurement; packet creation excluded, retries included."}
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:8080")
    parser.add_argument("--payments", type=int, default=100)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--copies", type=int, default=3)
    parser.add_argument("--output", default="load-results.json")
    args = parser.parse_args()
    if min(args.payments, args.workers, args.copies) < 1: parser.error("counts must be positive")
    report = run(args.base, args.payments, args.workers, args.copies)
    with open(args.output, "w") as f: json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))
