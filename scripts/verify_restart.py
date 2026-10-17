"""Verify persisted ledger, keys, and a queued packet across JVM restarts, then benchmark."""
import subprocess, time, pathlib, json, argparse
from load_test import request, run
parser = argparse.ArgumentParser()
parser.add_argument("--jar", default="target/upi-offline-mesh-0.0.1-SNAPSHOT.jar")
args = parser.parse_args()
base = "http://localhost:18080"
try:
    request(base, "/actuator/health")
except Exception:
    pass
else:
    raise RuntimeError("Port 18080 already has a server; stop it before verifying")
root = pathlib.Path("target/restart-check").resolve()
root.mkdir(parents=True, exist_ok=True)
log = open(root / "server.log", "a")
def start():
    process = subprocess.Popen(["java", "-jar", args.jar, "--server.port=18080",
        "--spring.datasource.url=jdbc:h2:file:" + (root / "ledger").as_posix(),
        "--upi.mesh.key-directory=" + str(root / "keys")], stdout=log, stderr=log)
    for _ in range(120):
        try:
            request(base, "/actuator/health")
            return process
        except Exception:
            if process.poll() is not None: raise RuntimeError("Server failed; inspect target/restart-check/server.log")
            time.sleep(.5)
    process.terminate()
    raise RuntimeError("Server startup timed out")
def stop(process):
    process.terminate()
    process.wait(timeout=30)
process = start()
try:
    packet = request(base, "/api/demo/send", {"senderVpa":"rahul@demo", "receiverVpa":"priya@demo", "amount":"0.01", "pin":"1234"})["packet"]
    queued = request(base, "/api/demo/send", {"senderVpa":"rahul@demo", "receiverVpa":"priya@demo", "amount":"0.01", "pin":"1234"})["packet"]
    key = request(base, "/api/server-key")
    assert request(base, "/api/bridge/ingest", packet)["outcome"] == "SETTLED"
    balances = request(base, "/api/accounts")
    stop(process)
    process = start()
    assert request(base, "/api/server-key") == key
    assert sorted(request(base, "/api/accounts"), key=lambda a:a["vpa"]) == sorted(balances, key=lambda a:a["vpa"])
    assert request(base, "/api/bridge/ingest", packet)["outcome"] == "DUPLICATE_DROPPED"
    assert request(base, "/api/bridge/ingest", queued)["outcome"] == "SETTLED"
    assert "packet" in request(base, "/api/demo/send", {"senderVpa":"rahul@demo", "receiverVpa":"priya@demo", "amount":"0.01", "pin":"1234"})
    report = run(base, 100, 8, 3)
    report["restart_checks_passed"] = True
    report["database"] = "H2 file"
    pathlib.Path("docs").mkdir(exist_ok=True)
    pathlib.Path("docs/local-verification.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
finally:
    if process.poll() is None: stop(process)
    log.close()
