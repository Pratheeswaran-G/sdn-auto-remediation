"""Flask backend: serves the dashboard and a REST API over the detection/remediation engine.
Run:  python3 server/app.py   ->  http://localhost:5000"""
import os, sys, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from flask import Flask, jsonify, request, send_from_directory
from core.engine import Network

app = Flask(__name__, static_folder="../dashboard")
net, lock, cfg = Network(), threading.Lock(), {"auto": True}

def monitor():                                   # continuous closed loop (1 s period)
    while True:
        time.sleep(1)
        with lock:
            if cfg["auto"]: net.cycle(auto=True)
threading.Thread(target=monitor, daemon=True).start()

@app.get("/")
def index(): return send_from_directory(app.static_folder, "index.html")
@app.get("/api/snapshot")
def snap():
    with lock: return jsonify(dict(net.snapshot(), auto=cfg["auto"]))
@app.post("/api/inject/<kind>")
def inject(kind):
    with lock:
        try: net.inject(kind.upper())
        except ValueError: return jsonify(error="unknown fault"), 400
    return jsonify(ok=True)
@app.post("/api/cycle")
def cycle():
    with lock: return jsonify(net.cycle(auto=True))
@app.post("/api/auto/<on>")
def auto(on): cfg["auto"] = on == "1"; return jsonify(auto=cfg["auto"])
@app.get("/api/tests/run")
def run_tests():
    from tests.test_suite import run_all
    return jsonify(run_all())
@app.post("/api/reset")
def reset():
    with lock: net.reset()
    return jsonify(ok=True)
@app.post("/api/topology")
def configure_topology():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON body with hosts and switches is required"), 400
    try:
        hosts = int(data["hosts"])
        switches = int(data["switches"])
        with lock:
            net.configure(hosts, switches)
            snapshot = net.snapshot()
    except (KeyError, TypeError, ValueError) as exc:
        return jsonify(error=str(exc) or "hosts and switches must be integers"), 400
    return jsonify(snapshot)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
