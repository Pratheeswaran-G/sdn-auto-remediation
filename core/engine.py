"""Detection + auto-remediation engine (simulation model of the live lab).
Five fault types: IP, ROUTING, FIREWALL, PORT, SWITCH. Mirrors ndc/auto_remediation_full.py."""
import time, copy, random

MIN_HOSTS, MAX_HOSTS = 2, 20
MIN_SWITCHES, MAX_SWITCHES = 4, 16

def build_topology(host_count=2, switch_count=4):
    if not MIN_HOSTS <= host_count <= MAX_HOSTS:
        raise ValueError(f"hosts must be between {MIN_HOSTS} and {MAX_HOSTS}")
    if not MIN_SWITCHES <= switch_count <= MAX_SWITCHES:
        raise ValueError(f"switches must be between {MIN_SWITCHES} and {MAX_SWITCHES}")
    primary = ["s1"] + [f"s{i}" for i in range(2, switch_count, 2)] + [f"s{switch_count}"]
    backup = ["s1"] + [f"s{i}" for i in range(3, switch_count, 2)] + [f"s{switch_count}"]
    links = [(a, b) for path in (primary, backup) for a, b in zip(path, path[1:])]
    source_hosts = (host_count + 1) // 2
    hosts = [f"h{i}" for i in range(1, host_count + 1)]
    links.extend((host, "s1" if i < source_hosts else f"s{switch_count}")
                 for i, host in enumerate(hosts))
    return {"nodes": hosts + [f"s{i}" for i in range(1, switch_count + 1)],
            "links": links}

def build_baseline(host_count=2, switch_count=4):
    build_topology(host_count, switch_count)
    hosts = {f"h{i}": {"ip": f"10.0.0.{i}/24"} for i in range(1, host_count + 1)}
    primary = ["s1"] + [f"s{i}" for i in range(2, switch_count, 2)] + [f"s{switch_count}"]
    routes = {switch: next_switch for switch, next_switch in zip(primary, primary[1:])}
    routes[primary[-1]] = f"h{host_count}"
    flows = {switch: (1, 2) for switch in primary}
    flows[primary[-1]] = (1, 3)
    return {
        "hosts": hosts,
        "routes": routes,
        "firewall": {"s2": "allow"},
        "open_ports": {host: ([80] if host == "h2" else []) for host in hosts},
        "flows": flows,
    }

BASELINE = build_baseline()
TOPO = build_topology()
SEV = {"IP": "HIGH", "ROUTING": "HIGH", "FIREWALL": "HIGH", "PORT": "MEDIUM", "SWITCH": "HIGH"}
W = {"IP": .25, "ROUTING": .25, "FIREWALL": .2, "PORT": .1, "SWITCH": .2}  # severity weights

class Network:
    def __init__(self, host_count=2, switch_count=4):
        self.configure(host_count, switch_count)

    def configure(self, host_count, switch_count):
        self.baseline = build_baseline(host_count, switch_count)
        self.topology = build_topology(host_count, switch_count)
        self.host_count = host_count
        self.switch_count = switch_count
        self.reset()

    def reset(self):
        self.state = copy.deepcopy(self.baseline); self.log = []; self.faults = {}
    def inject(self, kind, target=None):
        s = self.state
        if kind == "IP": s["hosts"]["h2"]["ip"] = "10.0.5.77/24"
        elif kind == "ROUTING": s["routes"]["s2"] = "s3"
        elif kind == "FIREWALL": s["firewall"]["s2"] = "drop"
        elif kind == "PORT": s["open_ports"]["h1"] = [23, 3389]
        elif kind == "SWITCH": s["flows"]["s2"] = (1, 3)
        else: raise ValueError(kind)
        self.faults[kind] = time.time()
        self._log("INJECT", kind, f"fault injected: {kind}")
    def _log(self, ev, kind, msg, **x):
        self.log.append({"t": round(time.time(), 2), "event": ev, "type": kind, "msg": msg, **x})

    def detect(self):
        b, s, out = self.baseline, self.state, []
        for h, d in b["hosts"].items():
            if s["hosts"][h]["ip"] != d["ip"]:
                out.append(("IP", h, f"{h} IP {s['hosts'][h]['ip']}, expected {d['ip']}"))
        for sw, nh in b["routes"].items():
            if s["routes"][sw] != nh:
                out.append(("ROUTING", sw, f"{sw} next hop {s['routes'][sw]}, expected {nh}"))
        for sw, a in b["firewall"].items():
            if s["firewall"][sw] != a:
                out.append(("FIREWALL", sw, f"{sw} rule '{s['firewall'][sw]}' blocks valid traffic"))
        for h, ports in b["open_ports"].items():
            for p in sorted(set(s["open_ports"][h]) - set(ports)):
                out.append(("PORT", h, f"{h} has unnecessary open port {p}"))
        for sw, f in b["flows"].items():
            if tuple(s["flows"][sw]) != f:
                out.append(("SWITCH", sw, f"{sw} flow {tuple(s['flows'][sw])}, expected {f}"))
        return [{"type": t, "target": g, "msg": m, "severity": SEV[t], "weight": W[t]} for t, g, m in out]

    def remediate(self, f):
        """Rewrite the faulty entry back to baseline (mimics an OpenFlow FlowMod / config push)."""
        b, s, t, g = self.baseline, self.state, f["type"], f["target"]
        if t == "IP": s["hosts"][g]["ip"] = b["hosts"][g]["ip"]; act = f"set {g} IP {b['hosts'][g]['ip']}"
        elif t == "ROUTING": s["routes"][g] = b["routes"][g]; act = f"FlowMod: {g} -> {b['routes'][g]}"
        elif t == "FIREWALL": s["firewall"][g] = b["firewall"][g]; act = f"reinstall allow rule on {g}"
        elif t == "PORT":
            s["open_ports"][g] = [p for p in s["open_ports"][g] if p in b["open_ports"][g]]; act = f"close extra ports on {g}"
        else: s["flows"][g] = b["flows"][g]; act = f"FlowMod: restore {g} {b['flows'][g]}"
        return act

    def cycle(self, auto=True):
        """One monitor->detect->alert->remediate->verify loop. Returns findings with timings."""
        res = []
        for f in self.detect():
            t0 = self.faults.get(f["type"], time.time()); t_alert = time.time()
            self._log("ALERT", f["type"], f["msg"], severity=f["severity"])
            r = dict(f, t_detect=round(t_alert - t0, 2), fixed=False)
            if auto:
                act = self.remediate(f); ok = not any(x["type"] == f["type"] and x["target"] == f["target"] for x in self.detect())
                r.update(action=act, fixed=ok, t_fix=round(time.time() - t_alert, 3))
                self._log("REMEDIATE" if ok else "FAILED", f["type"], act)
                if ok: self.faults.pop(f["type"], None)
            res.append(r)
        return res

    def confidence(self):
        return round(sum(W[t] for t in {f["type"] for f in self.detect()}), 2)   # C = sum_j w_j*delta_j (per fault class)

    def snapshot(self):
        det = self.detect(); bad = {d["target"] for d in det}
        return {"topo": self.topology, "host_count": self.host_count, "switch_count": self.switch_count,
                "health": {n: ("critical" if n in bad else "healthy") for n in self.topology["nodes"]},
                "findings": det, "score": self.confidence(), "log": self.log[-60:], "state": self.state}
PRIMARY_PORTS = {(1, 2), (2, 1), (2, 2), (4, 1)}   # same sets as live_sdn/controller.py
BACKUP_PORTS = {(1, 3), (3, 1), (3, 2), (4, 2)}

def select_route(failed_ports):
    """Mirror of DetectHealController._select_route: backup iff a primary port failed."""
    return "BACKUP" if any(p in failed_ports for p in PRIMARY_PORTS) else "PRIMARY"


if __name__ == "__main__":                       # CLI self-test of all five faults
    n = Network()
    for k in ("IP", "ROUTING", "FIREWALL", "PORT", "SWITCH"):
        n.inject(k); r = n.cycle(); print(k, "->", r[0]["action"], "| fixed:", r[0]["fixed"])
    assert not n.detect(); print("ALL 5 FAULT TYPES DETECTED + REMEDIATED + VERIFIED")
