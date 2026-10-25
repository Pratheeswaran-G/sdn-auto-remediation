"""Test suite covering all four team roles. Run: python3 tests/test_suite.py (writes tests/results.csv)."""
import os, sys, time, csv, statistics, io
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.engine import Network, BASELINE, MAX_HOSTS, select_route
from live_sdn.path_config import host_port_layout, path_port_layout
from ndc.auto_remediation_full import (
    _expected_live_flows,
    _expected_live_rules,
    _repair_live_flow_path,
    _repair_live_host_config,
    detect_ip_misconfigurations,
    detect_live_flow_path,
    parse_ovs_port_flows,
    run_demo_mode,
    run_live_scan,
)

KINDS = ("IP", "ROUTING", "FIREWALL", "PORT", "SWITCH")

def bench(n=200):
    ts = []
    for i in range(n):
        net = Network(); t = time.perf_counter(); net.inject(KINDS[i % 5]); net.cycle(); ts.append((time.perf_counter() - t) * 1000)
    ts.sort(); m = statistics.mean(ts)
    return m < 50, f"mean {m:.3f} ms, p95 {ts[int(n * .95)]:.3f} ms"

def stress(n=200):
    ok = 0
    for _ in range(n):
        net = Network(); [net.inject(k) for k in KINDS]; net.cycle(); ok += not net.detect()
    return ok == n, f"{ok}/{n} rounds healed"

def _detect(k):
    n = Network(); n.inject(k); d = n.detect(); return len(d) >= 1 and all(x["type"] == k for x in d), f"{len(d)} finding(s)"
def _fix(k):
    n = Network(); n.inject(k); n.cycle(); return not n.detect(), n.log[-1]["msg"]
def _idem():
    n = Network(); n.inject("SWITCH"); n.cycle(); c = len(n.log); n.cycle(); return len(n.log) == c, "2nd cycle no change"
def _stress5():
    n = Network(); [n.inject(k) for k in KINDS]; c = n.confidence(); n.cycle(); return abs(c - 1.0) < 1e-9 and not n.detect(), f"C={c}"
def _detonly():
    n = Network(); n.inject("ROUTING"); n.detect(); n.detect(); return len(n.detect()) == 1, "fault persists without auto-fix"
def _failover():
    r = [select_route(set()), select_route({(1, 2)}), select_route({(1, 2), (3, 1)}), select_route(set())]
    return r == ["PRIMARY", "BACKUP", "BACKUP", "PRIMARY"], "->".join(r)
def _dynamic_topology():
    n = Network(host_count=6, switch_count=8)
    s = n.snapshot()
    return (len([x for x in s["topo"]["nodes"] if x.startswith("h")]) == 6
            and len([x for x in s["topo"]["nodes"] if x.startswith("s")]) == 8
            and len(s["topo"]["links"]) == 14), f"{len(s['topo']['nodes'])} nodes, {len(s['topo']['links'])} links"
def _invalid_topology():
    try:
        Network(host_count=MAX_HOSTS + 1, switch_count=4)
    except ValueError:
        return True, "out-of-range host count rejected"
    return False, "out-of-range host count accepted"
def _dynamic_live_paths():
    primary, backup, ports, _ = path_port_layout(8)
    attachments, host_ports = host_port_layout(6, 8)
    ok = (primary == ["s1", "s2", "s4", "s6", "s8"]
          and backup == ["s1", "s3", "s5", "s7", "s8"]
          and ports[("s1", "s2")] == (2, 1)
          and ports[("s1", "s3")] == (3, 1)
          and attachments["h1"] == "s1" and attachments["h6"] == "s8"
          and len(set((attachments[h], port) for h, port in host_ports.items())) == 6)
    return ok, "8-switch paths and 6 host ports generated"

def _all_live_topology_paths():
    for switches in range(4, 17):
        primary, backup, _, _ = path_port_layout(switches)
        for hosts in range(2, 21):
            for path in (primary, backup):
                expected = _expected_live_rules(path, hosts, switches)
                findings, selected = detect_live_flow_path(expected, hosts, switches)
                if findings or selected == "UNKNOWN":
                    return False, f"{hosts} hosts, {switches} switches, {path}"
    return True, "both paths validate for all supported host/switch counts"

def _live_flow_remediation():
    primary, _, _, _ = path_port_layout(4)
    expected = _expected_live_rules(primary, 2, 4)
    actual = {switch: set(rules) for switch, rules in expected.items()}
    actual["s1"] = set()
    calls = []
    def fake_run(command, **kwargs):
        calls.append((command, kwargs.get("input")))
        switch = command[-1]
        stdout = ""
        if "dump-flows" in command:
            stdout = "priority=0 actions=CONTROLLER"
            if switch in ("s1", "s2", "s4"):
                stdout += "\npriority=10,in_port=1 actions=output:2"
            if switch == "s1":
                stdout += "\npriority=100,in_port=1 actions=drop"
        return SimpleNamespace(returncode=0, stderr="", stdout=stdout)
    with patch("ndc.auto_remediation_full.subprocess.run", side_effect=fake_run):
        selected = _repair_live_flow_path(actual, 2, 4)
    entries = _expected_live_flows(primary, 2, 4)
    added = [input_text for command, input_text in calls if "add-flows" in command]
    removed_priorities = [command for command, _ in calls if "del-flows" in command]
    ok = (selected == "PRIMARY" and len(calls) == 11
          and {command[-1] for command in removed_priorities} == {"priority=10", "priority=100"}
          and any("in_port=1,actions=output:2" in flow for flow in added if flow)
          and sum(bool(flows) for flows in entries.values()) == 3)
    return ok, f"{selected} path restored across 4 switches"

def _live_drop_flow_detection():
    output = "priority=0 actions=CONTROLLER\npriority=100,in_port=1 actions=drop"
    with patch("ndc.auto_remediation_full.subprocess.run",
               return_value=SimpleNamespace(returncode=0, stderr="", stdout=output)):
        pairs, _ = parse_ovs_port_flows("s1")
    return pairs == {(1, 0)}, f"blocking flow detected as {sorted(pairs)}"

def _live_ip_subnet_mask_detection():
    expected = {"devices": {"h1": {
        "ip": "10.0.0.1", "subnet": "10.0.0.0/24", "gateway": None}}}
    actual = {"devices": {"h1": {"ip": "10.0.0.1/16", "gateway": None}}}
    findings = detect_ip_misconfigurations(expected, actual)
    return (len(findings) == 1 and findings[0]["type"] == "SUBNET_MASK_MISMATCH",
            findings[0]["type"] if findings else "no finding")

def _live_host_remediation():
    class FakeHost:
        def __init__(self):
            self.commands = []
        def cmd(self, command):
            self.commands.append(command)
            if command == "ip -j -4 route show":
                return '[{"dst":"10.0.0.0/24","dev":"h1-eth0"},' \
                       '{"dst":"192.168.50.0/24","dev":"h1-eth0"}]'
            return "\n__SDN_EXIT:0"
    class FakeNet:
        def __init__(self):
            self.host = FakeHost()
        def get(self, name):
            assert name == "h1"
            return self.host
    net = FakeNet()
    expected = {
        "devices": {"h1": {"ip": "10.0.0.1", "subnet": "10.0.0.0/24", "gateway": None}},
        "routes": [{"destination": "10.0.0.0/24", "next_hop": "on-link"}],
    }
    actual = {"devices": {"h1": {"ip": "10.0.0.1/16", "gateway": None}}}
    actions = _repair_live_host_config(net, expected, actual)
    commands = net.host.commands
    ok = (any("ip addr flush dev h1-eth0" in command for command in commands)
          and any("ip addr add 10.0.0.1/24 dev h1-eth0" in command for command in commands)
          and any("ip route del 192.168.50.0/24 dev h1-eth0" in command for command in commands)
          and len(actions) == 2)
    return ok, ", ".join(actions)

def _live_scan_auto_remediation_cycle():
    expected = {"devices": {}, "routes": [], "allowed_ports": []}
    actual = {"devices": {"h1": {"ip": "10.0.0.1/24", "gateway": None}},
              "routes": [], "open_ports": [8080]}
    rules = {f"s{i}": set() for i in range(1, 5)}
    initial_findings = [
        {"module": "IP", "type": "IP_MISMATCH", "severity": "HIGH",
         "message": "test IP mismatch"},
        {"module": "FLOW", "type": "FLOW_PATH_MISMATCH", "severity": "HIGH",
         "message": "test flow mismatch"},
        {"module": "OPEN_PORTS", "type": "UNNECESSARY_PORT", "severity": "HIGH",
         "message": "test open port"},
    ]
    scan_results = [
        (expected, actual, rules, initial_findings, "UNKNOWN"),
        (expected, actual, rules, [], "PRIMARY"),
    ]
    output = io.StringIO()
    with patch("ndc.auto_remediation_full._collect_live_findings", side_effect=scan_results) as collect, \
            patch("ndc.auto_remediation_full._repair_live_host_config",
                  return_value=["h1 address restored"]), \
            patch("ndc.auto_remediation_full._repair_live_flow_path", return_value="PRIMARY"), \
            redirect_stdout(output):
        run_live_scan(object(), 2, 4)
    report = output.getvalue()
    ok = (collect.call_count == 2 and "Applied: h1 address restored" in report
          and "Applied: forwarding rules restored for PRIMARY path" in report
          and "not auto-closed" in report
          and "Verification after remediation:" in report
          and "No misconfiguration detected" in report)
    return ok, "host/flow repaired and verified; listener left for operator review"

def _demo_end_to_end():
    output = io.StringIO()
    with redirect_stdout(output):
        run_demo_mode()
    report = output.getvalue()
    ok = ("REMEDIATION SUCCESS" in report
          and "No misconfiguration detected. Network is healthy." in report
          and "removed disallowed simulated ports [23]" in report)
    return ok, "sample IP, route, port, and flow faults repaired and verified"

TESTS = []
for k in KINDS:
    TESTS += [(f"Detect {k}", "Thirudhanish", lambda k=k: _detect(k)), (f"Remediate {k}", "Praveenkanth", lambda k=k: _fix(k))]
TESTS += [("No false positives on baseline", "Thirudhanish", lambda: (not Network().detect(), "0 findings")),
          ("Stress: 5 simultaneous faults", "Praveenkanth", _stress5),
          ("Idempotent remediation", "Praveenkanth", _idem),
          ("Detection-only keeps fault", "Pratheeswaran", _detonly),
          ("Failover primary->backup->primary", "Rajasimman", _failover),
          ("Flow rules cover primary path", "Rajasimman", lambda: (all(s in BASELINE["flows"] for s in ("s1", "s2", "s4")), "s1,s2,s4 present")),
          ("Selectable host and switch counts", "Pratheeswaran", _dynamic_topology),
          ("Topology count validation", "Pratheeswaran", _invalid_topology),
          ("Dynamic live paths and ports", "Rajasimman", _dynamic_live_paths),
          ("All supported live path sizes", "Rajasimman", _all_live_topology_paths),
          ("Live flow auto-remediation", "Rajasimman", _live_flow_remediation),
          ("Live drop-flow detection", "Thirudhanish", _live_drop_flow_detection),
          ("Live subnet-mask detection", "Thirudhanish", _live_ip_subnet_mask_detection),
          ("Live host IP and route remediation", "Praveenkanth", _live_host_remediation),
          ("Live scan remediate and verify", "Praveenkanth", _live_scan_auto_remediation_cycle),
          ("Demo end-to-end remediation", "Praveenkanth", _demo_end_to_end),
          ("Benchmark: 200 detect+fix loops", "Pratheeswaran", bench),
          ("Stress x200 (5 faults each)", "Pratheeswaran", stress)]

def run_all():
    rows = []
    for i, (name, owner, fn) in enumerate(TESTS, 1):
        t = time.perf_counter()
        try: ok, d = fn()
        except Exception as e: ok, d = False, f"error: {e}"
        rows.append({"id": i, "test": name, "owner": owner, "result": "PASS" if ok else "FAIL", "ms": round((time.perf_counter() - t) * 1000, 3), "detail": d})
    return rows

if __name__ == "__main__":
    rows = run_all()
    for r in rows: print(f"{r['id']:>2} {r['result']} {r['owner']:<14} {r['test']:<36} {r['ms']:>8} ms  {r['detail']}")
    out = os.path.join(os.path.dirname(__file__), "results.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, rows[0].keys()); w.writeheader(); w.writerows(rows)
    p = sum(r["result"] == "PASS" for r in rows); print(f"\n{p}/{len(rows)} passed -> {out}"); sys.exit(p != len(rows))
