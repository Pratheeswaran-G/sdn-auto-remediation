"""
SDN-Based Detection and Auto-Remediation of Network Misconfiguration

Demo mode:
    python3 auto_remediation.py

Live Mininet mode:
    sudo python3 auto_remediation.py --mode live

Live mode uses the configurable resilient topology from topology.py and a
separately running OS-Ken controller. It reports live host and OVS state.
The controller handles primary/backup path failover and restoration.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from ipaddress import ip_interface, ip_network

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "live_sdn"))
from path_config import host_port_layout, path_port_layout

# -------------------------------------------------------------------
# DEMO CONFIGURATION — retained from the original prototype
# -------------------------------------------------------------------
ERROR_TYPE = "WRONG_OUTPUT_PORT"  # WRONG_OUTPUT_PORT, MISSING_FLOW, BLOCKED_FLOW

class SDNSwitch:
    """Small in-memory switch used by demo mode."""
    def __init__(self, name):
        self.name = name
        self.flow_table = {}

    def add_flow(self, src, dst, port, status="ACTIVE"):
        self.flow_table[(src, dst)] = {"port": port, "status": status}

    def remove_flow(self, src, dst):
        self.flow_table.pop((src, dst), None)

    def get_flow(self, src, dst):
        return self.flow_table.get((src, dst))

    def print_flow_table(self):
        if not self.flow_table:
            print("   (No flows configured)")
            return
        for (src, dst), data in self.flow_table.items():
            status_text = "" if data["status"] == "ACTIVE" else "  [BLOCKED]"
            print(f"{src} -> {dst} -> Port {data['port']}{status_text}")


expected_flow_table = {
    ("10.0.0.1", "10.0.0.2"): {"port": 2, "status": "ACTIVE"},
    ("10.0.0.2", "10.0.0.1"): {"port": 1, "status": "ACTIVE"},
}

expected_network_config = {
    "devices": {
        "host1": {"ip": "10.10.20.10", "subnet": "10.10.20.0/24", "gateway": "10.10.20.1"}
    },
    "routes": [{"destination": "10.10.20.0/24", "next_hop": "10.10.20.1"}],
    "allowed_ports": [22, 80],
}


def build_actual_network_config():
    """Sample faults used only by demo mode."""
    return {
        "devices": {
            "host1": {"ip": "10.10.10.55", "subnet": "10.10.20.0/24", "gateway": "10.10.20.254"}
        },
        "routes": [
            {"destination": "10.10.20.0/24", "next_hop": "10.10.20.1"},
            {"destination": "172.16.5.0/24", "next_hop": "10.10.20.254"},
        ],
        "open_ports": [22, 23, 80],
    }


def _finding(module, finding_type, severity, message, **details):
    return {
        "module": module,
        "type": finding_type,
        "severity": severity,
        "message": message,
        "details": details,
    }


def detect_ip_misconfigurations(expected_config, actual_config):
    """Detect missing devices, wrong IP/subnet, invalid IP, and gateway mismatch."""
    findings = []
    expected_devices = expected_config.get("devices", {})
    actual_devices = actual_config.get("devices", {})

    for device, expected in expected_devices.items():
        actual = actual_devices.get(device)
        if actual is None:
            findings.append(_finding("IP", "MISSING_DEVICE", "HIGH",
                                     f"{device} is missing from the actual configuration",
                                     device=device))
            continue

        try:
            expected_subnet = ip_network(expected["subnet"], strict=False)
            actual_ip_value = actual["ip"]
            if "/" not in actual_ip_value:
                actual_subnet = ip_network(actual.get("subnet", expected["subnet"]), strict=False)
                actual_ip_value = f"{actual_ip_value}/{actual_subnet.prefixlen}"
            actual_interface = ip_interface(actual_ip_value)
            actual_ip = actual_interface.ip
            expected_ip = ip_interface(expected["ip"]).ip
        except (KeyError, ValueError):
            findings.append(_finding("IP", "INVALID_IP", "HIGH",
                                     f"{device} has an invalid IP or subnet", device=device))
            continue

        if actual_ip not in expected_subnet:
            findings.append(_finding(
                "IP", "WRONG_SUBNET", "HIGH",
                f"{device} IP {actual['ip']} is outside {expected['subnet']}",
                device=device, expected_subnet=expected["subnet"], actual_ip=actual["ip"]))
        elif actual_interface.network != expected_subnet:
            findings.append(_finding(
                "IP", "SUBNET_MASK_MISMATCH", "HIGH",
                f"{device} subnet mask is /{actual_interface.network.prefixlen}, "
                f"expected /{expected_subnet.prefixlen}",
                device=device, expected_subnet=str(expected_subnet),
                actual_subnet=str(actual_interface.network)))
        elif actual_ip != expected_ip:
            findings.append(_finding(
                "IP", "IP_MISMATCH", "HIGH",
                f"{device} IP is {actual_ip}, expected {expected_ip}",
                device=device, expected_ip=str(expected_ip), actual_ip=str(actual_ip)))

        if actual.get("gateway") != expected.get("gateway"):
            findings.append(_finding(
                "IP", "GATEWAY_MISMATCH", "HIGH",
                f"{device} gateway is {actual.get('gateway')}, expected {expected.get('gateway')}",
                device=device, expected_gateway=expected.get("gateway"),
                actual_gateway=actual.get("gateway")))

    for device in set(actual_devices) - set(expected_devices):
        findings.append(_finding("IP", "UNREGISTERED_DEVICE", "HIGH",
                                 f"{device} is not registered in the expected configuration",
                                 device=device))
    return findings


def detect_routing_misconfigurations(expected_config, actual_config):
    """Detect missing routes and unexpected routes."""
    findings = []
    expected_routes = {
        (route["destination"], route["next_hop"])
        for route in expected_config.get("routes", [])
    }
    actual_routes = {
        (route["destination"], route["next_hop"])
        for route in actual_config.get("routes", [])
    }

    for destination, next_hop in sorted(expected_routes - actual_routes):
        findings.append(_finding(
            "ROUTING", "MISSING_ROUTE", "HIGH",
            f"Missing route to {destination} via {next_hop}",
            destination=destination, next_hop=next_hop))
    for destination, next_hop in sorted(actual_routes - expected_routes):
        findings.append(_finding(
            "ROUTING", "ROGUE_ROUTE", "HIGH",
            f"Unexpected route to {destination} via {next_hop}",
            destination=destination, next_hop=next_hop))
    return findings


def detect_flow_misconfigurations(switch, expected_table):
    """Detect flow faults in the original simulated switch."""
    findings = []
    for (src, dst), expected_data in expected_table.items():
        current_data = switch.get_flow(src, dst)
        if current_data is None:
            findings.append(_finding("FLOW", "MISSING_FLOW", "HIGH",
                                     f"Missing flow rule {src} -> {dst}",
                                     src=src, dst=dst, expected_port=expected_data["port"]))
            continue
        if current_data["port"] != expected_data["port"]:
            findings.append(_finding(
                "FLOW", "WRONG_OUTPUT_PORT", "HIGH",
                f"Flow {src} -> {dst} uses port {current_data['port']}, expected {expected_data['port']}",
                src=src, dst=dst, expected_port=expected_data["port"],
                current_port=current_data["port"]))
        if current_data["status"] != expected_data["status"]:
            findings.append(_finding(
                "FLOW", "BLOCKED_FLOW", "HIGH",
                f"Flow {src} -> {dst} has status {current_data['status']}",
                src=src, dst=dst, expected_status=expected_data["status"],
                current_status=current_data["status"]))

    for src, dst in set(switch.flow_table) - set(expected_table):
        findings.append(_finding("FLOW", "UNAUTHORIZED_FLOW", "HIGH",
                                 f"Unauthorized flow rule {src} -> {dst}", src=src, dst=dst))
    return findings


def detect_open_port_misconfigurations(expected_config, actual_config):
    """Detect listening ports not allowed by the baseline and missing expected ports."""
    allowed_ports = set(expected_config.get("allowed_ports", []))
    open_ports = set(actual_config.get("open_ports", []))
    findings = []
    for port in sorted(open_ports - allowed_ports):
        findings.append(_finding("OPEN_PORTS", "UNNECESSARY_PORT", "HIGH",
                                 f"Port {port} is open but is not allowed", port=port))
    for port in sorted(allowed_ports - open_ports):
        findings.append(_finding("OPEN_PORTS", "MISSING_ALLOWED_PORT", "MEDIUM",
                                 f"Allowed port {port} is not open", port=port))
    return findings


def detect_all_misconfigurations(expected_config, actual_config, switch):
    findings = []
    findings.extend(detect_ip_misconfigurations(expected_config, actual_config))
    findings.extend(detect_routing_misconfigurations(expected_config, actual_config))
    findings.extend(detect_flow_misconfigurations(switch, expected_flow_table))
    findings.extend(detect_open_port_misconfigurations(expected_config, actual_config))
    return findings


# -------------------------------------------------------------------
# DEMO-ONLY FLOW REMEDIATION — keeps the original console workflow
# -------------------------------------------------------------------
def build_switch_with_error(error_type):
    switch = SDNSwitch("S1")
    switch.add_flow("10.0.0.1", "10.0.0.2", 2, "ACTIVE")
    switch.add_flow("10.0.0.2", "10.0.0.1", 1, "ACTIVE")
    if error_type == "WRONG_OUTPUT_PORT":
        switch.add_flow("10.0.0.1", "10.0.0.2", 3, "ACTIVE")
    elif error_type == "MISSING_FLOW":
        switch.remove_flow("10.0.0.1", "10.0.0.2")
    elif error_type == "BLOCKED_FLOW":
        switch.add_flow("10.0.0.1", "10.0.0.2", 2, "BLOCKED")
    return switch


def detect_misconfiguration(switch, expected_table):
    for (src, dst), expected_data in expected_table.items():
        current_data = switch.get_flow(src, dst)
        if current_data is None:
            return {"type": "MISSING_FLOW", "src": src, "dst": dst,
                    "expected_port": expected_data["port"], "current_port": None}
        if current_data["port"] != expected_data["port"]:
            return {"type": "WRONG_OUTPUT_PORT", "src": src, "dst": dst,
                    "expected_port": expected_data["port"], "current_port": current_data["port"]}
        if current_data["status"] != expected_data["status"]:
            return {"type": "BLOCKED_FLOW", "src": src, "dst": dst,
                    "expected_port": expected_data["port"], "current_port": current_data["port"]}
    return None


def identify_problem(switch, problem):
    print(f"Switch: {switch.name}")
    print(f"Source: {problem['src']}")
    print(f"Destination: {problem['dst']}")


def generate_fix(problem):
    if problem["type"] == "WRONG_OUTPUT_PORT":
        print("Proposed Fix:")
        print(f"Change output port from {problem['current_port']} to {problem['expected_port']}")
    elif problem["type"] == "MISSING_FLOW":
        print("Proposed Fix:")
        print(f"Install new flow rule on Port {problem['expected_port']}")
    elif problem["type"] == "BLOCKED_FLOW":
        print("Proposed Fix:")
        print(f"Unblock flow and keep it on Port {problem['expected_port']}")
    return {"src": problem["src"], "dst": problem["dst"],
            "new_port": problem["expected_port"], "new_status": "ACTIVE"}


def apply_fix(switch, fix):
    switch.add_flow(fix["src"], fix["dst"], fix["new_port"], fix["new_status"])
    print("Fix applied successfully!")


def verify_fix(switch, expected_table, src, dst):
    print("Checking switch flow table...\n")
    current_data = switch.get_flow(src, dst)
    expected_data = expected_table[(src, dst)]
    if current_data is None:
        print("Flow is still missing.")
        return False
    print("Flow is now:")
    print(f"{src} -> {dst} -> Port {current_data['port']}")
    return current_data["port"] == expected_data["port"] and current_data["status"] == expected_data["status"]


def remediate_demo_network_config(expected_config, actual_config):
    """Restore simulated device/route state and remove disallowed listeners."""
    actions = []
    expected_devices = expected_config.get("devices", {})
    actual_devices = actual_config.setdefault("devices", {})
    for device, expected in expected_devices.items():
        actual = actual_devices.setdefault(device, {})
        for key, value in expected.items():
            if actual.get(key) != value:
                actual[key] = value
                actions.append(f"restored {device} {key} to {value}")
    for device in set(actual_devices) - set(expected_devices):
        del actual_devices[device]
        actions.append(f"removed unregistered device {device}")

    expected_routes = expected_config.get("routes", [])
    if actual_config.get("routes", []) != expected_routes:
        actual_config["routes"] = [dict(route) for route in expected_routes]
        actions.append("restored expected routes")

    allowed_ports = set(expected_config.get("allowed_ports", []))
    open_ports = set(actual_config.get("open_ports", []))
    unnecessary_ports = open_ports - allowed_ports
    if unnecessary_ports:
        actual_config["open_ports"] = sorted(open_ports & allowed_ports)
        actions.append(f"removed disallowed simulated ports {sorted(unnecessary_ports)}")
    return actions


def print_findings(findings):
    if not findings:
        print("No misconfiguration detected. Network is healthy.")
        return
    for number, finding in enumerate(findings, start=1):
        print(f"{number}. [{finding['severity']}] {finding['module']} - "
              f"{finding['type']}: {finding['message']}")


def run_demo_mode():
    print("=" * 40)
    print(" SDN AUTO-REMEDIATION SYSTEM")
    print("=" * 40)
    switch = build_switch_with_error(ERROR_TYPE)
    actual_network_config = build_actual_network_config()

    print("\n[1] CURRENT SWITCH CONFIGURATION")
    switch.print_flow_table()

    print("\n[2] DETECTION REPORT")
    findings = detect_all_misconfigurations(expected_network_config, actual_network_config, switch)
    print_findings(findings)
    print("\n[3] APPLYING SIMULATED AUTO-REMEDIATION...")
    for action in remediate_demo_network_config(expected_network_config, actual_network_config):
        print(f"Applied: {action}")

    problem = detect_misconfiguration(switch, expected_flow_table)
    if problem is not None:
        print(f"ERROR DETECTED: {problem['type'].replace('_', ' ')}")
        print(f"Expected Port: {problem['expected_port']}")
        print(f"Current Port: {problem['current_port']}")
        print("\n[4] IDENTIFYING PROBLEM...")
        identify_problem(switch, problem)
        print("\n[5] GENERATING FIX...")
        fix = generate_fix(problem)
        print("\n[6] APPLYING FIX...")
        apply_fix(switch, fix)
        print("\n[7] VERIFYING FLOW...")
        verify_fix(switch, expected_flow_table, problem["src"], problem["dst"])
    else:
        print("No flow misconfiguration requires remediation.")

    remaining = detect_all_misconfigurations(expected_network_config, actual_network_config, switch)
    print("\n[8] VERIFICATION SCAN")
    print_findings(remaining)
    print("=" * 40)
    print(" REMEDIATION SUCCESS" if not remaining else "REMEDIATION INCOMPLETE")
    print("=" * 40)


# -------------------------------------------------------------------
# LIVE MININET DETECTION
# -------------------------------------------------------------------
def _run_json(host, command):
    output = host.cmd(command)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse output of '{command}': {output}") from exc


def collect_host_state(net, host_count=2):
    """Collect actual IPs, routes and listening ports from Mininet host namespaces."""
    devices = {}
    route_set = set()
    open_ports = set()
    expected_devices = {
        f"h{i}": {"ip": f"10.0.0.{i}", "subnet": "10.0.0.0/24", "gateway": None}
        for i in range(1, host_count + 1)
    }

    for host_name in expected_devices:
        host = net.get(host_name)
        interfaces = _run_json(host, "ip -j -4 addr show")
        ipv4_entry = None
        for interface in interfaces:
            if interface.get("ifname") == f"{host_name}-eth0":
                ipv4_entry = next((a for a in interface.get("addr_info", [])
                                   if a.get("family") == "inet"), None)
                break
        if ipv4_entry:
            devices[host_name] = {
                "ip": f"{ipv4_entry['local']}/{ipv4_entry['prefixlen']}",
                "gateway": None,
            }

        routes = _run_json(host, "ip -j -4 route show")
        for route in routes:
            destination = route.get("dst", "default")
            gateway = route.get("gateway")
            if destination == "default":
                if gateway:
                    route_set.add((destination, gateway))
            else:
                route_set.add((destination, gateway or "on-link"))

        # Use listening TCP/UDP sockets as a basic host-port inventory.
        sockets = host.cmd("ss -H -lntu")
        for line in sockets.splitlines():
            # ss columns include the local address/port before the peer address.
            # Match the port followed by whitespace (or end-of-line for short output).
            match = re.search(r":(\d+)(?:\s|$)", line.strip())
            if match:
                open_ports.add(int(match.group(1)))

    actual_config = {
        "devices": devices,
        "routes": [{"destination": dst, "next_hop": hop}
                   for dst, hop in sorted(route_set)],
        "open_ports": sorted(open_ports),
    }
    expected_config = {
        "devices": expected_devices,
        # Mininet hosts have a directly connected route and no default gateway.
        "routes": [{"destination": "10.0.0.0/24", "next_hop": "on-link"}],
        # No listening service is expected in this simple lab by default.
        "allowed_ports": [],
    }
    return expected_config, actual_config


def parse_ovs_port_flows(switch_name):
    """Return actual (input_port, output_port) forwarding pairs from OVS."""
    result = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch_name],
        capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Cannot read OVS flows for {switch_name}: {result.stderr.strip()}. "
            "Run live mode with sudo and check that Mininet is running."
        )

    pairs = set()
    for line in result.stdout.splitlines():
        priority_match = re.search(r"\bpriority=(\d+)", line)
        in_match = re.search(r"\bin_port=(\d+)", line)
        actions_match = re.search(r"\bactions=(.*)", line)
        if not priority_match or int(priority_match.group(1)) < 10 or not actions_match:
            continue
        action_text = actions_match.group(1).strip()
        if re.search(r"\bdrop\b", action_text):
            pairs.add((int(in_match.group(1)) if in_match else -1, 0))
            continue
        if not in_match:
            continue
        for out_match in re.finditer(r"\boutput:(\d+)", action_text):
            pairs.add((int(in_match.group(1)), int(out_match.group(1))))
    return pairs, result.stdout


def _expected_live_rules(path, host_count, switch_count):
    _, _, link_ports, _ = path_port_layout(switch_count)
    attachments, host_ports = host_port_layout(host_count, switch_count)
    expected = {f"s{i}": set() for i in range(1, switch_count + 1)}
    for index, switch in enumerate(path[1:-1], start=1):
        incoming = link_ports[(path[index - 1], switch)][1]
        outgoing = link_ports[(switch, path[index + 1])][0]
        expected[switch].update(((incoming, outgoing), (outgoing, incoming)))
    for index, edge in ((0, path[0]), (len(path) - 1, path[-1])):
        link = (path[index], path[index + 1]) if index == 0 else (path[index - 1], path[index])
        edge_port = link_ports[link][0] if index == 0 else link_ports[link][1]
        edge_hosts = [host_ports[h] for h, attached in attachments.items() if attached == edge]
        for host_port in edge_hosts:
            expected[edge].update((host_port, other) for other in edge_hosts if other != host_port)
            expected[edge].add((host_port, edge_port))
        expected[edge].update((edge_port, host_port) for host_port in edge_hosts)
    return expected


def _expected_live_flows(path, host_count, switch_count):
    rules = _expected_live_rules(path, host_count, switch_count)
    flows = {}
    for switch, pairs in rules.items():
        by_input = {}
        for in_port, out_port in pairs:
            by_input.setdefault(in_port, set()).add(out_port)
        flows[switch] = [
            f"priority=10,in_port={in_port},actions="
            + ",".join(f"output:{out_port}" for out_port in sorted(out_ports))
            for in_port, out_ports in sorted(by_input.items())
        ]
    return flows


def detect_live_flow_path(actual_rules, host_count=2, switch_count=4):
    """Accept either complete dynamically generated primary or backup rules."""
    primary_path, backup_path, _, _ = path_port_layout(switch_count)
    primary_rules = _expected_live_rules(primary_path, host_count, switch_count)
    backup_rules = _expected_live_rules(backup_path, host_count, switch_count)
    primary_ok = all(actual_rules.get(sw, set()) == rules for sw, rules in primary_rules.items())
    backup_ok = all(actual_rules.get(sw, set()) == rules for sw, rules in backup_rules.items())
    if primary_ok or backup_ok:
        selected = "PRIMARY" if primary_ok else "BACKUP"
        return [], selected

    findings = []
    for switch_name in (f"s{i}" for i in range(1, switch_count + 1)):
        actual = actual_rules.get(switch_name, set())
        expected_primary = primary_rules[switch_name]
        expected_backup = backup_rules[switch_name]
        if actual != expected_primary and actual != expected_backup:
            findings.append(_finding(
                "FLOW", "FLOW_PATH_MISMATCH", "HIGH",
                f"{switch_name} forwarding rules do not match either complete primary or backup path",
                switch=switch_name,
                actual=sorted(actual),
                expected_primary=sorted(expected_primary),
                expected_backup=sorted(expected_backup)))
    if not findings:
        findings.append(_finding("FLOW", "INCONSISTENT_PATH", "HIGH",
                                 "Switch rules form a mixed path; expected one complete primary or backup path"))
    return findings, "UNKNOWN"


def _repair_live_flow_path(actual_rules, host_count, switch_count):
    """Restore the closest controller path while preserving its table-miss rules."""
    primary_path, backup_path, _, _ = path_port_layout(switch_count)
    primary_rules = _expected_live_rules(primary_path, host_count, switch_count)
    backup_rules = _expected_live_rules(backup_path, host_count, switch_count)
    primary_matches = sum(actual_rules.get(sw, set()) == rules for sw, rules in primary_rules.items())
    backup_matches = sum(actual_rules.get(sw, set()) == rules for sw, rules in backup_rules.items())
    selected_path = primary_path if primary_matches >= backup_matches else backup_path
    expected_flows = _expected_live_flows(selected_path, host_count, switch_count)

    for switch, entries in expected_flows.items():
        dumped = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
            capture_output=True, text=True, check=False
        )
        if dumped.returncode != 0:
            raise RuntimeError(f"Could not inspect flows on {switch}: {dumped.stderr.strip()}")
        priorities = {
            int(match.group(1))
            for line in dumped.stdout.splitlines()
            if (match := re.search(r"\bpriority=(\d+)", line))
            if int(match.group(1)) > 0
        }
        for priority in sorted(priorities):
            deleted = subprocess.run(
                ["ovs-ofctl", "-O", "OpenFlow13", "del-flows", switch, f"priority={priority}"],
                capture_output=True, text=True, check=False
            )
            if deleted.returncode != 0:
                raise RuntimeError(
                    f"Could not remove unauthorized priority-{priority} flows on "
                    f"{switch}: {deleted.stderr.strip()}"
                )
        if entries:
            added = subprocess.run(
                ["ovs-ofctl", "-O", "OpenFlow13", "add-flows", switch, "-"],
                input="\n".join(entries) + "\n",
                capture_output=True, text=True, check=False
            )
            if added.returncode != 0:
                raise RuntimeError(f"Could not restore managed flows on {switch}: {added.stderr.strip()}")
    return "PRIMARY" if selected_path == primary_path else "BACKUP"


def _run_host_checked(host, command):
    output = host.cmd(f'{command}; status=$?; printf "\\n__SDN_EXIT:%s" "$status"')
    match = re.search(r"__SDN_EXIT:(\d+)\s*$", output)
    if not match or int(match.group(1)) != 0:
        raise RuntimeError(f"Live host remediation failed: {output.strip()}")


def _repair_live_host_config(net, expected_config, actual_config):
    repaired = []
    for name, expected in expected_config["devices"].items():
        actual = actual_config["devices"].get(name)
        expected_network = ip_network(expected["subnet"], strict=False)
        expected_address = f"{expected['ip']}/{expected_network.prefixlen}"
        if actual and actual.get("ip") == expected_address:
            continue
        if not re.fullmatch(r"h\d+", name):
            raise ValueError(f"Refusing to configure unexpected Mininet host name: {name}")
        interface = f"{name}-eth0"
        host = net.get(name)
        _run_host_checked(host, f"ip addr flush dev {interface} scope global")
        _run_host_checked(host, f"ip addr add {expected_address} dev {interface}")
        repaired.append(f"{name} address restored to {expected_address}")

    expected_routes = {
        (route["destination"], route["next_hop"])
        for route in expected_config.get("routes", [])
    }
    for name in expected_config["devices"]:
        host = net.get(name)
        actual_host_routes = set()
        for route in _run_json(host, "ip -j -4 route show"):
            destination = route.get("dst", "default")
            gateway = route.get("gateway")
            actual_host_routes.add((destination, gateway or "on-link"))

        for destination, next_hop in sorted(actual_host_routes - expected_routes):
            network = ip_network(destination, strict=False) if destination != "default" else None
            gateway = None if next_hop == "on-link" else ip_interface(f"{next_hop}/32").ip
            interface = f"{name}-eth0"
            if network is None:
                route_command = (
                    f"ip route del default via {gateway}" if gateway is not None
                    else f"ip route del default dev {interface}"
                )
            elif gateway is not None:
                route_command = f"ip route del {network} via {gateway}"
            else:
                route_command = f"ip route del {network} dev {interface}"
            _run_host_checked(host, route_command)
            repaired.append(f"{name} unexpected route {destination} removed")

        for destination, next_hop in sorted(expected_routes - actual_host_routes):
            network = ip_network(destination, strict=False)
            interface = f"{name}-eth0"
            if next_hop == "on-link":
                route_command = f"ip route replace {network} dev {interface}"
            else:
                gateway = ip_interface(f"{next_hop}/32").ip
                route_command = f"ip route replace {network} via {gateway} dev {interface}"
            _run_host_checked(host, route_command)
            repaired.append(f"{name} expected route {network} restored")
    return repaired


def _collect_live_findings(net, host_count, switch_count):
    expected_config, actual_config = collect_host_state(net, host_count)
    actual_rules = {}
    for switch_name in (f"s{i}" for i in range(1, switch_count + 1)):
        pairs, _ = parse_ovs_port_flows(switch_name)
        actual_rules[switch_name] = pairs

    findings = []
    findings.extend(detect_ip_misconfigurations(expected_config, actual_config))
    findings.extend(detect_routing_misconfigurations(expected_config, actual_config))
    findings.extend(detect_open_port_misconfigurations(expected_config, actual_config))
    flow_findings, selected_path = detect_live_flow_path(actual_rules, host_count, switch_count)
    findings.extend(flow_findings)
    return expected_config, actual_config, actual_rules, findings, selected_path


def run_live_scan(net, host_count=2, switch_count=4, auto_remediate=True):
    print("\n" + "=" * 46)
    print(" LIVE SDN MISCONFIGURATION DETECTION")
    print("=" * 46)

    expected_config, actual_config, actual_rules, findings, selected_path = _collect_live_findings(
        net, host_count, switch_count)
    print("\n[1] ACTUAL MININET HOST CONFIGURATION")
    for name, details in actual_config["devices"].items():
        print(f"{name}: IP {details['ip']} | gateway {details['gateway']}")
    print("Routes:")
    for route in actual_config["routes"]:
        print(f"  {route['destination']} via {route['next_hop']}")
    print(f"Listening ports found: {actual_config['open_ports']}")

    print("\n[2] ACTUAL OVS FORWARDING RULES")
    for switch_name in (f"s{i}" for i in range(1, switch_count + 1)):
        pairs = actual_rules[switch_name]
        print(f"{switch_name}: " + (", ".join(
            f"in_port {in_port} -> out_port {out_port}"
            for in_port, out_port in sorted(pairs)) if pairs else "(no forwarding rules)"))

    print("\n[3] DETECTION REPORT")
    print_findings(findings)
    if selected_path != "UNKNOWN":
        print(f"\nValidated forwarding path: {selected_path}")
    print("\n[4] AUTO-REMEDIATION STATUS")
    if not findings:
        print("No remediation required.")
    elif not auto_remediate:
        print("Auto-remediation is disabled; findings were not changed.")
    else:
        actions = []
        if any(f["module"] in ("IP", "ROUTING") for f in findings):
            try:
                actions.extend(_repair_live_host_config(net, expected_config, actual_config))
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"Host IP/route remediation failed: {exc}")
        if any(f["module"] == "FLOW" for f in findings):
            try:
                path = _repair_live_flow_path(actual_rules, host_count, switch_count)
                actions.append(f"forwarding rules restored for {path} path")
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"OVS flow remediation failed: {exc}")
        for action in actions:
            print(f"Applied: {action}")
        if any(f["module"] == "OPEN_PORTS" for f in findings):
            print("Open-port findings were not auto-closed: stopping an unknown service could disrupt the host.")
        _, _, _, remaining, verified_path = _collect_live_findings(net, host_count, switch_count)
        print("\nVerification after remediation:")
        print_findings(remaining)
        if verified_path != "UNKNOWN":
            print(f"Validated forwarding path: {verified_path}")
    print("=" * 46)


def run_live_mode(args):
    if not 2 <= args.hosts <= 20 or not 4 <= args.switches <= 16:
        print("Live topology requires 2–20 hosts and 4–16 switches.")
        return 2
    if sys.version_info < (3, 8):
        print("Python 3.8 or newer is required.")
        return 2
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("Run live mode with sudo, for example:")
        print("sudo env SDN_HOSTS=2 SDN_SWITCHES=4 python3 ndc/auto_remediation_full.py --mode live")
        return 2

    try:
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
        from mininet.cli import CLI
        from topology import ResilientTopo
    except ImportError as exc:
        print(f"Could not import Mininet or topology.py: {exc}")
        print("Save auto_remediation.py beside topology.py and run it with the")
        print("system Python that can import Mininet.")
        return 2

    net = None
    try:
        print("=" * 46)
        print(" STARTING LIVE MININET DETECTION LAB")
        print("=" * 46)
        net = Mininet(topo=ResilientTopo(host_count=args.hosts, switch_count=args.switches),
                      switch=OVSSwitch, controller=None,
                      autoSetMacs=True, build=False)
        net.addController("c0", controller=RemoteController,
                          ip=args.controller_ip, port=args.controller_port)
        net.build()
        net.start()
        print("\nWaiting for OS-Ken controller to install forwarding rules...")
        time.sleep(3)
        run_live_scan(net, args.hosts, args.switches)
        if not args.no_cli:
            print("\nMininet CLI is ready. Commands: pingall, scan, links, net, exit")
            primary, _, _, _ = path_port_layout(args.switches)
            print(f"Try a primary link: link {primary[0]} {primary[1]} down -> scan")
            class DetectionCLI(CLI):
                def do_scan(self, line):
                    """Run the live misconfiguration detector against this Mininet network."""
                    run_live_scan(self.mn, args.hosts, args.switches)
            DetectionCLI(net)
    except KeyboardInterrupt:
        print("\nLive detection stopped.")
    except Exception as exc:
        print(f"\nLive mode failed: {exc}")
        print("Check that controller.py is running and topology.py is in this folder.")
        return 1
    finally:
        if net is not None:
            net.stop()
    return 0


def parse_arguments():
    parser = argparse.ArgumentParser(description="SDN misconfiguration detection demo/live lab")
    parser.add_argument("--mode", choices=("demo", "live"), default="demo",
                        help="demo uses sample data; live starts the Mininet topology")
    parser.add_argument("--controller-ip", default="127.0.0.1",
                        help="OS-Ken controller IP (default: 127.0.0.1)")
    parser.add_argument("--controller-port", type=int, default=6653,
                        help="OpenFlow controller port (default: 6653)")
    parser.add_argument("--hosts", type=int, default=int(os.environ.get("SDN_HOSTS", "2")),
                        help="Number of hosts (2-20)")
    parser.add_argument("--switches", type=int, default=int(os.environ.get("SDN_SWITCHES", "4")),
                        help="Number of switches (4-16)")
    parser.add_argument("--no-cli", action="store_true",
                        help="In live mode, scan once and exit without opening Mininet CLI")
    return parser.parse_args()


def main():
    args = parse_arguments()
    if args.mode == "live":
        return run_live_mode(args)
    run_demo_mode()
    return 0


if __name__ == "__main__":
    sys.exit(main())
