# Four-Member Project Guide

Project: SDN-Based Detection and Auto-Remediation of Network Misconfigurations

## Member 1 — SDN Controller and Network Management
Files:
- `live_sdn/controller.py`
- `live_sdn/topology.py`
- `live_sdn/path_config.py`

Responsibilities:
- Build the Mininet topology and OpenFlow 1.3 controller.
- Maintain the primary route and switch to the backup route when a primary link fails.
- Restore the primary route after the link is restored.

Live demo commands (Linux/WSL2; requires Mininet, Open vSwitch and OS-Ken):
Use the dashboard's **Live WSL commands** button for the selected counts. For example, with 6 hosts and 8 switches:
Terminal 1:
```bash
cd live_sdn
SDN_HOSTS=6 SDN_SWITCHES=8 osken-manager --verbose controller.py
```
Terminal 2, from the project root:
```bash
sudo env PYTHONPATH="$PWD/live_sdn" SDN_HOSTS=6 SDN_SWITCHES=8 python3 ndc/auto_remediation_full.py --mode live --hosts 6 --switches 8
```
Mininet commands:
```text
pingall
scan
link s1 s2 down
scan
link s1 s2 up
scan
exit
```

## Member 2 — Misconfiguration Detection
Files:
- `core/engine.py` (`Network.detect`)
- `ndc/auto_remediation_full.py`

Responsibilities:
- Compare observed state with the expected baseline.
- Detect IP, routing, firewall, open-port, and switch-flow deviations.
- Report affected target, actual/expected state, severity and confidence score.
- The live scan treats blocking OpenFlow rules as flow-path mismatches; it does not inspect host nftables/iptables policy.

## Member 3 — Auto-Remediation and Security
Files:
- `core/engine.py` (`Network.remediate`, `Network.cycle`)
- `server/app.py` (closed-loop monitor)

Responsibilities:
- Apply corrective actions to the simulation state.
- Re-detect to verify the repair.
- Record success/failure and timings.
- In live Mininet mode, repair host IP/subnet and route deviations and restore managed OVS forwarding rules, then verify by rescanning.
- Do not stop unknown listening services automatically; open-port findings are reported for operator review.

## Member 4 — Simulation, Testing and Dashboard
Files:
- `dashboard/index.html`
- `tests/test_suite.py`
- `server/app.py`
- `live_sdn/topology.py`

Responsibilities:
- Run the dashboard and demonstrate fault injection.
- Test normal state, fault detection, remediation, failover, stress and latency.
- Save test results and screenshots for the report.

## Run the simulation dashboard
From the project root:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python3 server/app.py
```
Open `http://localhost:5000`.

The dashboard's **Hosts (demo + live)** and **Switches (demo + live)** inputs control the selected counts
(2–20 hosts, 4–16 switches). **Apply topology** rebuilds the simulation and displays matching commands for
the live topology; run those manually in two WSL terminals. A running Mininet network must be exited and
restarted to use different counts.

If creating the environment fails, install the OS Python venv package first on Ubuntu:
```bash
sudo apt update
sudo apt install python3-venv python3-pip
```

## Run the engine self-test
```bash
python3 core/engine.py
```

## Run the automated tests
```bash
python3 tests/test_suite.py
```
The test suite writes `tests/results.csv`. It covers the simulation engine, controller route-selection logic, and mocked live detection/remediation helpers; it does not require a running Mininet instance.

## Important scope distinction
- The simulation engine models detection and remediation for five fault classes: IP, routing, firewall, open ports, and switch flows.
- The live controller supports primary/backup path failover and restoration.
- Live scans automatically restore host IP/subnet settings, routes, and managed OVS forwarding flows, then rescan to verify. Blocking flows are detected as path mismatches. Unexpected listening ports are reported but not terminated automatically because the service owner cannot be inferred safely.
- Recovery-time values in the dashboard are target/reference values unless replaced with measurements from actual experiments.
