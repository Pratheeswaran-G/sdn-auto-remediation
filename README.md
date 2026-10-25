# SDN-Based Detection and Auto-Remediation of Network Misconfigurations
(Dashboard name: **SDN Testing Dashboard**)
CS23502 – Networks and Data Communication · Mini Project · Mentor: Dr. S. Neelavathy Pari

## Team roles
| Member | Role | Main files |
|---|---|---|
| Rajasimman R | SDN controller and network management | `live_sdn/controller.py` |
| Thirudhanish T | Misconfiguration detection | `core/engine.py` (`detect`), `ndc/auto_remediation_full.py` |
| Praveenkanth M | Auto-remediation and security | `core/engine.py` (`remediate`, `cycle`) |
| Pratheeswaran G | Simulation, testing and dashboard | `live_sdn/topology.py`, `server/app.py`, `dashboard/index.html`, `tests/test_suite.py` |

## Project structure
```text
sdn-auto-remediation/
├── tests/test_suite.py       # Tests for all four roles, writes tests/results.csv
├── core/engine.py            # baseline, 5 detectors, remediation, verification, confidence score
├── server/app.py             # Flask REST API + 1 s closed-loop monitor
├── dashboard/index.html      # live dashboard (uses the API, or a built-in browser simulation)
├── live_sdn/controller.py    # OS-Ken OpenFlow 1.3 controller (primary/backup failover)
├── live_sdn/topology.py      # configurable resilient Mininet topology
├── live_sdn/path_config.py   # shared dynamic path and switch-port layout
├── ndc/auto_remediation_full.py   # demo + live Mininet detector (CLI)
├── requirements.txt
└── README.md
```

## 1. Live demo dashboard (works anywhere)
```bash
pip install -r requirements.txt
python3 server/app.py          # open http://localhost:5000
```
Or just open `dashboard/index.html` in a browser (no backend needed, it simulates the same engine).
Click **Wrong IP / Routing / Firewall / Open Ports / Switch** to inject a fault. The node turns red, the alert is
logged, the engine rewrites the entry to the baseline, verifies it and the node turns green again.
Toggle **Auto-Remediate: OFF** to see detection-only behaviour (the manual-fix baseline).
Use the **Hosts** and **Switches** fields and select **Apply topology** to rebuild the resilient simulated
topology. Supported counts are 2–20 hosts and 4–16 switches. The switches are split across primary and
backup paths; hosts attach to the two edge switches. Applying a topology resets the simulation state and
shows the matching live commands. The count selectors are shared by the demo and live command generator.

## 2. Engine self-test
```bash
python3 core/engine.py         # injects all 5 faults, detects, fixes, verifies
python3 ndc/auto_remediation_full.py --mode demo  # sample IP/route/port/flow repair and verification
```

## 3. Testing (all four roles)
```bash
python3 tests/test_suite.py    # exits 0 if all tests pass, results in tests/results.csv
```
The dashboard has the same suite in the **Testing Lab** panel (Run all tests, Stress x200, Show CSV). Also available at `GET /api/tests/run`.

| Owner | Tests |
|---|---|
| Rajasimman | primary -> backup -> primary failover logic, flow rules cover the primary path |
| Thirudhanish | detect each of the 5 fault types, no false positives on a healthy baseline |
| Praveenkanth | remediate each of the 5 fault types, 5 simultaneous faults, idempotent remediation |
| Pratheeswaran | detection-only keeps the fault, dynamic topology, latency benchmark, 200-round stress test |
| Live integration checks | flow repair, blocking-flow detection, subnet-mask detection, and host IP/route repair |

## 4. Real Mininet lab (Linux / WSL2)
The dashboard's **Live WSL commands** button generates these commands with its selected host/switch counts.
Run them manually in two WSL terminals from the project root; the dashboard intentionally does not start
privileged Mininet processes itself.

```bash
# Terminal 1
cd live_sdn && SDN_HOSTS=6 SDN_SWITCHES=8 osken-manager --verbose controller.py
# Terminal 2
sudo env PYTHONPATH="$PWD/live_sdn" SDN_HOSTS=6 SDN_SWITCHES=8 python3 ndc/auto_remediation_full.py --mode live --hosts 6 --switches 8
# mininet> pingall | scan | link s1 s2 down | scan | link s1 s2 up | scan
```
Live scans automatically repair detected host IP/subnet and route deviations
and restore the closest valid primary or backup OVS path, then rescan to verify
the result. Blocking OVS flows are treated as path mismatches. Unexpected
listening ports are reported but not killed automatically, since the detector
cannot safely determine whether stopping their service is allowed. The OS-Ken
controller continues to manage link-failure failover and restoration.

## Method
Confidence score `C = Σ w_j · δ_j` over violated fault classes, alert when a deviation from the baseline is found,
remediation `f' = R_j(f)` (FlowMod / config rewrite), then re-detect to verify.
Timings: `T_detect = t_alert − t_fault`, `T_fix = t_resolved − t_alert`.

## Honest scope notes
* The dashboard and `core/engine.py` use a simulated network model, so all five fault types can be injected and healed safely. Host/switch selectors configure this simulation.
* In the real Mininet lab the controller manages link failover; live scans also
  repair detected host IP/subnet, route, and managed OVS flow deviations, then
  verify by rescanning. Unexpected listening ports remain findings for an operator to review.
* A blocking OpenFlow drop rule is detected as a flow-path mismatch and removed
  when the lab path is restored. The live scanner does not inspect arbitrary
  host firewall frameworks such as nftables/iptables; firewall fault injection
  and remediation for those are covered by the dashboard simulation.
* Live Mininet supports 2–20 hosts and 4–16 switches. Use the dashboard-generated commands to start a matching topology; changing the dashboard selection does not reconfigure an already-running Mininet network.
* The "48 s / 22 s / 4 s" recovery bars on the dashboard are the targets from the review slides, not measured results.
  Replace them with your own measurements from Week 10 experiments.
