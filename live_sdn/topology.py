#!/usr/bin/env python3
"""Mininet topology for the live SDN detect-and-auto-remediation lab."""
import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from path_config import host_attachments, resilient_paths

class ResilientTopo(Topo):
    def __init__(self, host_count=2, switch_count=4, **opts):
        if host_count < 2 or switch_count < 4:
            raise ValueError("A resilient topology needs at least 2 hosts and 4 switches")
        self.host_count = host_count
        self.switch_count = switch_count
        super().__init__(**opts)

    def build(self):
        attachments = host_attachments(self.host_count, self.switch_count)
        for i in range(1, self.host_count + 1):
            self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        for i in range(1, self.switch_count + 1):
            self.addSwitch(f"s{i}", dpid=f"{i:016x}", protocols="OpenFlow13")

        # Keep the first host link and path links ordered with path_config.py.
        self.addLink("h1", attachments["h1"])
        primary, backup = resilient_paths(self.switch_count)
        for path in (primary, backup):
            for left, right in zip(path, path[1:]):
                self.addLink(left, right)
        for host, switch in attachments.items():
            if host != "h1":
                self.addLink(host, switch)

def run(host_count=2, switch_count=4):
    topo = ResilientTopo(host_count=host_count, switch_count=switch_count)
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,
        autoSetMacs=True,
        build=False
    )
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    net.build()
    net.start()
    primary, backup = resilient_paths(switch_count)
    info(f"\n*** Topology started with {host_count} hosts and {switch_count} switches.\n")
    info(f"*** Primary path: {' -> '.join(primary)} | Backup path: {' -> '.join(backup)}\n")
    info("*** Commands: pingall, links, net, scan, exit\n")
    info("*** Test failover by taking a primary-path link down, then run scan.\n\n")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    run(int(os.environ.get("SDN_HOSTS", "2")), int(os.environ.get("SDN_SWITCHES", "4")))
