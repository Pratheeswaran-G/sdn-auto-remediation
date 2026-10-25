"""
Live SDN Detect-and-Auto-Remediation controller.
OS-Ken + OpenFlow 1.3 resilient topology with configurable path lengths.

Switch and host counts are set with SDN_SWITCHES and SDN_HOSTS.
Expected Mininet port numbers are defined in path_config.py.
"""
import os
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from path_config import host_port_layout, path_port_layout

class DetectHealController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.switch_count = int(os.environ.get("SDN_SWITCHES", "4"))
        self.host_count = int(os.environ.get("SDN_HOSTS", "2"))
        self.primary_path, self.backup_path, self.path_ports, _ = path_port_layout(self.switch_count)
        self.host_attachments, self.host_ports = host_port_layout(self.host_count, self.switch_count)
        self.primary_ports = self._path_failure_ports(self.primary_path)
        self.backup_ports = self._path_failure_ports(self.backup_path)
        self.datapaths = {}
        self.failed_ports = set()
        self.use_backup = False
        self._last_reason = "startup"

    def _path_failure_ports(self, path):
        ports = set()
        for left, right in zip(path, path[1:]):
            left_port, right_port = self.path_ports[(left, right)]
            ports.add((int(left[1:]), left_port))
            ports.add((int(right[1:]), right_port))
        return ports

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.logger.info("Switch s%d connected (dpid=%d)", dp.id, dp.id)
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        # Table-miss: send unmatched packets to controller while installing.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        if len(self.datapaths) >= self.switch_count:
            self._install_all_paths()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        port_no = msg.desc.port_no
        key = (dp.id, port_no)
        ofp = dp.ofproto
        is_down = (msg.reason == ofp.OFPPR_DELETE) or bool(msg.desc.state & ofp.OFPPS_LINK_DOWN)
        if is_down:
            self.failed_ports.add(key)
            self.logger.warning("LINK/PORT DOWN detected: s%d port %d", dp.id, port_no)
        else:
            self.failed_ports.discard(key)
            self.logger.info("LINK/PORT UP detected: s%d port %d", dp.id, port_no)
        self._select_route()
        self._install_all_paths()

    def _select_route(self):
        # Primary route needs both s1-s2 and s2-s4 links to be up.
        primary_failed = any(p in self.failed_ports for p in self.primary_ports)
        backup_failed = any(p in self.failed_ports for p in self.backup_ports)
        if primary_failed and not backup_failed:
            new_backup = True
            reason = "primary path failed; backup path available"
        elif not primary_failed:
            new_backup = False
            reason = "primary path available"
        else:
            # Both paths appear to have a failed port; use backup as best effort.
            new_backup = True
            reason = "primary and backup have failures; backup selected as best effort"
        if new_backup != self.use_backup or reason != self._last_reason:
            self.use_backup = new_backup
            self._last_reason = reason
            self.logger.warning("ROUTE SELECTED: %s (%s)", "BACKUP" if self.use_backup else "PRIMARY", reason)

    def _add_flow(self, dp, priority, match, actions):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=instructions, idle_timeout=0, hard_timeout=0
        )
        dp.send_msg(mod)

    def _delete_flows(self, dp):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch()
        ))

    def _install_all_paths(self):
        for dpid, dp in list(self.datapaths.items()):
            self._delete_flows(dp)
            self._add_flow(dp, 0, dp.ofproto_parser.OFPMatch(), [
                dp.ofproto_parser.OFPActionOutput(
                    dp.ofproto.OFPP_CONTROLLER, dp.ofproto.OFPCML_NO_BUFFER
                )
            ])
        path = self.backup_path if self.use_backup else self.primary_path
        for index, switch in enumerate(path[1:-1], start=1):
            previous_link = self.path_ports[(path[index - 1], switch)]
            next_link = self.path_ports[(switch, path[index + 1])]
            self._route_pair(int(switch[1:]), previous_link[1], next_link[0])
        for edge_switch, neighbor, index in (
            (path[0], path[1], 0),
            (path[-1], path[-2], len(path) - 1),
        ):
            edge_dpid = int(edge_switch[1:])
            link = (neighbor, edge_switch) if index == len(path) - 1 else (edge_switch, neighbor)
            edge_port = self.path_ports[link][1 if index == len(path) - 1 else 0]
            host_ports = [
                self.host_ports[host]
                for host, attached_switch in self.host_attachments.items()
                if attached_switch == edge_switch
            ]
            self._install_edge_flows(edge_dpid, host_ports, edge_port)

        self.logger.info("Installed %s route flows", "BACKUP" if self.use_backup else "PRIMARY")

    def _install_edge_flows(self, dpid, host_ports, network_port):
        dp = self.datapaths.get(dpid)
        if dp is None:
            return
        parser = dp.ofproto_parser
        for host_port in host_ports:
            actions = [parser.OFPActionOutput(port) for port in host_ports if port != host_port]
            actions.append(parser.OFPActionOutput(network_port))
            self._add_flow(dp, 10, parser.OFPMatch(in_port=host_port), actions)
        self._add_flow(
            dp, 10, parser.OFPMatch(in_port=network_port),
            [parser.OFPActionOutput(port) for port in host_ports]
        )

    def _route_pair(self, dpid, left_port, right_port):
        dp = self.datapaths.get(dpid)
        if dp is None:
            return
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        # Match ingress port, forwarding both ARP and IPv4 Ethernet frames.
        for in_port, out_port in ((left_port, right_port), (right_port, left_port)):
            match = parser.OFPMatch(in_port=in_port)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(dp, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == CONFIG_DISPATCHER:
            # Keep datapath during config so features can be processed.
            self.datapaths[dp.id] = dp
