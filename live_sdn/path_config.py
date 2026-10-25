"""Shared resilient-path and OpenFlow-port layout for the live Mininet lab."""

MAX_HOSTS = 20
MAX_SWITCHES = 16


def resilient_paths(switch_count):
    if not 4 <= switch_count <= MAX_SWITCHES:
        raise ValueError(f"switch_count must be between 4 and {MAX_SWITCHES}")
    primary = ["s1"] + [f"s{i}" for i in range(2, switch_count, 2)] + [f"s{switch_count}"]
    backup = ["s1"] + [f"s{i}" for i in range(3, switch_count, 2)] + [f"s{switch_count}"]
    return primary, backup


def host_attachments(host_count, switch_count):
    if not 2 <= host_count <= MAX_HOSTS:
        raise ValueError(f"host_count must be between 2 and {MAX_HOSTS}")
    source_count = (host_count + 1) // 2
    return {
        f"h{i}": "s1" if i <= source_count else f"s{switch_count}"
        for i in range(1, host_count + 1)
    }


def path_port_layout(switch_count):
    """Return ports for both paths using the link-add order in ResilientTopo."""
    primary, backup = resilient_paths(switch_count)
    next_port = {f"s{i}": int(i == 1) for i in range(1, switch_count + 1)}
    port_by_link = {}
    for path in (primary, backup):
        for left, right in zip(path, path[1:]):
            next_port[left] += 1
            next_port[right] += 1
            port_by_link[(left, right)] = (next_port[left], next_port[right])
    return primary, backup, port_by_link, next_port


def host_port_layout(host_count, switch_count):
    attachments = host_attachments(host_count, switch_count)
    _, _, _, next_port = path_port_layout(switch_count)
    ports = {}
    for host, switch in attachments.items():
        if host == "h1":
            ports[host] = 1
        else:
            next_port[switch] += 1
            ports[host] = next_port[switch]
    return attachments, ports
