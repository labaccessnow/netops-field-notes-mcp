"""Infer device adjacency from shared subnets and render a Mermaid diagram.
v0.1 uses shared-subnet inference (devices with an interface on the same network
are adjacent); v0.2 can add LLDP/CDP neighbor parsing for physical links."""
from __future__ import annotations
import re
from collections import defaultdict

# skip subnets too broad to imply a real shared segment
def _too_broad(net: str) -> bool:
    try:
        return int(net.split("/")[1]) < 16
    except (IndexError, ValueError):
        return True

def infer(facts: list[dict]) -> dict:
    """Returns {subnet: [device,...]} for subnets shared by >=2 devices. A subnet
    contained in a broader DECLARED subnet is merged into it (same L2 segment — e.g.
    a /24-masked host on a /23 mgmt LAN)."""
    import ipaddress
    sub = defaultdict(set)
    for f in facts:
        for net in f["nets"]:
            if not _too_broad(net):
                sub[net].add(f["device"])
    merged: dict = {}
    for net in sorted(sub, key=lambda n: int(n.split("/")[1])):  # broadest (smallest prefix) first
        n = ipaddress.ip_network(net)
        host = next((b for b in merged if n.subnet_of(ipaddress.ip_network(b))), None)
        if host:
            merged[host] |= sub[net]
        else:
            merged[net] = set(sub[net])
    return {net: sorted(d) for net, d in merged.items() if len(d) >= 2}

def _nid(name: str) -> str:
    return "d_" + re.sub(r"[^A-Za-z0-9]", "_", name)

def mermaid(facts: list[dict], shared: dict) -> str:
    lines = ["graph LR"]
    linked = {d for devs in shared.values() for d in devs}
    for f in facts:
        label = f'{f["hostname"]}<br/>{f["role"]} · {f["vendor"]}'
        lines.append(f'  {_nid(f["device"])}["{label}"]')
    for i, (net, devs) in enumerate(sorted(shared.items())):
        snid = f"net{i}"
        lines.append(f'  {snid}(("{net}"))')
        for d in devs:
            lines.append(f"  {snid} --- {_nid(d)}")
    # class styling
    lines.append("  classDef net fill:#eef5ff,stroke:#8fb6e8,color:#234;")
    nets = " ".join(f"net{i}" for i in range(len(shared)))
    if nets:
        lines.append(f"  class {nets} net;")
    return "\n".join(lines), sorted(linked)
