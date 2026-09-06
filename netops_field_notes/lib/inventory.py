"""Extract per-device facts from a config (best-effort, multi-vendor, regex/stdlib).
The system-of-record layer NetDoc builds its docs + topology from. v0.2 can swap in
an LLM extractor for richer facts; deterministic regex keeps the MVP key-free."""
from __future__ import annotations
import ipaddress, re

def role_of(name: str, vendor: str) -> str:
    n = name.lower()
    if vendor == "opnsense" or "fw" in n or "firewall" in n:
        return "firewall"
    if vendor == "mikrotik" or vendor == "edgeos" or n.startswith(("rb", "crs", "er")) \
       or "router" in n:
        return "router"
    if vendor == "edgeswitch" or n.startswith(("es-", "es1", "sw")) or "switch" in n:
        return "switch"
    if vendor == "slp" or "slp" in n:
        return "PDU"
    if vendor == "digi" or "digicm" in n:
        return "console-server"
    return "device"

def hostname_of(text: str, fallback: str) -> str:
    # EdgeOS config.boot uses `host-name` for the SYSTEM name AND for DDNS /
    # static-host-mappings (often FQDNs) — prefer a non-FQDN system label.
    eos = [m.strip('"') for m in re.findall(r'(?:set system |^\s*)host-name\s+"?([A-Za-z0-9_.\-]+)', text, re.M)]
    for h in eos:
        if "." not in h:  # system host-names are simple labels; skip DDNS/static FQDNs
            return h
    for p in (r'/system identity[^\n]*name="?([^\s"]+)',
              r'<hostname>([^<]+)</hostname>',
              r'^\s*hostname\s+"?([A-Za-z0-9_.\-]+)'):
        m = re.search(p, text, re.M)
        if m and m.group(1).strip():
            return m.group(1).strip().strip('"')
    return eos[0] if eos else fallback

def _is_opnsense(text: str, vendor: str) -> bool:
    return vendor == "opnsense" or "<opnsense" in text[:1000] or "<ipaddr>" in text[:8000]

def _opnsense_addresses(text: str) -> list[dict]:
    """Parse OPNsense config.xml interface IPs (<ipaddr>/<subnet> per interface)."""
    out = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(text)
        ifs = root.find("interfaces")
        for iface in (list(ifs) if ifs is not None else []):
            ip = (iface.findtext("ipaddr") or "").strip()
            sub = (iface.findtext("subnet") or "").strip()
            if re.match(r"\d{1,3}(\.\d{1,3}){3}$", ip) and sub.isdigit():
                try:
                    cidr = int(sub)
                    out.append({"ip": ip, "cidr": cidr,
                                "net": str(ipaddress.ip_network(f"{ip}/{cidr}", strict=False))})
                except ValueError:
                    pass
    except Exception:
        pass
    return out

def _regex_addresses(text: str) -> list[dict]:
    out = []
    for m in re.finditer(r'address[=\s]+["\']?(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})', text):
        ip, cidr = m.group(1), int(m.group(2))
        if 8 <= cidr <= 32:
            try:
                out.append({"ip": ip, "cidr": cidr,
                            "net": str(ipaddress.ip_network(f"{ip}/{cidr}", strict=False))})
            except ValueError:
                pass
    # EdgeSwitch 'ip address A MASK' AND FastPath mgmt 'network parms A MASK [GW]'
    for m in re.finditer(r'(?:ip address|network parms)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})', text):
        ip, mask = m.group(1), m.group(2)
        try:
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            out.append({"ip": ip, "cidr": cidr,
                        "net": str(ipaddress.ip_network(f"{ip}/{cidr}", strict=False))})
        except ValueError:
            pass
    # SLP PDUs (and similar): 'IP Address: A' + 'Subnet Mask: M' on separate lines
    ipm = re.search(r'IP Address[:\s]+(\d{1,3}(?:\.\d{1,3}){3})', text)
    mm = re.search(r'Subnet Mask[:\s]+(\d{1,3}(?:\.\d{1,3}){3})', text)
    if ipm and mm:
        try:
            cidr = ipaddress.IPv4Network(f"0.0.0.0/{mm.group(1)}").prefixlen
            out.append({"ip": ipm.group(1), "cidr": cidr,
                        "net": str(ipaddress.ip_network(f"{ipm.group(1)}/{cidr}", strict=False))})
        except ValueError:
            pass
    return out

def addresses(text: str, vendor: str = "") -> list[dict]:
    """All IPv4 addr+cidr — OPNsense XML, EdgeOS/MikroTik 'address[=]A/N',
    EdgeSwitch 'ip address A MASK'. Returns deduped [{ip,cidr,net}]."""
    out = _opnsense_addresses(text) if _is_opnsense(text, vendor) else _regex_addresses(text)
    seen, ded = set(), []
    for a in out:
        k = (a["ip"], a["cidr"])
        if k not in seen and not a["ip"].startswith("127."):
            seen.add(k); ded.append(a)
    return ded

def _expand(part: str, v: set, maxspan: int = 300):
    part = part.strip()
    if "-" in part:
        a, b = part.split("-", 1)
        if a.isdigit() and b.isdigit() and 0 <= int(b) - int(a) <= maxspan:
            v |= set(range(int(a), int(b) + 1))
    elif part.isdigit():
        v.add(int(part))

def vlans(text: str, vendor: str = "") -> list[int]:
    """VLANs — OPNsense <tag>, EdgeSwitch authoritative `vlan database` list (NOT
    the noisy 'switchport trunk allowed' ranges), else EdgeOS vif + MikroTik vlan-id(s)."""
    v: set = set()
    if _is_opnsense(text, vendor):
        v = {int(t) for t in re.findall(r"<tag>(\d{1,4})</tag>", text)}
    elif vendor == "edgeswitch" or "vlan database" in text:
        m = re.search(r"vlan database(.*?)\n\s*exit", text, re.S | re.I)
        for line in (m.group(1).splitlines() if m else []):
            ml = re.match(r"\s*vlan\s+([\d,\-]+)\s*$", line)
            if ml:
                for part in ml.group(1).split(","):
                    _expand(part, v)
    else:  # EdgeOS (vif N) + MikroTik (vlan-id= / vlan-ids=1000,1800)
        for m in re.finditer(r"\bv(?:lan|if)[ =]+(\d{1,4})\b", text):
            v.add(int(m.group(1)))
        for m in re.finditer(r"vlan-ids?[=\s]+([\d,\-]+)", text):
            for part in m.group(1).split(","):
                _expand(part, v)
    return sorted(x for x in v if 1 <= x <= 4094)[:64]

def extract(text: str, vendor: str, device: str) -> dict:
    addr = addresses(text, vendor)
    return {"device": device, "vendor": vendor,
            "hostname": hostname_of(text, device), "role": role_of(device, vendor),
            "addresses": addr, "nets": sorted({a["net"] for a in addr}),
            "vlans": vlans(text, vendor), "ip_count": len(addr)}
