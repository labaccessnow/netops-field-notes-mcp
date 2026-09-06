"""Config sanitising, structured diff and deterministic drift explanation.

The rules DriftWatch runs nightly, as pure functions over two config texts. No model
call anywhere: two people running this on the same snapshots get the same answer.
"""
from __future__ import annotations
import difflib
import re

# ---------------------------------------------------------------- vendor detection
_VENDOR_HINTS = [
    (re.compile(r"<opnsense>|<pfsense>"), "opnsense"),
    (re.compile(r"^\s*set (interfaces|firewall|protocols|service|system) ", re.M), "edgeos"),
    (re.compile(r"^(firewall|interfaces|protocols|service|system)\s*\{", re.M), "edgeos"),
    (re.compile(r"^/(interface|ip|system|routing) ", re.M), "mikrotik"),
    (re.compile(r"^\s*(vlan database|network parms)", re.M), "edgeswitch"),
    (re.compile(r"^(interface|router bgp|ip route|line vty|hostname)\b", re.M), "cisco-ios"),
]


def detect_vendor(text: str) -> str:
    for pat, vendor in _VENDOR_HINTS:
        if pat.search(text or ""):
            return vendor
    return "unknown"


# ---------------------------------------------------------------- sanitise
# Lines that change on their own and mean nothing. Dropped before diffing so the
# output is real drift, not timestamps. Conservative: nothing here touches
# firewall, interface or routing config.
VOLATILE = [
    re.compile(r"vyatta-config-version"), re.compile(r"Release version"),
    re.compile(r"Last configuration change"), re.compile(r"^! Last config", re.I),
    re.compile(r"ntp clock-period"), re.compile(r"^#\s*\w+ \d+ \d{2}:\d{2}:\d{2}"),
    re.compile(r"uptime", re.I), re.compile(r"\b\d+ packets, \d+ bytes\b"),
    # OPNsense config.xml save bookkeeping. On a real fleet these produced two thirds
    # of one firewall's drift events, most rated high risk — alarming noise.
    re.compile(r"^\s*<time>\d{9,}(?:\.\d+)?</time>\s*$"),
    re.compile(r"^\s*<description>/api/[^<]*made changes</description>\s*$"),
]

# Volatile VALUES inside a line that is otherwise real config: mask the value in
# place so the rest of the line still diffs.
VOLATILE_SUBS = [
    (re.compile(r'(persisted_at=")[^"]*(")'), r"\1*\2"),
]


def sanitize(text: str, vendor: str = "") -> list[str]:
    out = []
    for ln in (text or "").splitlines():
        s = ln.rstrip()
        if any(p.search(s) for p in VOLATILE):
            continue
        for pat, repl in VOLATILE_SUBS:
            s = pat.sub(repl, s)
        out.append(s)
    return out


# ---------------------------------------------------------------- section path
def section_path(lines: list[str], idx: int) -> str:
    """Best-effort enclosing block for a changed line (brace formats like EdgeOS
    config.boot). Walks upward tracking brace depth."""
    depth = 0
    path = []
    for i in range(min(idx, len(lines) - 1), -1, -1):
        ln = lines[i]
        depth += ln.count("}") - ln.count("{")
        if ln.strip().endswith("{") and depth < 0:
            path.append(ln.strip()[:-1].strip())
            depth = 0
        if len(path) >= 3:
            break
    if path:
        return " > ".join(reversed(path))
    for i in range(min(idx, len(lines) - 1), -1, -1):
        s = lines[i].strip()
        if s.startswith("/") or s.startswith("interface ") or (s.startswith("!") and len(s) > 1):
            return s
    return "(top level)"


# ---------------------------------------------------------------- structured diff
def structured_diff(old_text: str, new_text: str, vendor: str = "") -> list[dict]:
    """Change hunks: {op, section, added[], removed[]}."""
    old = sanitize(old_text, vendor)
    new = sanitize(new_text, vendor)
    sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    hunks = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        removed, added = old[i1:i2], new[j1:j2]
        sect = section_path(new, j1) if added else section_path(old, i1)
        hunks.append({"op": tag, "section": sect,
                      "added": [l for l in added if l.strip()],
                      "removed": [l for l in removed if l.strip()]})
    return [h for h in hunks if h["added"] or h["removed"]]


# ---------------------------------------------------------------- explain
CATS = [
    ("security", "high", r"\b(firewall|rule|acl|access-list|deny|permit|nat|policy|zone)\b"),
    ("access/mgmt", "high", r"\b(snmp|aaa|tacacs|radius|user|password|secret|ssh|telnet|login|community)\b"),
    ("routing", "high", r"\b(route|bgp|ospf|protocols|next-hop|prefix|neighbor|redistribute)\b"),
    ("connectivity", "medium", r"\b(interface|address|vlan|bridge|ethernet|wireguard|peer|vif)\b"),
    ("services", "medium", r"\b(dns|dhcp|forwarding|service|listen)\b"),
    ("mgmt/time", "low", r"\b(ntp|clock|timezone|log|syslog|hostname|description|banner)\b"),
]

_WHY = {
    "security": "Firewall, ACL and NAT changes alter what traffic is allowed — confirm this was intended and did not quietly open or close access.",
    "access/mgmt": "Authentication and management changes decide who can reach the device — the blast radius is the device itself.",
    "routing": "Routing changes can black-hole or reroute traffic well beyond this device.",
    "connectivity": "Interface and addressing changes drop links or move subnets.",
    "services": "Service changes propagate to every client that depends on them.",
    "mgmt/time": "Operational change, low risk.",
    "cosmetic": "No functional impact.",
}


def _classify(lines: list[str]):
    blob = " ".join(lines).lower()
    for cat, risk, pat in CATS:
        if re.search(pat, blob):
            return cat, risk
    return "cosmetic", "low"


def explain(hunk: dict, device: str = "", vendor: str = "") -> dict:
    lines = hunk["added"] + hunk["removed"]
    cat, risk = _classify(lines)
    op = {"insert": "added", "delete": "removed", "replace": "changed"}.get(hunk["op"], hunk["op"])
    n = len(hunk["added"]) + len(hunk["removed"])
    return {"summary": f"{n} line{'s' if n != 1 else ''} {op} under '{hunk['section']}' ({cat}).",
            "why": _WHY.get(cat, "Review the change."), "risk": risk, "category": cat,
            "remediation": "Confirm with the change record; to revert, restore the prior block from the previous snapshot.",
            "confidence": 0.55, "source": "deterministic"}


# kept for callers that expect the old name
_deterministic = explain
