"""Plain-English change stories for OPNsense config.xml drift — deterministic.

WHY THIS EXISTS (2026-09-05). The product's pitch is "the change explained in
English, not a diff". For OPNsense the deterministic explainer in
`core/pipeline.py` produced, for every real firewall change, exactly this:

    "336 line(s) added under '(top level)' (security)."

That is a restated diff stat, and it is the weakest point in the product: the
deterministic path is the one that has to carry the demo, because the LLM path
is unconfigured. Worse than useless, it was actively misleading: 10 of the 15
opnsense drift events in the database were pure save-timestamp noise, 9 of them
rated HIGH RISK, because the line

    <Filter version="1.0.5" persisted_at="1788378200.10" description="Firewall rules (new)">

contains the word "firewall" and matches pipeline.CATS' security regex. Two
thirds of this device's output was noise, most of it alarming noise.

WHAT THIS MODULE DOES DIFFERENTLY, all measured against the 6 distinct opnsense
snapshots actually on disk (220 captures collapse to 6 distinct states, so 5
transitions and 554 rule instances):

  1. It parses the XML instead of the line diff. `pipeline.section_path()` walks
     brace depth and then looks for lines starting with '/' or 'interface ' —
     XML has neither, so every opnsense hunk was labelled '(top level)'. Here
     the section is real: OPNsense > Firewall > Filter > rules.
  2. It keys rules by their `uuid` attribute, so the single 336-line difflib
     hunk of 2026-08-12 resolves into the SIX independent rules it actually
     contains — one of which is a `block`, invisible in "336 line(s) added".
     The uuid is also what makes an in-place edit distinguishable from a
     delete-plus-re-add, and what licenses the cross-capture lifecycle sentence.
  3. It renders from a TYPED RECORD, not from diff text. 42 of the 54 fields in
     every <rule> are empty or pinned at their OPNsense default across all 554
     rule instances; only 12 ever carry signal. All 54 are still modelled:
     anything off-stock gets its own clause, and any tag this module does not
     know is printed verbatim rather than silently dropped. Describing a rule
     WRONGLY in a client-facing report is the worst outcome available, so
     unknown beats guessed everywhere — including negation (source_not,
     destination_not and interfacenot), port ranges and aliases, disabled rules
     and disabled aliases.
  4. It suppresses the three noise leaf-paths (any @persisted_at,
     /revision/time, /revision/description) as CHANGES while keeping their
     parsed values as METADATA — and it is deliberately weak about attribution.
     revision/description records only the LAST API call before the save: in
     this dataset it names /api/firewall/filter/delRule/cff10d4a… for a capture
     whose observed change was four rules ADDED, and that uuid appears in none
     of the six snapshots. So it is always worded "the most recent
     config-changing API call recorded before that save", never "this rule was
     added by", and when the recorded call disagrees with what was observed the
     report says so.
  5. It never invents risk. Ratings come from grounds derivable from the rule
     itself (an unrestricted source reaching a remote-administration port, an
     any/any/any permit, a removed broad isolation block), the grounds are
     printed next to the rating so a reader can disagree with them, and a change
     PROVEN to be an exact rollback is capped rather than alarmed about.

HONESTY PATHS (each exercised by the self-test at the bottom of this file):
  * a capture that will not parse as XML -> return None so the caller falls back
    to the raw line diff, with the reason appended to the optional `notes` list.
  * a hunk in the legacy <filter>/<nat> trees (a different schema, never
    observed to change here) -> None rather than describing it with the wrong
    grammar.
  * an alias / interface / port token not defined in the snapshot -> printed raw
    and marked unresolved, and confidence drops.
  * an alias whose contents do not fully resolve is treated as UNRESOLVED rather
    than partially resolved, because a partially-resolved address set on the
    inner side of a containment test can license a precedence note that is not
    warranted (see `Ctx.addr_networks`).
  * rule count moved with no uuid delta to explain it -> said out loud.
  * hostnames are never asserted: this config has zero DNS host overrides, zero
    Kea reservations and zero unbound hosts, so "dc1" exists only inside
    operator-written rule descriptions and is quoted as the operator's label,
    never stated as fact.
  * port names come from a curated table, never socket.getservbyport(), which
    reads the REPORT HOST's /etc/services (machine-dependent output) and returns
    misleading names such as 8088 -> "omniorb".

WIRING — this module is NOT self-installing, and pipeline.explain(hunk, device,
vendor) cannot supply the two config texts this analysis needs. There are two
supported ways to connect it; neither is a drop-in:

  (a) Explicit, preferred. In driftwatch.cmd_scan(), after structured_diff():

        from core import explain_opnsense
        ...
        hunks = structured_diff(a["raw"], b["raw"], dev["vendor"])
        if dev["vendor"] == "opnsense":
            explain_opnsense.bind(hunks, a["raw"], b["raw"],
                                  captured_at=b["captured_at"],
                                  history=[(s["captured_at"], s["raw"]) for s in snaps])
        ...
            ex = explain_opnsense.explain_hunk(h, dev["name"], dev["vendor"]) \
                 or explain(h, dev["name"], dev["vendor"])

      `bind()` is what unlocks the capture-time, lifecycle and rollback
      sentences — the best story in this dataset ("identical to the 2026-08-07
      16:14 capture") only exists if `history` is supplied.

  (b) Zero-edit. Call `explain_opnsense.install()` once at start-up. It wraps
      pipeline.structured_diff and pipeline.explain and rebinds those names
      wherever they were already imported. It is a monkeypatch, and without a
      later `bind()` call it has no capture timestamps, so the timing,
      lifecycle and rollback sentences are omitted rather than guessed.

API
    explain_opnsense(hunk, prev_text, curr_text, **kw) -> dict | None
        pipeline.explain()-shaped; None means "I cannot beat the template".
    split_events(hunk, prev_text, curr_text, **kw) -> [(sub_hunk, explain_dict)]
        the recommended shape: ONE event per rule instead of one per difflib hunk.
    analyze(prev_text, curr_text) -> the raw uuid-keyed delta, for other callers.
    bind / explain_hunk / install -> wiring, above.

RENDERING NOTE for report.py: a multi-rule `summary` contains newlines and reads
best under `white-space: pre-line`. It is written so that it still reads
correctly when that whitespace is collapsed — the per-rule paragraphs are
numbered "(1) (2) …" for exactly that reason. `headline` (one sentence) and
`story` (list of paragraphs) are provided for a renderer that wants to lay the
event out itself.

Stdlib only (xml.etree, ipaddress, hashlib, re, sys, time). No network, no API
key, no third-party imports.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import sys
import time
import xml.etree.ElementTree as ET

SOURCE = "deterministic-opnsense"
RULES_PATH = "./OPNsense/Firewall/Filter/rules/rule"
SECTION_RULES = "OPNsense > Firewall > Filter > rules"
SECTION_META = "OPNsense > save metadata (revision / persisted_at)"

# --------------------------------------------------------------------------
# noise + secrets
# --------------------------------------------------------------------------
# Suppressed as CHANGES; their parsed values are still reported as metadata.
# Matched on the attribute/tag name generically, not on the one path that
# happened to move: there are 51 persisted_at attributes in this config, one per
# plugin model, and every one is the same class of save stamp.
NOISE_KINDS = (
    ("persisted_at", re.compile(r'\spersisted_at="[^"]*"'),
     "a plugin save stamp (@persisted_at)"),
    ("revision_time", re.compile(r"^\s*<time>\s*\d+(\.\d+)?\s*</time>\s*$"),
     "the config-save timestamp (/revision/time)"),
    ("api_call", re.compile(r"^\s*<description>\s*/api/\S+\s+made changes\s*</description>\s*$"),
     "the record of the last API call (/revision/description)"),
)

# Redacted unconditionally — a credential must never reach a client-facing
# report. /revision/user_apitoken did not move in this window, but it WILL the
# day the token rotates, and then it lands in a document an MSP hands a client.
SECRET_TAG_RE = re.compile(
    r"(<(user_apitoken|apitoken|password|authtoken|pre-shared-key|privatekey|secret)>)"
    r"(.*?)(</\2>)", re.I | re.S)


def redact(line) -> str:
    """Replace credential element bodies with a marker. Idempotent.

    Coerces a non-string to str rather than raising: this runs on caller-supplied
    hunk lines on the way into a client-facing report, and a redaction step that
    can throw is a redaction step that can be skipped.
    """
    if not isinstance(line, str):
        line = str(line)
    return SECRET_TAG_RE.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(4), line)


def noise_kind(line: str):
    """Name of the noise class this line belongs to, or None if it is signal."""
    if not line.strip():
        return "blank"
    for name, pattern, _label in NOISE_KINDS:
        if pattern.search(line):
            return name
    return None


def is_noise_line(line: str) -> bool:
    return noise_kind(line) is not None


# --------------------------------------------------------------------------
# rule field model — all 54 tags OPNsense writes, with their stock value
# --------------------------------------------------------------------------
# "" means the field is normally empty; None means it has no stock value and is
# always rendered in the main sentence. Anything off this table gets its own
# clause; anything NOT in this table is printed verbatim as an unmodelled
# setting. Measured across 554 rule instances, only enabled, sequence, action,
# interface, direction, protocol, source_net, destination_net, destination_port,
# log, description and quick ever vary — but all 54 are modelled anyway, because
# the day one of the other 42 moves is exactly the day silence would be a lie.
FIELD_DEFAULTS = {
    # rendered in the main sentence
    "enabled": "1", "sequence": None, "action": None, "quick": "1",
    "interface": None, "interfacenot": "0", "direction": None,
    "ipprotocol": "inet", "protocol": None,
    "source_net": None, "source_not": "0", "source_port": "",
    "destination_net": None, "destination_not": "0", "destination_port": "",
    "log": "0", "description": "", "icmptype": "", "icmp6type": "",
    # rendered only when they deviate from stock
    "statetype": "keep", "state-policy": "",
    "divert-to": "", "gateway": "", "replyto": "", "disablereplyto": "0",
    "allowopts": "0", "nosync": "0", "nopfsync": "0", "statetimeout": "",
    "udp-first": "", "udp-multiple": "", "udp-single": "",
    "max-src-nodes": "", "max-src-states": "", "max-src-conn": "", "max": "",
    "max-src-conn-rate": "", "max-src-conn-rates": "", "overload": "",
    "adaptivestart": "", "adaptiveend": "", "prio": "", "set-prio": "",
    "set-prio-low": "", "tag": "", "tagged": "", "tcpflags1": "", "tcpflags2": "",
    "tcpflags_any": "0", "categories": "", "sched": "", "tos": "",
    "shaper1": "", "shaper2": "",
}

# Fields consumed by the main sentence. Everything else in FIELD_DEFAULTS is
# rendered by extra_clauses() when it is off-stock, so a field must appear in
# exactly one of the two places or it goes unreported — which is how
# `interfacenot` was silently dropped before.
CORE_FIELDS = {
    "enabled", "sequence", "action", "quick", "interface", "interfacenot",
    "direction", "ipprotocol", "protocol", "source_net", "source_not",
    "source_port", "destination_net", "destination_not", "destination_port",
    "log", "description", "icmptype", "icmp6type",
}

# Phrasing for the non-core fields when they are NOT at their stock value.
EXTRA_PHRASE = {
    "statetype": "state handling is '%s' (stock is 'keep')",
    "state-policy": "state policy '%s'",
    "gateway": "policy-routed via gateway '%s'",
    "divert-to": "diverted to '%s'",
    "replyto": "reply-to '%s'",
    "disablereplyto": "reply-to disabled",
    "allowopts": "IP options are allowed",
    "nosync": "not synchronised to the HA peer",
    "nopfsync": "excluded from pfsync state sync",
    "statetimeout": "state timeout %ss",
    "sched": "active only during schedule '%s'",
    "tag": "tags matching packets '%s'",
    "tagged": "matches only packets already tagged '%s'",
    "tcpflags1": "TCP flags set: %s",
    "tcpflags2": "TCP flags checked: %s",
    "tcpflags_any": "matches any TCP flag combination",
    "categories": "category '%s'",
    "prio": "matches priority %s",
    "set-prio": "sets priority %s",
    "set-prio-low": "sets low priority %s",
    "tos": "ToS/DSCP %s",
    "shaper1": "traffic shaper '%s'",
    "shaper2": "traffic shaper '%s'",
    "max": "max %s states",
    "max-src-nodes": "max %s source hosts",
    "max-src-states": "max %s states per source",
    "max-src-conn": "max %s connections per source",
    "max-src-conn-rate": "connection rate limit %s",
    "max-src-conn-rates": "connection rate window %ss",
    "overload": "overload table '%s'",
    "adaptivestart": "adaptive state scaling starts at %s",
    "adaptiveend": "adaptive state scaling ends at %s",
    "udp-first": "UDP first-packet timeout %ss",
    "udp-single": "UDP single-packet timeout %ss",
    "udp-multiple": "UDP multi-packet timeout %ss",
}

# --------------------------------------------------------------------------
# ports
# --------------------------------------------------------------------------
# Deliberately CURATED and short. Everything not in this table is printed as a
# bare port number — among the distinct destination_port values in this config
# that means 10250, 2379, 2380, 6443, 8472, 1514, 1515, 1700, 3081, 8000, 8088,
# 51821 and 32400 stay unnamed. 32400 is Plex only in the operator's own
# description text, and that text is quoted as a label, not turned into a claim.
PORT_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP server", 68: "DHCP client", 69: "TFTP", 80: "HTTP", 110: "POP3",
    119: "NNTP", 123: "NTP", 135: "MS RPC", 137: "NetBIOS name",
    138: "NetBIOS datagram", 139: "NetBIOS session", 143: "IMAP", 161: "SNMP",
    162: "SNMP trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE/IPsec", 514: "syslog", 515: "LPD print",
    546: "DHCPv6 client", 547: "DHCPv6 server", 587: "SMTP submission",
    623: "IPMI/BMC", 636: "LDAPS", 989: "FTPS data", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1701: "L2TP", 1723: "PPTP",
    1812: "RADIUS auth", 1813: "RADIUS accounting", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}

# Ports whose exposure to an unrestricted source is defensible grounds for
# calling a change high-risk: remote administration of a device or a host.
MGMT_PORTS = {22: "SSH", 23: "Telnet", 161: "SNMP", 623: "IPMI/BMC",
              3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}

# Tokens OPNsense uses for "no address restriction". '::/0' is in this set: an
# IPv6 any/any permit is the same finding as an IPv4 one, and leaving it out
# meant such a rule rendered as the literal '::/0' and never escalated past
# medium.
ANY_TOKENS = {"any", "", "*", "0.0.0.0/0", "::/0"}
ANY_LABEL = {"0.0.0.0/0": "anywhere (0.0.0.0/0 — every IPv4 address)",
             "::/0": "anywhere (::/0 — every IPv6 address)"}
PORTED_PROTOS = {"tcp", "udp", "tcp/udp", "sctp"}

PROTO_PHRASE = {"any": "any protocol", "tcp": "TCP", "udp": "UDP",
                "tcp/udp": "TCP/UDP", "icmp": "ICMP", "esp": "ESP", "gre": "GRE",
                "igmp": "IGMP", "ah": "AH", "carp": "CARP", "pfsync": "pfsync",
                "ospf": "OSPF", "sctp": "SCTP"}
DIRECTION_PHRASE = {"in": "inbound", "out": "outbound", "any": "in either direction"}
IPPROTO_PHRASE = {"inet": "", "inet6": "IPv6 only", "inet46": "IPv4 and IPv6"}
ACTION_PHRASE = {"pass": "allow", "block": "block (silently drop)",
                 "reject": "reject (drop and answer with an error)"}

# Broad-destination thresholds, per address family, used only to justify calling
# a REMOVED block rule an isolation rule.
BROAD_PREFIX = {4: 12, 6: 32}


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
# ElementTree does not resolve external entities and raises on undefined ones,
# so it is not vulnerable to the classic XXE file read. A document with an
# internal DTD is still refused: this parser exists to read captures written by
# OPNsense, which never emits one, and refusing costs nothing but a fallback to
# the line diff.
DOCTYPE_RE = re.compile(r"<!(DOCTYPE|ENTITY)\b", re.I)


def parse_config(text: str):
    """(root, error). root is None when the capture cannot be trusted as XML."""
    if not isinstance(text, str) or not text.strip():
        return None, "capture is empty"
    if DOCTYPE_RE.search(text[:8192]):
        return None, ("capture carries a DTD or entity declaration, which OPNsense never "
                      "writes — refusing to parse it")
    try:
        return ET.fromstring(text), None
    except Exception as exc:                                    # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _digest(text) -> str:
    """Stable content identity. hashlib, not hash(): str hashing is salted per
    process, so hash() cannot be compared across runs or stored."""
    if not isinstance(text, str):
        text = str(text)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class Rule:
    """One <rule> of the Firewall.Filter plugin model, as a typed record."""

    __slots__ = ("uuid", "index", "f", "unknown")

    def __init__(self, el, index):
        self.uuid = el.get("uuid") or ""
        self.index = index
        self.f = {}
        self.unknown = {}
        for child in el:
            val = (child.text or "").strip()
            self.f[child.tag] = val
            if child.tag not in FIELD_DEFAULTS and val:
                self.unknown[child.tag] = val

    def get(self, tag, default=""):
        return self.f.get(tag, default)

    @property
    def enabled(self):
        return self.get("enabled", "1") != "0"

    @property
    def action(self):
        return (self.get("action") or "").lower()

    @property
    def ifaces(self):
        return [i for i in re.split(r"[\s,]+", self.get("interface") or "") if i]

    @property
    def iface_negated(self):
        return self.get("interfacenot") == "1"

    @property
    def short(self):
        """First uuid segment — enough to identify a rule in prose. The full
        uuid is still printed once, in the remediation, where it is acted on."""
        return (self.uuid.split("-", 1)[0] or self.uuid)[:8] or "?"

    def signature(self):
        """The fields that decide what this rule matches and does."""
        keys = ("enabled", "action", "interface", "interfacenot", "direction",
                "ipprotocol", "protocol", "source_net", "source_not", "source_port",
                "destination_net", "destination_not", "destination_port", "quick",
                "log", "sequence", "description")
        return tuple((k, self.get(k)) for k in keys)


def rule_map(root):
    """{uuid: Rule} for the plugin ruleset, in document order."""
    out = {}
    if root is None:
        return out
    for i, el in enumerate(root.findall(RULES_PATH)):
        r = Rule(el, i)
        if r.uuid:
            out[r.uuid] = r
    return out


class Ctx:
    """Everything the renderer is allowed to resolve, all of it from the SAME
    snapshot. Nothing here is looked up externally, inferred or guessed."""

    def __init__(self, root):
        self.root = root
        self.ifaces = {}
        self.vlan_tag = {}
        self.aliases = {}
        if root is None:
            return
        ifnode = root.find("interfaces")
        if ifnode is not None:
            for el in ifnode:
                self.ifaces[el.tag] = {
                    "descr": (el.findtext("descr") or "").strip(),
                    "if": (el.findtext("if") or "").strip(),
                    "ipaddr": (el.findtext("ipaddr") or "").strip(),
                    "subnet": (el.findtext("subnet") or "").strip(),
                    "enable": (el.findtext("enable") or "").strip(),
                }
        for v in root.findall("./vlans/vlan"):
            vlanif = (v.findtext("vlanif") or "").strip()
            if vlanif:
                self.vlan_tag[vlanif] = (v.findtext("tag") or "").strip()
        for a in root.findall("./OPNsense/Firewall/Alias/aliases/alias"):
            name = (a.findtext("name") or "").strip()
            if not name:
                continue
            self.aliases[name] = {
                "type": (a.findtext("type") or "").strip(),
                "content": [c.strip() for c in (a.findtext("content") or "").splitlines()
                            if c.strip()],
                "description": (a.findtext("description") or "").strip(),
                "enabled": (a.findtext("enabled") or "1").strip(),
            }

    # -- interfaces -------------------------------------------------------
    def iface_label(self, key):
        """'opt3' -> 'opt3 (VLAN100_GUEST, VLAN 100)'. Unknown keys come back
        raw and flagged, never guessed."""
        info = self.ifaces.get(key)
        if info is None:
            return "no interface set" if not key else \
                f"{key} (unresolved: no such interface in this snapshot)"
        descr = info["descr"] or {"lan": "LAN", "wan": "WAN"}.get(key, "")
        tag = self.vlan_tag.get(info["if"], "")
        bits = [b for b in (descr if descr and descr != key else "",
                            f"VLAN {tag}" if tag else "") if b]
        label = f"{key} ({', '.join(bits)})" if bits else key
        if info["enable"] == "0":
            label += " [interface is DISABLED]"
        return label

    def iface_scope(self, rule):
        """Where the rule applies, HONOURING interfacenot.

        `interfacenot=1` inverts the interface list: the rule then applies to
        every interface EXCEPT the ones named. Rendering that as "on opt8" —
        which is what this module used to do, because interfacenot sits in
        CORE_FIELDS and so was skipped by extra_clauses() and printed by nothing
        else — states the exact opposite of the rule's scope in a document an
        MSP hands a client. It is now rendered on every path that names an
        interface.
        """
        names = rule.ifaces
        if not names:
            return "no interface set (a floating rule: it is not bound to one interface)"
        label = " and ".join(self.iface_label(i) for i in names)
        if rule.iface_negated:
            return (f"every interface EXCEPT {label} (the rule's interface match is "
                    f"NEGATED, interfacenot=1)")
        return label

    def iface_networks(self, key):
        info = self.ifaces.get(key)
        if not info or not info["ipaddr"] or not info["subnet"]:
            return None
        try:
            return [ipaddress.ip_network(f"{info['ipaddr']}/{info['subnet']}", strict=False)]
        except ValueError:
            return None

    # -- address tokens ---------------------------------------------------
    def addr_phrase(self, token, negated=False):
        """One source_net/destination_net token as English. Alias CONTENTS are
        not inlined here — they get their own definition sentence, which keeps
        the traffic sentence readable."""
        tok = (token or "").strip()
        neg = "anything except " if negated else ""
        if tok in ANY_TOKENS:
            if negated:
                return ("nothing (the address is 'any' with NOT set, which matches no "
                        "traffic)")
            return ANY_LABEL.get(tok, "anywhere")
        if tok == "(self)":
            # OPNsense magic token, NOT an alias. Rendering it as one would be a
            # lie a reader could act on.
            return neg + ("this firewall itself (OPNsense '(self)': every address "
                          "configured on the firewall)")
        if tok in self.aliases:
            a = self.aliases[tok]
            return neg + f"alias {tok}" + (" [alias is DISABLED]" if a["enabled"] == "0" else "")
        if tok.endswith("ip") and tok[:-2] in self.ifaces:
            return neg + f"the {self.iface_label(tok[:-2])} interface address"
        if tok in self.ifaces:
            return neg + f"the {self.iface_label(tok)} network"
        net = _as_network(tok)
        if net is not None:
            return neg + (str(net.network_address)
                          if net.prefixlen == net.max_prefixlen else tok)
        return neg + (f"'{tok}' (unresolved: not an alias, interface or IP range in "
                      f"this snapshot)")

    def addr_networks(self, token):
        """[ip_network] the token covers, or None when it does not fully resolve.

        Resolution is ALL-OR-NOTHING on purpose. `_contains()` is used in both
        directions: shrinking the OUTER (block-rule) set only makes a positive
        result less likely and so stays conservative, but shrinking the INNER
        (new-rule) set makes a positive result MORE likely — a half-resolved
        alias on the inner side could license a precedence note that is not
        warranted. So an alias with even one unparseable member resolves to
        None, and the caller stays silent instead.
        """
        tok = (token or "").strip()
        if tok in ANY_TOKENS:
            return [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
        if tok == "(self)":
            return None            # every address on the firewall; not enumerable here
        if tok in self.aliases:
            a = self.aliases[tok]
            if a["type"] not in ("network", "host") or a["enabled"] == "0":
                return None
            nets = []
            for member in a["content"]:
                n = _as_network(member)
                if n is None:
                    return None    # nested alias / hostname / range: do not half-resolve
                nets.append(n)
            return nets or None
        if tok in self.ifaces:
            return self.iface_networks(tok)
        n = _as_network(tok)
        return [n] if n is not None else None

    # -- ports ------------------------------------------------------------
    def port_phrase(self, token):
        tok = (token or "").strip()
        if not tok:
            return ""
        out = []
        for p in re.split(r"[\s,]+", tok):
            if not p:
                continue
            if p in self.aliases:
                a = self.aliases[p]
                out.append(f"port alias {p}" +
                           (" [alias is DISABLED]" if a["enabled"] == "0" else ""))
            elif re.fullmatch(r"\d+", p):
                n = int(p)
                out.append(f"port {n} ({PORT_NAMES[n]})" if n in PORT_NAMES else f"port {n}")
            elif re.fullmatch(r"\d+[-:]\d+", p):
                lo, hi = re.split(r"[-:]", p)
                out.append(f"ports {lo}-{hi}")
            else:
                out.append(f"port '{p}' (unresolved: not a number, range or port alias "
                           f"in this snapshot)")
        return " / ".join(out)

    def port_numbers(self, token):
        """Set of ports a token covers, or None when unresolvable/unrestricted."""
        tok = (token or "").strip()
        if not tok:
            return None                                   # empty = every port
        out = set()
        items = re.split(r"[\s,]+", tok)
        if tok in self.aliases:
            a = self.aliases[tok]
            if a["type"] != "port" or a["enabled"] == "0":
                return None
            items = a["content"]
        for p in items:
            if re.fullmatch(r"\d+", p):
                out.add(int(p))
            elif re.fullmatch(r"\d+[-:]\d+", p):
                lo, hi = (int(x) for x in re.split(r"[-:]", p))
                if hi < lo or hi - lo > 4096:
                    return None
                out.update(range(lo, hi + 1))
            else:
                return None
        return out or None

    def alias_definitions(self, rule):
        """'net_rfc1918 = 10.0.0.0/8, … (network alias, operator description: …)'
        for every alias the rule references. Hoisted out of the traffic sentence
        so that sentence stays a sentence."""
        out = []
        for tok in (rule.get("source_net"), rule.get("destination_net"),
                    rule.get("source_port"), rule.get("destination_port")):
            for name in re.split(r"[\s,]+", (tok or "").strip()):
                if name in self.aliases and not any(o.startswith(name + " =") for o in out):
                    a = self.aliases[name]
                    members = ", ".join(a["content"][:8])
                    if len(a["content"]) > 8:
                        members += f", +{len(a['content']) - 8} more"
                    txt = f"{name} = {members or '(empty)'}"
                    detail = [f"{a['type'] or 'unknown'} alias"]
                    if a["enabled"] == "0":
                        detail.append("DISABLED")
                    if a["description"]:
                        detail.append(f'operator description: "{a["description"]}"')
                    out.append(txt + f" ({'; '.join(detail)})")
        return out


def _as_network(tok):
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# rule -> English
# --------------------------------------------------------------------------
def _action_verb(rule: Rule) -> str:
    """Grammatical in all three cases, including the one where <action> is
    missing — which used to render as 'action 'unset' unspecified protocol'."""
    act = rule.action
    if act in ACTION_PHRASE:
        return ACTION_PHRASE[act]
    if act:
        return f"apply the unrecognised action '{rule.get('action')}' to"
    return "apply an action this report cannot read (the rule has no <action> value) to"


def _proto_phrase(rule: Rule) -> str:
    raw = (rule.get("protocol") or "").lower()
    if not raw:
        return "traffic of any protocol (the rule sets no protocol)"
    return PROTO_PHRASE.get(raw, f"protocol '{rule.get('protocol')}'")


def describe_rule(rule: Rule, ctx: Ctx) -> str:
    """One sentence for what the rule matches and does. Facts only, no judgement."""
    verb = _action_verb(rule)
    proto_raw = (rule.get("protocol") or "").lower()
    proto = _proto_phrase(rule)

    src = ctx.addr_phrase(rule.get("source_net"), rule.get("source_not") == "1")
    dst = ctx.addr_phrase(rule.get("destination_net"), rule.get("destination_not") == "1")
    sport = ctx.port_phrase(rule.get("source_port"))
    dport = ctx.port_phrase(rule.get("destination_port"))
    if not dport and proto_raw in PORTED_PROTOS:
        dport = "any port"

    clause = f"{verb} {proto} from {src}"
    if sport:
        clause += f" (source {sport})"
    clause += f" to {dst}"
    if dport:
        clause += f" on {dport}"

    tail = []
    d = DIRECTION_PHRASE.get((rule.get("direction") or "").lower())
    if d:
        tail.append(d)
    elif rule.get("direction"):
        tail.append(f"direction '{rule.get('direction')}'")
    ipp = IPPROTO_PHRASE.get((rule.get("ipprotocol") or "inet").lower())
    if ipp:
        tail.append(ipp)
    elif rule.get("ipprotocol") not in ("", "inet"):
        tail.append(f"address family {rule.get('ipprotocol')}")
    # quick=1 on all 554 rule instances measured, but it is stated: it is what
    # makes rule order decisive, and the precedence note depends on it.
    tail.append("first match wins" if rule.get("quick", "1") == "1"
                else "evaluation continues past this rule")
    tail.append("logging ON" if rule.get("log") == "1" else "logging OFF")
    icmp = rule.get("icmptype") or rule.get("icmp6type")
    if icmp:
        tail.append(f"ICMP type {icmp}")

    prefix = "" if rule.enabled else \
        "DISABLED — it matches no traffic until someone re-enables it: "
    return f"{prefix}{clause}, {', '.join(tail)}."


def extra_clauses(rule: Rule) -> list:
    """A clause for every field that is NOT at its OPNsense default, plus any tag
    this module does not model. Nothing is silently dropped."""
    out = []
    for tag, value in rule.f.items():
        if tag in CORE_FIELDS or tag not in FIELD_DEFAULTS:
            continue
        if value == (FIELD_DEFAULTS[tag] or ""):
            continue
        phrase = EXTRA_PHRASE.get(tag)
        out.append((phrase % value if "%s" in phrase else phrase) if phrase
                   else f"{tag}={value}")
    for tag, value in rule.unknown.items():
        out.append(f"{tag}={value} (setting not modelled by this report — shown verbatim)")
    return out


# --------------------------------------------------------------------------
# precedence observation
# --------------------------------------------------------------------------
def _contains(outer_nets, inner_nets):
    """True only when EVERY inner network sits inside some outer network.

    Both arguments must be FULLY resolved (see Ctx.addr_networks): a partial
    inner set would make this return True for traffic the outer rule does not
    actually cover.
    """
    if not outer_nets or not inner_nets:
        return False
    for i in inner_nets:
        if not any(i.subnet_of(o) for o in outer_nets if o.version == i.version):
            return False
    return True


def _proto_covers(outer, inner):
    o, i = (outer or "any").lower(), (inner or "any").lower()
    return o == "any" or o == i or (o == "tcp/udp" and i in ("tcp", "udp"))


def precedence_note(rule: Rule, ctx: Ctx, all_rules, new_uuids=()) -> str:
    """When an ADDED pass rule shares a scope with an enabled block rule whose
    match set provably covers it, say so — with both sequences, and WITHOUT
    claiming which one wins.

    This is the single most report-worthy relationship in the dataset: a pass
    rule added at a low sequence on a DMZ interface, alongside an existing
    "block DMZ -> internal (isolation)" rule at a high sequence whose destination
    alias (an RFC 1918 aggregate such as 10.0.0.0/8) provably contains the pass
    rule's target. It is stated as a relationship, never as a verdict: XML order
    is not evaluation order, and several rules on one interface can share a
    sequence number, so sequence is not even a total order over that interface.
    """
    if rule.action != "pass" or not rule.enabled:
        return ""
    if rule.get("source_not") == "1" or rule.get("destination_not") == "1":
        return ""                                # negation: do not reason about it
    src = ctx.addr_networks(rule.get("source_net"))
    dst = ctx.addr_networks(rule.get("destination_net"))
    if not src or not dst:
        return ""
    my_ifaces, my_ports = set(rule.ifaces), ctx.port_numbers(rule.get("destination_port"))
    hits = []
    for other in all_rules:
        if other.uuid == rule.uuid or other.action not in ("block", "reject"):
            continue
        if not other.enabled or set(other.ifaces) != my_ifaces:
            continue
        # Same interface list AND the same sense of it: two rules that name
        # opt8 apply to opposite sets if one of them negates.
        if other.iface_negated != rule.iface_negated:
            continue
        if other.get("direction") != rule.get("direction"):
            continue
        if other.get("source_not") == "1" or other.get("destination_not") == "1":
            continue
        if not _proto_covers(other.get("protocol"), rule.get("protocol")):
            continue
        oports = ctx.port_numbers(other.get("destination_port"))
        if oports is not None and (my_ports is None or not my_ports.issubset(oports)):
            continue
        if not _contains(ctx.addr_networks(other.get("source_net")), src):
            continue
        if not _contains(ctx.addr_networks(other.get("destination_net")), dst):
            continue
        hits.append(other)
    if not hits:
        return ""
    b = hits[0]
    label = f'"{b.get("description")}"' if b.get("description") else f"rule {b.short}"
    extra = (f" (and {len(hits) - 1} further block rule(s) in the same scope)"
             if len(hits) > 1 else "")
    scope = "this interface" if not rule.iface_negated else "the same interface scope"
    # A block rule that arrived in the SAME change is not a pre-existing
    # restriction, and calling it one would misdate the relationship.
    if b.uuid in set(new_uuids):
        opener = (f"Note: this same change also added a BLOCK rule whose match set covers "
                  f"the same traffic")
        closing = ("The two were added together, so this pair was most likely designed as a "
                   "deny-with-exception. ")
    else:
        opener = (f"Note: {scope} already carried an enabled BLOCK rule whose match set covers "
                  f"the same traffic")
        closing = "The new rule is therefore an exception to an existing restriction. "
    return (f"{opener} — {label}, sequence {b.get('sequence') or '?'} against this rule's "
            f"sequence {rule.get('sequence') or '?'}{extra}. {closing}Which of the two applies "
            f"depends on the order OPNsense generates the ruleset in, which this report does "
            f"not attempt to determine — confirm the intended precedence in "
            f"Firewall > Rules.")


# --------------------------------------------------------------------------
# risk — grounds only, never vibes
# --------------------------------------------------------------------------
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _exposure(rule: Rule, ctx: Ctx) -> tuple:
    """(risk, ground) for a PASS rule's own match set, or (None, ground|None).

    Only three shapes are treated as defensible grounds for 'high', and each one
    is printed next to the rating: an unrestricted source reaching a remote-
    administration port, an unrestricted source reaching the firewall itself,
    and a rule where source, destination and protocol are all 'any'. '::/0'
    counts as unrestricted exactly as '0.0.0.0/0' does.
    """
    src_any = (rule.get("source_net") or "").strip() in ANY_TOKENS and \
        rule.get("source_not") != "1"
    dst_any = (rule.get("destination_net") or "").strip() in ANY_TOKENS and \
        rule.get("destination_not") != "1"
    dst_self = (rule.get("destination_net") or "").strip() == "(self)"
    ports = ctx.port_numbers(rule.get("destination_port"))
    proto_any = (rule.get("protocol") or "any").lower() == "any"
    mgmt = sorted({MGMT_PORTS[p] for p in (ports or set()) if p in MGMT_PORTS})

    if src_any and mgmt:
        return "high", (f"it permits ANY source to reach {', '.join(mgmt)}, a "
                        f"remote-administration service")
    if src_any and dst_self:
        return "high", "it permits ANY source to reach the firewall itself"
    if src_any and dst_any and proto_any:
        return "high", ("source, destination and protocol are all 'any' — it permits "
                        "everything arriving in the rule's scope")
    if src_any:
        return None, "the source is unrestricted ('any')"
    if ports is None and proto_any:
        return None, ("no protocol or port restriction, so it permits all traffic between "
                      "the named endpoints")
    return None, None


def _scope_ground(rule: Rule) -> str:
    """A negated interface match widens a rule from one interface to all the
    others. Reported as a ground rather than an automatic escalation."""
    if rule.iface_negated and rule.ifaces:
        return ("its interface match is negated, so it applies to every interface EXCEPT "
                "the one(s) named — a far wider scope than a single-interface rule")
    if not rule.ifaces:
        return "it is a floating rule, so it is not limited to one interface"
    return ""


def assess(op: str, rule: Rule, ctx: Ctx) -> tuple:
    """(risk, [grounds]). op is 'added' | 'removed' | 'modified'. Every rating
    carries the ground it stands on, so a reader can disagree with it."""
    if not rule.enabled:
        return "low", ["the rule is disabled, so it changes no traffic until "
                       "someone enables it"]

    dst_any = (rule.get("destination_net") or "").strip() in ANY_TOKENS and \
        rule.get("destination_not") != "1"
    grounds = []
    scope = _scope_ground(rule)

    if op == "added" and rule.action == "pass":
        risk = "medium"
        grounds.append("this is a new permit rule, so it widens what the firewall allows")
        esc, ground = _exposure(rule, ctx)
        if ground:
            grounds.append(ground)
        if scope:
            grounds.append(scope)
        return (esc or risk), grounds

    if op == "modified":
        # Rate the rule's NEW state: after the edit it is what the firewall does.
        risk = "medium"
        grounds.append("an existing rule's match or action changed")
        if rule.action == "pass":
            esc, ground = _exposure(rule, ctx)
            if ground:
                grounds.append("after the edit, " + ground)
            if scope:
                grounds.append("after the edit, " + scope)
            return (esc or risk), grounds
        if scope:
            grounds.append("after the edit, " + scope)
        return risk, grounds

    if op == "added" and rule.action in ("block", "reject"):
        grounds.append("this is a new block rule: it restricts rather than widens, but it "
                       "can break traffic that used to pass")
        if rule.get("log") != "1":
            grounds.append("logging is off, so denied traffic will not appear in the "
                           "firewall log, which makes any resulting outage harder to trace")
        return "low", grounds

    if op == "removed" and rule.action in ("block", "reject"):
        risk = "medium"
        grounds.append("a block rule was removed, so traffic it used to deny is now decided "
                       "by whatever rules remain")
        broad = ctx.addr_networks(rule.get("destination_net"))
        if dst_any or (broad and any(n.prefixlen <= BROAD_PREFIX[n.version] for n in broad)):
            risk = "high"
            grounds.append("the removed rule denied a broad destination range (an isolation "
                           "rule), so removing it reopens a wide path")
        return risk, grounds

    if op == "removed" and rule.action == "pass":
        return "medium", ["a permit rule was removed, so traffic that was explicitly allowed "
                          "now falls through to the remaining rules — expect service impact "
                          "if anything depended on it"]

    return "low", ["change recorded"]


# --------------------------------------------------------------------------
# confidence — earned, not pinned
# --------------------------------------------------------------------------
def _confidence(texts, caveats=(), unknown_fields=0) -> float:
    """0.95 for a clean render; lower whenever the text itself admits doubt.

    A confidence pinned at 0.9 on a render full of '(unresolved: …)' markers is
    a small lie in a document that is otherwise careful, so the number tracks
    the same doubts the prose already states.
    """
    score = 0.95
    blob = " ".join(t for t in texts if t)
    if "unresolved:" in blob:
        score -= 0.15
    if "not modelled by this report" in blob or unknown_fields:
        score -= 0.05
    if "cannot read" in blob or "unrecognised action" in blob:
        score -= 0.10
    if caveats:
        score -= 0.15
    return round(max(0.5, score), 2)


# --------------------------------------------------------------------------
# capture / save metadata
# --------------------------------------------------------------------------
def _fmt_epoch(value):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(value)))
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _fmt_capture(ts):
    """'20260812-071002' / '20260812071002' -> '2026-08-12 07:10 UTC'. The
    device's <system><timezone> is Etc/UTC and captures are stamped UTC."""
    if not ts:
        return None
    m = re.search(r"(\d{4})(\d{2})(\d{2})[-_ ]?(\d{2})(\d{2})", str(ts))
    if not m:
        return str(ts)
    y, mo, d, h, mi = m.groups()
    return f"{y}-{mo}-{d} {h}:{mi} UTC"


def save_metadata(root) -> dict:
    """The only trustworthy 'when', and a weakly-worded 'by what'."""
    out = {"saved_at": None, "api_call": None, "user": None}
    rev = root.find("revision") if root is not None else None
    if rev is None:
        return out
    out["saved_at"] = _fmt_epoch(rev.findtext("time"))
    desc = (rev.findtext("description") or "").strip()
    m = re.match(r"(/api/\S+)\s+made changes", desc)
    out["api_call"] = m.group(1) if m else (desc or None)
    out["user"] = (rev.findtext("username") or "").strip() or None
    return out


def metadata_sentences(meta, captured_at, observed_ops) -> list:
    """Save time + attribution, worded so it cannot be read as more than it is.

    revision/time is NOT the capture time — measured lag across the 5 real
    transitions was 15m, 27m, 32m, 1h05m and 4h56m — so both are printed.
    revision/description is only the LAST API call before the save: in this
    dataset it names a delRule for a uuid present in NONE of the six snapshots
    while the observed change was four rules ADDED. So when the recorded call
    disagrees with what was observed, the report says so.
    """
    out = []
    cap = _fmt_capture(captured_at)
    if meta.get("saved_at") and cap:
        out.append(f"OPNsense recorded the config save at {meta['saved_at']}; first seen in "
                   f"the {cap} capture.")
    elif meta.get("saved_at"):
        out.append(f"OPNsense recorded the config save at {meta['saved_at']}.")
    elif cap:
        out.append(f"Seen in the {cap} capture (the device recorded no save timestamp).")
    if meta.get("api_call"):
        who = f" by {meta['user']}" if meta.get("user") else ""
        line = (f"The most recent config-changing API call OPNsense recorded before that "
                f"save{who} was {meta['api_call']}.")
        call = meta["api_call"]
        mismatch = (("addRule" in call and observed_ops == {"removed"}) or
                    ("delRule" in call and observed_ops == {"added"}))
        if mismatch:
            line += (" That call does not match the change seen here, so it is attribution "
                     "metadata only — OPNsense stores just the last call before a save, not "
                     "the set of changes since the previous capture.")
        out.append(line)
    return out


# --------------------------------------------------------------------------
# history (optional) — lifecycle + revert detection
# --------------------------------------------------------------------------
def normalize_for_compare(text: str) -> str:
    """Drop the save-stamp lines so two captures can be compared for real
    equality. Proven useful: normalized, the 2026-08-12 13:54 capture is
    byte-identical to the 2026-08-07 16:14 one — which is what licenses calling
    that change a complete rollback instead of guessing it."""
    return "\n".join(l for l in text.splitlines() if not is_noise_line(l))


def _history_pairs(history):
    """Accept [(captured_at, raw)], [{'captured_at':…,'raw':…}] or sqlite3.Row."""
    out = []
    for h in history or []:
        if isinstance(h, (tuple, list)) and len(h) >= 2:
            out.append((str(h[0]), h[1]))
        else:
            try:
                out.append((str(h["captured_at"]), h["raw"]))
            except Exception:                                   # noqa: BLE001
                continue
    return [(ts, raw) for ts, raw in out if isinstance(raw, str)]


_HIST_CACHE = {}
_ANALYZE_CACHE = {}
_CACHE_MAX = 8


def _cache_put(cache, key, value):
    if len(cache) >= _CACHE_MAX:
        cache.clear()                     # tiny bounded cache; no LRU bookkeeping
    cache[key] = value
    return value


def _history_index(history):
    """[(ts, sha256, normalized_text, {uuid…})] — parsed once, then cached.

    Without the cache the lifecycle sentence would re-parse a 260 KB XML file
    once per rule per hunk (36 parses for one 6-rule change)."""
    pairs = _history_pairs(history)
    if not pairs:
        return []
    key = tuple((ts, _digest(raw)) for ts, raw in pairs)
    hit = _HIST_CACHE.get(key)
    if hit is not None:
        return hit
    index = []
    for (ts, raw), (_ts, dig) in zip(pairs, key):
        root, err = parse_config(raw)
        index.append((ts, dig, normalize_for_compare(raw),
                      set() if err else set(rule_map(root))))
    return _cache_put(_HIST_CACHE, key, index)


def _locate(index, curr_text):
    """Which history entry IS this capture? Exact text first; normalized only as
    a fallback, and then the LAST match.

    Order matters, and getting it wrong is silent: the 2026-08-12 13:54 capture
    normalizes EQUAL to the 2026-08-07 16:14 one (that equality is the rollback
    we want to report). Matching normalized-first located the capture at the
    earlier index and killed rollback detection outright.
    """
    dig = _digest(curr_text)
    for i, (_ts, rh, _n, _u) in enumerate(index):
        if rh == dig:
            return i
    norm = normalize_for_compare(curr_text)
    last = None
    for i, (_ts, _rh, n, _u) in enumerate(index):
        if n == norm:
            last = i
    return last


def lifecycle_sentence(uuid, op, index, idx, plural=False):
    """'gone again by the … capture' / 'first appeared in the … capture'.

    Silent without history rather than speculative. `plural` gives the same fact
    phrased for a whole group of rules, so a bulk change can state it once
    instead of repeating an identical sentence after every rule.
    """
    if not index or idx is None or len(index) < 2:
        return ""
    n_present = sum(1 for _ts, _rh, _n, us in index if uuid in us)
    total = len(index)
    if op == "added":
        for ts, _rh, _n, us in index[idx + 1:]:
            if uuid not in us:
                if plural:
                    return (f"All of these rules were gone again by the {_fmt_capture(ts)} "
                            f"capture — each was present in only {n_present} of {total} "
                            f"captures in the window.")
                return (f"This rule was gone again by the {_fmt_capture(ts)} capture — it was "
                        f"present in only {n_present} of {total} captures in the window.")
        latest = _fmt_capture(index[-1][0])
        return (f"All of them are still present in the latest capture ({latest})." if plural
                else f"It is still present in the latest capture ({latest}).")
    if op == "removed":
        first = next((ts for ts, _rh, _n, us in index if uuid in us), None)
        if first:
            if plural:
                return (f"These rules first appeared in the {_fmt_capture(first)} capture and "
                        f"were present in {n_present} of {total} captures in the window.")
            return (f"That rule first appeared in the {_fmt_capture(first)} capture and was "
                    f"present in {n_present} of {total} captures in the window.")
    return ""


def revert_sentence(index, idx):
    """Only fires when the normalized configs are genuinely identical.

    This is the best single sentence available in this dataset, so it is carried
    into every per-rule event as well as the aggregate one — it must not be
    reachable only through the risk-cap ground buried in `why`.
    """
    if not index or idx is None or idx < 2:
        return ""
    norm = index[idx][2]
    for ts, _rh, n, _u in reversed(index[:idx - 1]):
        if n == norm:
            return (f"After this change the configuration is identical (ignoring save "
                    f"timestamps) to the {_fmt_capture(ts)} capture — this change is a "
                    f"complete rollback to that state.")
    return ""


# --------------------------------------------------------------------------
# hunk -> rules
# --------------------------------------------------------------------------
# Read the uuid attribute as WRITTEN rather than validating its shape: these are
# OPNsense's identifiers, not ours, and a rule we refuse to recognise is a rule
# the report silently drops.
UUID_RE = re.compile(r'<rule\s+uuid="([^"]+)"')
LEGACY_HINT_RE = re.compile(r"^\s*<(type|descr|statetype)>", re.M)


def hunk_uuids(hunk) -> list:
    """uuids of <rule> blocks named in this hunk, in order of appearance."""
    seen, out = set(), []
    for line in list(hunk.get("added") or []) + list(hunk.get("removed") or []):
        for u in UUID_RE.findall(line):
            if u not in seen:
                seen.add(u)
                out.append(u)
    return out


def _field_line_forms(tag, value):
    """Both ways OPNsense can write one field, so an empty value still matches."""
    forms = {f"<{tag}>{value}</{tag}>"}
    if not value:
        forms.add(f"<{tag}/>")
        forms.add(f"<{tag} />")
    return forms


def attribute_uuidless(hunk, modified):
    """Which edited rule does a hunk with no <rule uuid=…> line belong to?

    An in-place edit (OPNsense's setRule) does NOT produce a whole-block hunk:
    difflib emits just the changed field lines, e.g. `<destination_port>443` ->
    `<destination_port>22`, with no uuid anywhere in the hunk. Matching those
    lines against each edited rule's own changed fields recovers the owner
    without needing line numbers, which structured_diff does not carry.
    Ambiguity is reported, never resolved by picking a favourite.

    NOTE this shape was never observed in the six real captures — 0 in-place
    edits across all 5 transitions — so it is written to be honest rather than
    demonstrated. An operator delete-plus-re-add produces a NEW uuid and is
    correctly reported as a remove plus an add, not as an edit.
    """
    if not modified:
        return []
    added = {l.strip() for l in (hunk.get("added") or []) if l.strip()
             and not is_noise_line(l)}
    removed = {l.strip() for l in (hunk.get("removed") or []) if l.strip()
               and not is_noise_line(l)}
    if not (added or removed):
        return []
    hits = []
    for old, new in modified:
        keys = [k for k, v in new.signature() if old.get(k) != v]
        new_forms, old_forms = set(), set()
        for k in keys:
            new_forms |= _field_line_forms(k, new.get(k))
            old_forms |= _field_line_forms(k, old.get(k))
        if added <= new_forms and removed <= old_forms:
            hits.append((old, new))
    return hits


def rule_block_lines(lines, uuid):
    """The <rule uuid=…> … </rule> slice for one uuid, from raw hunk lines."""
    start = next((i for i, l in enumerate(lines) if f'uuid="{uuid}"' in l), None)
    if start is None:
        return []
    out = []
    for line in lines[start:]:
        out.append(redact(line))
        if "</rule>" in line:
            break
    return out


# --------------------------------------------------------------------------
# event construction
# --------------------------------------------------------------------------
def _noise_event(prev_root, curr_root, captured_at, lines):
    """A hunk that is nothing but save stamps. Returned as a real (low-risk)
    event rather than None, because None hands the caller back to the keyword
    classifier — which is exactly what rated 9 of these HIGH RISK for containing
    the words "Firewall rules" in an XML attribute."""
    kinds = {noise_kind(l) for l in lines} - {"blank", None}
    labels = [lbl for name, _re, lbl in NOISE_KINDS if name in kinds]
    meta, prev_meta = save_metadata(curr_root), save_metadata(prev_root)
    what = ", ".join(labels) if labels else "OPNsense save markers"
    headline = (f"No configuration changed here: this hunk contains only {what}. These "
                f"fields move on every save, including saves that change nothing this "
                f"report tracks.")
    story = [headline]
    story.extend(metadata_sentences(meta, captured_at, set()))
    if prev_meta.get("saved_at"):
        story.append(f"The previous capture's save stamp was {prev_meta['saved_at']}.")
    return {
        "category": "metadata", "risk": "low", "summary": " ".join(story),
        "why": ("Save timestamps are not configuration. They are reported so the change "
                "record is complete, and are deliberately not rated as drift."),
        "remediation": "No action — nothing to review.",
        "confidence": 0.98, "source": SOURCE, "section": SECTION_META,
        "suppress": True, "rules": [], "n_rules": 0,
        "headline": headline, "story": story,
        "lines": [redact(l) for l in lines],
    }


def _rule_event(op, rule, ctx, peer_rules, meta, captured_at, index, idx, observed_ops,
                rollback="", prev_rule=None, new_uuids=()):
    """One complete explain-shaped dict for ONE rule.

    `summary` is the standalone story (used when this event is emitted on its
    own, which is what split_events() does); `body` is the same story without
    the per-capture metadata, so a multi-rule hunk can print that metadata once
    instead of six times.
    """
    risk, grounds = assess(op, rule, ctx)
    if rollback and risk == "high":
        # Do not alarm about re-opening something that was open in the state this
        # change restores. The rollback is PROVEN (normalized byte equality), not
        # inferred, so the cap is defensible.
        risk = "medium"
        grounds.append("capped from high: this change is an exact rollback to an earlier "
                       "captured state, so it opens nothing that was not open in that state")

    verb = {"added": "ADDED", "removed": "REMOVED", "modified": "MODIFIED"}[op]
    where = f" on {ctx.iface_scope(rule)}"

    if op == "modified" and prev_rule is not None:
        changed = [f"{k}: '{prev_rule.get(k)}' -> '{v}'"
                   for k, v in rule.signature() if prev_rule.get(k) != v]
        lead = (f"An existing firewall rule ({rule.short}) was EDITED in place{where}. "
                f"The uuid is unchanged, so this is an edit and not a delete plus re-add. "
                f"Fields changed: {'; '.join(changed)}.")
        second = f"It now reads: {describe_rule(rule, ctx)}"
        body = [lead, second]
    else:
        body = [f"A firewall rule was {verb}{where}: {describe_rule(rule, ctx)}"]

    extras = extra_clauses(rule)
    if extras:
        body.append("Non-default settings on this rule: " + "; ".join(extras) + ".")
    for definition in ctx.alias_definitions(rule):
        body.append(f"Alias used: {definition}.")
    desc = rule.get("description")
    body.append(f'Operator label: "{desc}".' if desc
                else "The rule carries no operator description.")
    if rule.get("sequence"):
        body.append(f"Sequence number {rule.get('sequence')}.")
    if op == "added":
        note = precedence_note(rule, ctx, list(peer_rules.values()), new_uuids)
        if note:
            body.append(note)
    life = lifecycle_sentence(rule.uuid, op, index, idx)

    # `body` is the rule's own story and nothing else. The capture metadata, the
    # lifecycle line and the rollback line are all SHARED by every rule in a bulk
    # change, so they are kept out of it and the aggregate renderer states them
    # once; the standalone `summary` below still carries all three.
    meta_lines = metadata_sentences(meta, captured_at, observed_ops)
    tail = ([life] if life else []) + ([rollback] if rollback else [])
    story = body + meta_lines + tail
    summary = " ".join(story)

    why = f"Rated {risk}: " + "; ".join(grounds) + "."
    if op == "added" and rule.action == "pass" and rule.enabled:
        why += (" Confirm the source, destination and port are the ones intended and that "
                "the rule is still needed.")
    if op == "removed":
        why += " Confirm the removal was intended and that nothing depended on it."

    ifname = " / ".join(ctx.iface_label(i) for i in rule.ifaces) or "Floating"
    if rule.iface_negated and rule.ifaces:
        ifname += " (negated)"
    if op == "added":
        rem = (f"If unintended, delete rule {rule.uuid} in Firewall > Rules ({ifname}) and "
               f"apply. The full rule block is in the diff below and can be restored verbatim.")
    elif op == "removed":
        rem = (f"If unintended, re-create rule {rule.uuid} from the previous snapshot — the "
               f"complete rule block is in the diff below.")
    else:
        rem = (f"Compare rule {rule.uuid} with the previous snapshot and restore the prior "
               f"field values if the edit was unintended.")

    return {
        "category": "security", "risk": risk, "summary": summary, "why": why,
        "remediation": rem,
        "confidence": _confidence([summary], unknown_fields=len(rule.unknown)),
        "source": SOURCE,
        "section": f"{SECTION_RULES} > {rule.short}", "suppress": False,
        "uuid": rule.uuid, "op": op, "grounds": grounds,
        "headline": body[0], "story": story,
        "body": " ".join(body), "body_sentences": body,
        "lifecycle": life, "rollback": rollback,
    }


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def analyze(prev_text, curr_text, *, notes=None):
    """Full uuid-keyed delta between two captures, independent of any hunk.

    {'ok', 'reason', 'prev', 'curr', 'added', 'removed', 'modified', 'moved',
     'ctx', 'prev_ctx', 'meta', 'prev_root', 'curr_root'}

    Cached on the content digests of the two texts: structured_diff hands the
    same transition back once per hunk, and re-parsing two 260 KB documents
    three times per transition is pure waste.
    """
    notes = notes if notes is not None else []
    key = (_digest(prev_text), _digest(curr_text))
    hit = _ANALYZE_CACHE.get(key)
    if hit is not None:
        if not hit["ok"]:
            notes.append(hit["reason"])
        return hit

    prev_root, perr = parse_config(prev_text)
    curr_root, cerr = parse_config(curr_text)
    if perr or cerr:
        reason = (f"could not parse this capture as XML ({cerr or perr}) — falling back to "
                  f"the raw line diff")
        notes.append(reason)
        return _cache_put(_ANALYZE_CACHE, key,
                          {"ok": False, "reason": reason,
                           "prev_root": prev_root, "curr_root": curr_root})
    prev_rules, curr_rules = rule_map(prev_root), rule_map(curr_root)
    added = [curr_rules[u] for u in curr_rules if u not in prev_rules]
    removed = [prev_rules[u] for u in prev_rules if u not in curr_rules]
    modified = [(prev_rules[u], curr_rules[u]) for u in curr_rules
                if u in prev_rules and prev_rules[u].signature() != curr_rules[u].signature()]
    moved = [curr_rules[u] for u in curr_rules
             if u in prev_rules and prev_rules[u].index != curr_rules[u].index
             and prev_rules[u].signature() == curr_rules[u].signature()]
    return _cache_put(_ANALYZE_CACHE, key, {
        "ok": True, "reason": "", "prev_root": prev_root, "curr_root": curr_root,
        "prev": prev_rules, "curr": curr_rules, "added": added, "removed": removed,
        "modified": modified, "moved": moved,
        "ctx": Ctx(curr_root), "prev_ctx": Ctx(prev_root),
        "meta": save_metadata(curr_root)})


def explain_opnsense(hunk, prev_text, curr_text, *, captured_at=None, history=None,
                     notes=None):
    """Explain ONE structured_diff hunk from a pair of OPNsense config.xml captures.

    Returns a pipeline.explain()-shaped dict — {category, risk, summary, why,
    remediation, confidence, source} — plus extras:
        section   a real XML path, so a caller can replace '(top level)'
        suppress  True for save-stamp-only hunks (nothing changed)
        rules     per-rule explain dicts; see split_events()
        headline  one sentence; story: the same text as a list of paragraphs
    Returns None when it cannot do better than the generic template, so the
    caller falls back; the reason is appended to `notes` when a list is given.

    Deliberate side effect: credential elements in hunk['added']/['removed'] are
    redacted in place. The caller stores those lists verbatim into the report,
    and shipping an API token to a client is worse than a surprising mutation.

    Optional `history` — [(captured_at, raw), …] over the device's whole snapshot
    series — unlocks the lifecycle and rollback sentences. Without it the module
    is simply silent about them rather than speculative.

    Note for callers: an in-place rule EDIT can span several difflib hunks (one
    per changed field), and each of those hunks explains the same rule, so dedupe
    on (ex['rules'][i]['uuid'], op) if you emit one event per hunk.
    """
    notes = notes if notes is not None else []
    if not isinstance(hunk, dict):
        return None
    # redact() also coerces, so every line is a str from here down. A non-str
    # line is a caller bug; it is normalised rather than dropped, so nothing
    # disappears from the diff the report shows.
    for key in ("added", "removed"):
        if hunk.get(key):
            hunk[key] = [redact(l) for l in hunk[key]]
    lines = [l for l in (list(hunk.get("added") or []) + list(hunk.get("removed") or []))
             if l.strip()]
    if not lines:
        return None

    res = analyze(prev_text, curr_text, notes=notes)
    if not res["ok"]:
        return None                     # honest fallback: caller uses the line diff

    ctx, meta = res["ctx"], res["meta"]
    signal = [l for l in lines if not is_noise_line(l)]
    if not signal:
        return _noise_event(res["prev_root"], res["curr_root"], captured_at, lines)

    uuids = hunk_uuids(hunk)
    edited = []
    if not uuids:
        # No whole rule block here. Either an in-place edit (whose hunk is just
        # the changed field lines), or a change that is not a Filter-plugin rule
        # at all: the legacy <filter>/<nat> trees use a different schema, and
        # describing those with this grammar would be describing them wrongly.
        edited = attribute_uuidless(hunk, res["modified"])
        if not edited:
            blob = "\n".join(signal)
            notes.append("hunk contains rule-like XML with no plugin uuid (legacy <filter> "
                         "tree?) — not modelled here" if ("<rule" in blob or
                                                          LEGACY_HINT_RE.search(blob))
                         else "hunk is outside OPNsense > Firewall > Filter > rules — "
                              "not modelled here")
            return None
        uuids = [new.uuid for _old, new in edited]

    index = _history_index(history)
    idx = _locate(index, curr_text) if index else None
    rollback = revert_sentence(index, idx)

    added_by = {r.uuid: r for r in res["added"]}
    removed_by = {r.uuid: r for r in res["removed"]}
    modified_by = {new.uuid: (old, new) for old, new in res["modified"]}
    observed_ops = ({"added"} if res["added"] else set()) | \
                   ({"removed"} if res["removed"] else set())

    events, unexplained = [], []
    new_uuids = set(added_by)
    for u in uuids:
        if u in added_by:
            events.append(_rule_event("added", added_by[u], ctx, res["curr"], meta,
                                      captured_at, index, idx, observed_ops, rollback,
                                      new_uuids=new_uuids))
        elif u in removed_by:
            # A removed rule must be described against the snapshot it existed
            # in: its interfaces and aliases may not exist in the new one.
            events.append(_rule_event("removed", removed_by[u], res["prev_ctx"], res["prev"],
                                      meta, captured_at, index, idx, observed_ops, rollback))
        elif u in modified_by:
            old, new = modified_by[u]
            events.append(_rule_event("modified", new, ctx, res["curr"], meta, captured_at,
                                      index, idx, observed_ops, rollback, prev_rule=old))
        else:
            unexplained.append(u)

    if not events:
        notes.append("uuids in this hunk match no add/remove/edit in the parsed delta — "
                     "cannot explain it")
        return None

    # honesty: the rule count moved in a way the uuid delta does not account for
    caveats = []
    n_prev, n_curr = len(res["prev"]), len(res["curr"])
    if (n_curr - n_prev) != (len(res["added"]) - len(res["removed"])):
        caveats.append(f"The rule count moved {n_prev} -> {n_curr}, which the uuid delta does "
                       f"not fully explain — treat this summary as partial.")
    if unexplained:
        caveats.append(f"{len(unexplained)} rule block(s) in this diff could not be matched to "
                       f"an add, remove or edit and are not described above.")
    if res["moved"]:
        caveats.append(f"{len(res['moved'])} rule(s) kept their settings but changed position "
                       f"in the file.")
    if len(edited) > 1:
        caveats.append(f"These diff lines match {len(edited)} edited rules equally well "
                       f"(the diff carries no rule identifier), so all of them are described "
                       f"here rather than one being picked.")

    risk = max((e["risk"] for e in events), key=lambda r: RISK_ORDER.get(r, 0))
    counts = [(sum(1 for e in events if e["op"] == op), word)
              for op, word in (("added", "added"), ("removed", "removed"),
                               ("modified", "edited"))]
    head = " and ".join(f"{n} rule{'' if n == 1 else 's'} {w}" for n, w in counts if n)

    meta_lines = metadata_sentences(meta, captured_at, observed_ops)
    if len(events) == 1:
        headline = events[0]["headline"]
        story = events[0]["story"] + caveats
        summary = " ".join(events[0]["story"] + caveats)
    else:
        # Say the shared things ONCE: the capture metadata, the rollback line and
        # — when every rule in the hunk has the same one — the lifecycle line.
        # e['body'] deliberately excludes all three, so nothing has to be sliced
        # back off a rendered string.
        lifes = [e["lifecycle"] for e in events]
        shared_life = (lifecycle_sentence(events[0]["uuid"], events[0]["op"], index, idx,
                                          plural=True)
                       if lifes[0] and all(l == lifes[0] for l in lifes) else None)
        bodies = []
        for i, e in enumerate(events, 1):
            text = e["body"] if shared_life else \
                " ".join([e["body"]] + ([e["lifecycle"]] if e["lifecycle"] else []))
            # "(1) …" rather than a bare newline: report.py escapes summary into
            # a <b> with no white-space:pre-line, so the newlines below collapse
            # to spaces today and the numbering is what keeps it readable.
            bodies.append(f"({i}) {text}")
        headline = f"{head} in the OPNsense firewall ruleset."
        lead = [headline] + caveats + meta_lines
        if rollback:
            lead.append(rollback)
        if shared_life:
            lead.append(shared_life)
        story = lead + bodies
        summary = " ".join(lead) + "\n" + "\n".join(bodies)

    whys = list(dict.fromkeys(e["why"] for e in events))
    why = (f"Highest rating in this change: {risk}. " if len(events) > 1 else "") + " ".join(whys)
    # The aggregate is never more confident than its least confident rule.
    floor = min(e["confidence"] for e in events)

    return {
        "category": "security", "risk": risk, "summary": summary, "why": why,
        "remediation": events[0]["remediation"] if len(events) == 1 else
        ("Review each rule above in Firewall > Rules. Every rule block is reproduced verbatim "
         "in the diff below, so any of them can be restored or removed exactly as it was."),
        "confidence": min(floor, _confidence([summary], caveats)),
        "source": SOURCE, "section": SECTION_RULES,
        "suppress": False, "rules": events, "n_rules": len(events),
        "headline": headline, "story": story, "caveats": caveats,
    }


def split_events(hunk, prev_text, curr_text, *, captured_at=None, history=None, notes=None):
    """THE RECOMMENDED SHAPE: [(sub_hunk, explain_dict)] — one event per RULE.

    difflib emitted a single 336-line hunk for the six rules added on 2026-08-12,
    one of which was a `block`. The per-rule event is the honest unit: each
    carries only its own rule block as its diff, and each carries the rollback
    sentence, so the best story in the dataset survives this path too.
    """
    ex = explain_opnsense(hunk, prev_text, curr_text, captured_at=captured_at,
                          history=history, notes=notes)
    if ex is None:
        return []
    if not ex.get("rules"):
        return [(dict(hunk, section=ex["section"]), ex)]
    added_lines = list(hunk.get("added") or [])
    removed_lines = list(hunk.get("removed") or [])
    out = []
    for sub in ex["rules"]:
        u = sub.get("uuid", "")
        add, rem = rule_block_lines(added_lines, u), rule_block_lines(removed_lines, u)
        if not add and not rem:
            # an in-place edit: the hunk holds changed field lines, not a block
            add, rem = added_lines, removed_lines
        out.append(({"op": hunk.get("op", ""), "section": sub["section"],
                     "added": add, "removed": rem}, sub))
    return out


# --------------------------------------------------------------------------
# wiring — see the WIRING section of the module docstring
# --------------------------------------------------------------------------
# pipeline.explain(hunk, device, vendor) cannot pass the two config texts this
# analysis needs, so the texts are registered against the hunk objects that came
# out of the same structured_diff() call. Keyed by id() and holding a reference
# to the hunk itself, so the id cannot be recycled underneath us. Nothing is
# written into the hunk dict: store.add_diff() json.dumps() the hunk list, and
# putting two 260 KB configs in there would bloat the diffs table on every save.
_BINDINGS = {}
_BIND_MAX = 512


class _Binding:
    __slots__ = ("prev_text", "curr_text", "captured_at", "history")

    def __init__(self, prev_text, curr_text, captured_at, history):
        self.prev_text = prev_text
        self.curr_text = curr_text
        self.captured_at = captured_at
        self.history = history


def bind(hunks, prev_text, curr_text, *, captured_at=None, history=None):
    """Register the config texts (and optionally the capture time and the full
    snapshot history) behind the hunks of one transition, so explain_hunk() can
    reach them through pipeline.explain()'s 3-argument signature.

    Re-binding the same hunks upgrades the registration, which is what lets
    install() bind the texts automatically and a caller add the timestamps
    afterwards. Returns `hunks` so it can be used inline.
    """
    b = _Binding(prev_text, curr_text, captured_at, history)
    if len(_BINDINGS) > _BIND_MAX:
        _BINDINGS.clear()
    for h in hunks or []:
        if isinstance(h, dict):
            _BINDINGS[id(h)] = (h, b)
    return hunks


def explain_hunk(hunk, device="", vendor="opnsense", notes=None):
    """pipeline.explain()-compatible: (hunk, device, vendor) -> dict | None.

    None means "not mine, or I cannot beat the template" — the caller then calls
    pipeline.explain() as before. Returns None for a hunk that was never passed
    to bind(), because without the two config texts there is nothing to parse.
    """
    if vendor and vendor != "opnsense":
        return None
    if not isinstance(hunk, dict):
        return None
    entry = _BINDINGS.get(id(hunk))
    if entry is None or entry[0] is not hunk:
        return None
    b = entry[1]
    return explain_opnsense(hunk, b.prev_text, b.curr_text, captured_at=b.captured_at,
                            history=b.history, notes=notes)


def install(pipeline=None, *also_rebind, rebind_imports=True):
    """Zero-edit wiring: wrap pipeline.structured_diff and pipeline.explain.

    This is a monkeypatch, and it is the second-best option — option (a) in the
    module docstring, an explicit call in driftwatch, is clearer and is the only
    way to supply `captured_at` and `history` (and so the timing, lifecycle and
    rollback sentences). Without them this wrapper still replaces the template
    with per-rule stories and stops the save-stamp hunks being rated HIGH.

    `from .pipeline import structured_diff, explain` binds those names into
    the importing module, so patching the pipeline module alone would not reach
    an already-imported caller; with rebind_imports the same names are rebound
    in every loaded module that currently points at the originals. Idempotent.
    Returns True if it patched, False if it was already installed.
    """
    if pipeline is None:
        try:
            from . import pipeline as pipeline          # noqa: WPS433, PLC0415
        except ImportError:                             # running as a script
            from . import pipeline as pipeline            # noqa: WPS433, PLC0415
    if getattr(pipeline.explain, "_opnsense_installed", False):
        return False

    orig_diff, orig_explain = pipeline.structured_diff, pipeline.explain

    def structured_diff(old_text, new_text, vendor):
        hunks = orig_diff(old_text, new_text, vendor)
        if vendor == "opnsense":
            bind(hunks, old_text, new_text)
        return hunks

    def explain(hunk, device, vendor):
        if vendor == "opnsense":
            ex = explain_hunk(hunk, device, vendor)
            if ex is not None:
                return ex
        return orig_explain(hunk, device, vendor)

    structured_diff._opnsense_installed = True
    structured_diff._opnsense_original = orig_diff
    explain._opnsense_installed = True
    explain._opnsense_original = orig_explain

    targets = [pipeline] + [m for m in also_rebind if m is not None]
    if rebind_imports:
        targets += [m for m in list(sys.modules.values()) if m is not None]
    seen = set()
    for mod in targets:
        if id(mod) in seen:
            continue
        seen.add(id(mod))
        try:
            if getattr(mod, "structured_diff", None) is orig_diff:
                mod.structured_diff = structured_diff
            if getattr(mod, "explain", None) is orig_explain:
                mod.explain = explain
        except Exception:                               # noqa: BLE001
            continue                                    # a module that refuses setattr
    return True


def uninstall(pipeline=None, *also_rebind, rebind_imports=True):
    """Undo install(). Used by the self-test; harmless if never installed."""
    if pipeline is None:
        try:
            from . import pipeline as pipeline          # noqa: WPS433, PLC0415
        except ImportError:
            from . import pipeline as pipeline            # noqa: WPS433, PLC0415
    patched_diff = getattr(pipeline.structured_diff, "_opnsense_original", None)
    patched_explain = getattr(pipeline.explain, "_opnsense_original", None)
    if patched_explain is None:
        return False
    cur_diff, cur_explain = pipeline.structured_diff, pipeline.explain
    targets = [pipeline] + [m for m in also_rebind if m is not None]
    if rebind_imports:
        targets += [m for m in list(sys.modules.values()) if m is not None]
    for mod in targets:
        try:
            if patched_diff is not None and getattr(mod, "structured_diff", None) is cur_diff:
                mod.structured_diff = patched_diff
            if getattr(mod, "explain", None) is cur_explain:
                mod.explain = patched_explain
        except Exception:                               # noqa: BLE001
            continue
    _BINDINGS.clear()
    return True


# --------------------------------------------------------------------------
# self-test — python3 -m core.explain_opnsense <dir-of-captures> [--per-rule]
# --------------------------------------------------------------------------
def _selftest(path, diff_fn=None, per_rule=False):
    import glob
    import os
    if diff_fn is None:
        try:
            from .pipeline import structured_diff as diff_fn            # noqa: WPS433
        except ImportError:
            from .pipeline import structured_diff as diff_fn       # noqa: WPS433
    files = sorted(glob.glob(os.path.join(path, "*.xml")) +
                   glob.glob(os.path.join(path, "*.conf")))
    if not files:
        print("no captures found in", path)
        return
    hist = []
    for f in files:
        m = re.search(r"(\d{8})[-_]?(\d{6})", os.path.basename(f))
        hist.append((f"{m.group(1)}-{m.group(2)}" if m else os.path.basename(f),
                     open(f, encoding="utf-8", errors="replace").read()))
    for (pts, ptext), (cts, ctext) in zip(hist, hist[1:]):
        print("=" * 78)
        print(f"{pts} -> {cts}")
        for h in diff_fn(ptext, ctext, "opnsense"):
            notes = []
            if per_rule:
                for sub_hunk, ex in split_events(h, ptext, ctext, captured_at=cts,
                                                 history=hist, notes=notes):
                    print("-" * 78)
                    print(f"[{ex['risk']:6}] {ex['category']:9} conf={ex['confidence']} "
                          f"{sub_hunk['section']}")
                    print(ex["summary"])
                continue
            ex = explain_opnsense(h, ptext, ctext, captured_at=cts, history=hist, notes=notes)
            print("-" * 78)
            if ex is None:
                print(f"[fallback to line diff] {notes}")
                continue
            print(f"[{ex['risk']:6}] {ex['category']:9} suppress={ex['suppress']} "
                  f"rules={ex['n_rules']} conf={ex['confidence']} section={ex['section']}")
            print(ex["summary"])
            print("WHY:", ex["why"])
            print("FIX:", ex["remediation"])


if __name__ == "__main__":                                          # pragma: no cover
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    _selftest(args[0] if args else ".", per_rule="--per-rule" in sys.argv)