"""netops-field-notes-mcp — the NetOps Field Notes toolbox as MCP tools.

Everything runs locally on deterministic rules — no model call, no account, no
telemetry, nothing read from your disk (configs and logs are passed in as text).
The two exceptions are check_tls_endpoint, which connects to the host you name, and
latest_field_note, which reads a public RSS feed.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET

from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field

from .lib import certscan, certutil, explain_opnsense, inventory, nacpilot, pipeline, tlsprobe, topology
from .lib.changeguard import preflight
from .lib.checks import run_checks
from .lib.sanitize import sanitize


def _vendor(text: str, given: str) -> str:
    return (given or "").strip().lower() or pipeline.detect_vendor(text)


server = MCPServer(
    name="netops-field-notes",
    version="0.1.0",
    instructions="Read-only network engineering tools: config drift, compliance, 802.1X diagnosis, certificates "
                 "inside configs, device facts and topology, OPNsense rule changes, change pre-flight, config "
                 "sanitising. Paste configs and logs as text.",
)


class DeviceConfig(BaseModel):
    name: str = Field(description="Device name, e.g. core-sw01")
    config: str = Field(description="The device's config text")
    vendor: str = Field(default="", description="Optional vendor hint (edgeos, mikrotik, opnsense, edgeswitch, cisco-ios)")


# ---------------------------------------------------------------- drift

_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _explain_hunks(before: str, after: str, device: str, vendor: str) -> list[dict]:
    hunks = pipeline.structured_diff(before, after, vendor)
    out = []
    if vendor == "opnsense":
        explain_opnsense.bind(hunks, before, after)
        for h in hunks:
            events = explain_opnsense.split_events(h, before, after)
            if not events:
                out.append({**h, **pipeline.explain(h, device, vendor)})
                continue
            for sub, ex in events:
                if ex.get("suppress"):
                    continue
                out.append({**sub, **ex})
    else:
        out = [{**h, **pipeline.explain(h, device, vendor)} for h in hunks]
    out.sort(key=lambda c: _RISK_ORDER.get(c.get("risk", "low"), 9))
    return out


def _render_changes(changes: list[dict], device: str, vendor: str) -> str:
    if not changes:
        return "No drift: the two snapshots are identical once volatile lines (timestamps, counters, save stamps) are removed."
    counts = {}
    for c in changes:
        counts[c["risk"]] = counts.get(c["risk"], 0) + 1
    head = (f"{len(changes)} change{'s' if len(changes) != 1 else ''} on {device or 'this device'} ({vendor}) — "
            + ", ".join(f"{counts.get(r, 0)} {r}" for r in ("critical", "high", "medium", "low") if counts.get(r)) + " risk.")
    blocks = []
    for c in changes:
        story = [p for p in (c.get("story") or []) if p]
        if story:
            lines = [f"  [{c['risk']}] {c.get('headline') or story[0]}"]
            lines += ["    " + p for p in story if p != (c.get("headline") or story[0])]
        else:
            lines = [f"  [{c['risk']}] {c.get('summary', '')}"]
            if c.get("why"):
                lines.append("    " + c["why"])
        shown = [f"    - {l.strip()}" for l in (c.get("removed") or [])[:6]] + [f"    + {l.strip()}" for l in (c.get("added") or [])[:6]]
        more = len(c.get("added") or []) + len(c.get("removed") or []) - len(shown)
        lines += shown
        if more > 0:
            lines.append(f"    ... {more} more line{'s' if more != 1 else ''}")
        blocks.append("\n".join(lines))
    tail = ("\nTo revert, restore the affected block from the previous snapshot rather than retyping it, and check "
            "the change record before assuming any of this was deliberate.")
    return "\n\n".join([head, *blocks]) + "\n" + tail


@server.tool(
    name="explain_config_diff",
    description="Explain what changed between two network device config snapshots, in plain English. EdgeOS, MikroTik "
                "RouterOS, OPNsense config.xml (per-rule stories, save-stamp noise filtered), EdgeSwitch and Cisco IOS-style "
                "configs: volatile lines stripped, changes grouped by config section, each tagged with a risk level and why "
                "it matters. Deterministic — no model call, nothing leaves the machine.",
)
def explain_config_diff(before: str, after: str, device: str = "", vendor: str = "") -> str:
    if not (before or "").strip() or not (after or "").strip():
        return "Both before and after snapshots are needed."
    v = _vendor(after, vendor)
    return _render_changes(_explain_hunks(before, after, device, v), device, v)


# ---------------------------------------------------------------- compliance

@server.tool(
    name="check_config_compliance",
    description="Run a CIS/PCI starter pack over one device config: cleartext management, SSH, default SNMP "
                "communities, centralised AAA, remote logging, NTP, hashed credentials, default credentials, management "
                "exposed to any source, login banner. Ten deterministic checks, each with a framework reference and a "
                "one-line remediation. Cisco, MikroTik, EdgeOS, OPNsense.",
)
def check_config_compliance(config: str, vendor: str = "") -> str:
    if not (config or "").strip():
        return "Paste the device config to check."
    v = _vendor(config, vendor)
    rows = run_checks(config, v)
    failed = [r for r in rows if r["status"] == "fail"]
    w = max(len(r["title"]) for r in rows)
    body = "\n".join(f"  {'pass' if r['status'] == 'pass' else 'FAIL'}  {r['title'].ljust(w)}  {r['ref']} ({r['severity']})" for r in rows)
    head = f"{len(rows) - len(failed)}/{len(rows)} checks pass on this {v} config."
    if failed:
        fixes = "\n".join(f"  - {r['title']}: {r['remediation']}" for r in failed)
        tail = f"\nFix first (highest severity at the top):\n{fixes}\n\nThese are regex checks over one config file — good for the obvious, not a substitute for a full benchmark run."
    else:
        tail = "\nEvery check passed. Treat that as a floor, not a certification."
    return "\n".join([head, "", body, tail])


# ---------------------------------------------------------------- 802.1X

@server.tool(
    name="diagnose_dot1x",
    description="Diagnose a port that will not authenticate. Paste any of: the RADIUS/ISE authentication log, the "
                "switchport interface config, the supplicant (Windows wired AutoConfig) log. Names the root cause — EAP "
                "method mismatch, unknown CA, shared-secret/NAD mismatch, missing dynamic VLAN, CoA NAK on the wrong port, "
                "invalid dACL — decodes ISE failure codes, and gives the fix on the switch AND in ISE. Read-only, rule-based.",
)
def diagnose_dot1x(radius_log: str = "", switchport_config: str = "", supplicant_log: str = "") -> str:
    if not any((radius_log or "").strip() for _ in [0]) and not (switchport_config or "").strip() and not (supplicant_log or "").strip():
        return "Give at least one of: radius_log, switchport_config, supplicant_log."
    d = nacpilot.diagnose(nacpilot.parse_radius(radius_log or ""), nacpilot.parse_supplicant(supplicant_log or ""),
                          nacpilot.parse_switchport(switchport_config or ""))
    return nacpilot.render_text(d, {})


@server.tool(
    name="lookup_ise_failure_code",
    description="Decode a Cisco ISE / RADIUS failure or step code (5400, 5411, 5440, 11007, 11036, 11514, 12321, 12508, "
                "12514, 15039, 22056): what it means, the usual cause, and the fix.",
)
def lookup_ise_failure_code(code: str) -> str:
    c = re.sub(r"\D", "", str(code or ""))
    entry = nacpilot.ISE_CODES.get(c)
    if not entry:
        known = ", ".join(sorted(nacpilot.ISE_CODES, key=int))
        return (f"Code {c or code!s} is not in the table (it covers {known}).\n"
                "In ISE, open Operations > RADIUS > Live Logs, click the details icon on the failed attempt, and read the "
                "'Failure Reason' and 'Steps' panes — the step code next to the last non-green step is the real reason.")
    name, meaning, fix = entry
    return f"ISE {c} — {name}\n\n  What it means  {meaning}\n  Fix            {fix}"


# ---------------------------------------------------------------- certificates

def _render_cert(rec: dict, findings: list[dict], now: float) -> str:
    days = certscan.days_left(rec, now)
    exp = time.strftime("%Y-%m-%d", time.gmtime(rec["not_after"]))
    key = f"{rec.get('key_type') or '?'}-{rec.get('key_bits') or '?'}" if rec.get("key_type") else "key unknown"
    lines = [f"  {rec.get('subject_cn') or '(no CN)'}  — issued by {rec.get('issuer_cn') or '?'}",
             f"    expires {exp} ({'EXPIRED ' + str(-days) + 'd ago' if days < 0 else str(days) + ' days left'})"
             f" · {key} · sig {rec.get('sig_algo') or '?'}"
             f"{' · self-signed' if rec.get('self_signed') else ''}{' · CA' if rec.get('is_ca') else ''}"
             f"{' · SANs: ' + ', '.join(rec['sans'][:6]) if rec.get('sans') else ''}"]
    for f in findings:
        lines.append(f"    [{f['risk']}] {f['category']}: {f['summary']}")
        lines.append(f"      {f['why']} → {f['remediation']}")
    return "\n".join(lines)


@server.tool(
    name="find_certs_in_config",
    description="Find every certificate embedded in a device config and check it: expiry (with severity buckets), weak RSA "
                "keys, MD5/SHA-1 signatures, self-signed leaves, CA certificates about to expire. Reads inline PEM blocks "
                "(Cisco crypto pki chains, EdgeOS, RouterOS exports, anything) and OPNsense config.xml <crt> blobs — the "
                "certificates web monitors never see because they are inside the config, not on a port.",
)
def find_certs_in_config(config: str, vendor: str = "", role: str = "") -> str:
    if not (config or "").strip():
        return "Paste the config to scan."
    v = _vendor(config, vendor)
    ders = certutil.certs_from_config(config, v)
    if not ders:
        return "No certificates found: no PEM blocks and no OPNsense <crt> elements in that text."
    now = time.time()
    blocks, total = [], 0
    for der in ders:
        rec = certutil.record_from_der(der)
        if not rec:
            blocks.append("  (one certificate could not be decoded)")
            continue
        f = certscan.findings_for(rec, role=role, endpoint=None, now=now)
        total += len(f)
        blocks.append(_render_cert(rec, f, now))
    head = f"{len(ders)} certificate{'s' if len(ders) != 1 else ''} in this {v} config, {total} finding{'s' if total != 1 else ''}."
    return "\n\n".join([head, *blocks])


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified)


@server.tool(
    name="check_tls_endpoint",
    description="Connect to a public host:port, read the certificate it actually serves, and run the same findings as "
                "find_certs_in_config on it (expiry, weak key, weak signature, self-signed, hostname not in SANs, CA expiry). "
                "Any port. Refuses hosts that resolve to private or reserved addresses.",
)
def check_tls_endpoint(host: str, port: int = 443, role: str = "") -> str:
    h = (host or "").strip().lower()
    h = re.sub(r"^[a-z]+://", "", h).split("/")[0]
    if ":" in h and not h.startswith("["):
        h, _, p = h.rpartition(":")
        port = int(p) if p.isdigit() else port
    if not h or not re.match(r"^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$", h) or ".." in h:
        return "Give a hostname like example.com or example.com:8443."
    if not 1 <= int(port) <= 65535:
        return f"{port} is not a valid port."
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(h, port, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return f"DNS resolution failed for {h}."
    bad = [ip for ip in ips if not _is_public(ip)]
    if bad:
        return f"{h} resolves to {bad[0]}, which is private or reserved space — refused. This tool only inspects hosts on the public internet."
    r = tlsprobe.probe(f"{h}:{port}")
    if not r["ok"]:
        return f"Could not read a certificate from {h}:{port}: {r['error']}"
    rec = certutil.record_from_der(r["der"])
    if not rec:
        return f"{h}:{port} served a certificate this tool could not decode."
    now = time.time()
    f = certscan.findings_for(rec, role=role, endpoint=f"{h}:{port}", verify_ok=r["verify_ok"], now=now)
    verify = "chain and hostname verify" if r["verify_ok"] else ("chain does NOT verify on this machine" if r["verify_ok"] is False else "verification result unknown")
    head = f"{h}:{port} — {r['tls_version'] or '?'}, {verify}, {len(f)} finding{'s' if len(f) != 1 else ''}."
    return "\n\n".join([head, _render_cert(rec, f, now)])


# ---------------------------------------------------------------- facts + topology

@server.tool(
    name="extract_device_facts",
    description="Pull the facts out of a device config: hostname, inferred role, every IPv4 address with its subnet, the "
                "subnets it sits on, and its VLANs. EdgeOS config.boot, MikroTik export, OPNsense config.xml, EdgeSwitch/"
                "FastPath, and Cisco IOS-style text.",
)
def extract_device_facts(config: str, vendor: str = "", device: str = "") -> str:
    if not (config or "").strip():
        return "Paste the device config."
    v = _vendor(config, vendor)
    f = inventory.extract(config, v, device or "device")
    addrs = "\n".join(f"    {a['ip']}/{a['cidr']}  (on {a['net']})" for a in f["addresses"]) or "    none found"
    body = [f"{f['hostname']} — {f['role']} ({v})", "", f"  Addresses ({f['ip_count']}):", addrs,
            f"  Subnets: {', '.join(f['nets']) or 'none'}", f"  VLANs ({len(f['vlans'])}): {', '.join(map(str, f['vlans'])) or 'none'}"]
    return "\n".join(body)


@server.tool(
    name="infer_topology",
    description="Given several device configs, work out which devices share subnets or VLANs and draw the segments as a "
                "Mermaid diagram (graph LR). Shared-subnet inference: two devices with an interface on the same network are "
                "adjacent. A subnet contained in a broader declared one is merged into it. Prefixes shorter than /16 are "
                "ignored as too broad to mean a segment.",
)
def infer_topology(devices: list[DeviceConfig]) -> str:
    if not devices:
        return "Give a list of {name, config} objects — at least two devices."
    facts = [inventory.extract(d.config, _vendor(d.config, d.vendor), d.name) for d in devices]
    shared = topology.infer(facts)
    mm, linked = topology.mermaid(facts, shared)
    unlinked = [f["device"] for f in facts if f["device"] not in linked]
    seg = "\n".join(f"  {net}: {', '.join(devs)}" for net, devs in sorted(shared.items())) or "  none — no two devices share a subnet or VLAN"
    body = [f"{len(facts)} devices, {len(shared)} shared segment{'s' if len(shared) != 1 else ''}, {len(linked)} linked.", "",
            "Shared segments:", seg]
    if unlinked:
        body += ["", f"Not linked to anything: {', '.join(unlinked)} (no shared subnet — DHCP-addressed, or a segment only one config declares)"]
    body += ["", "Mermaid:", "```mermaid", mm, "```"]
    return "\n".join(body)


# ---------------------------------------------------------------- OPNsense rules

@server.tool(
    name="explain_firewall_change",
    description="Explain a change between two OPNsense config.xml captures rule by rule: which rules were added, removed, "
                "edited or moved (keyed by uuid, so an edit is not mistaken for delete-plus-add), what each rule does in "
                "plain English, a risk rating with its stated grounds (any-source to a management port, any-source to the "
                "firewall itself, any/any/any pass), shadowed-rule notes, and which API call made the change. Save-stamp "
                "noise is recognised and set aside.",
)
def explain_firewall_change(before: str, after: str, device: str = "") -> str:
    if not (before or "").strip() or not (after or "").strip():
        return "Both captures are needed."
    if "<opnsense" not in after[:600] and "<opnsense" not in before[:600]:
        return "This tool reads OPNsense config.xml. For other vendors use explain_config_diff."
    changes = _explain_hunks(before, after, device, "opnsense")
    return _render_changes(changes, device or "firewall", "opnsense")


# ---------------------------------------------------------------- pre-flight

@server.tool(
    name="preflight_change",
    description="Before you push a change: diff the proposed config against the current one, risk-tag every change, list "
                "compliance checks that would regress, and — if you pass the configs of the other devices you manage — "
                "compute the blast radius (who shares the affected subnets and VLANs). Returns a gate verdict: BLOCK, "
                "REVIEW REQUIRED, PROCEED WITH CARE, or NO CHANGE. Read-only; nothing is applied.",
)
def preflight_change(current: str, proposed: str, device: str = "", vendor: str = "", fleet: list[DeviceConfig] | None = None) -> str:
    if not (current or "").strip() or not (proposed or "").strip():
        return "Both current and proposed configs are needed."
    v = _vendor(proposed, vendor)
    dev = device or "device"
    others = {d.name: d.config for d in (fleet or [])}
    explain_fn = None
    if v == "opnsense":
        cache = {}

        def explain_fn(h):  # noqa: E306 — per-hunk OPNsense story, falling back to the generic template
            if not cache:
                cache["hunks"] = pipeline.structured_diff(current, proposed, v)
                explain_opnsense.bind(cache["hunks"], current, proposed)
            match = next((x for x in cache["hunks"] if x["added"] == h["added"] and x["removed"] == h["removed"]), None)
            return explain_opnsense.explain_hunk(match, dev, v) if match else None
    pf = preflight(current, proposed, dev, v, others, explain_fn=explain_fn)
    gate, why = pf["gate"]
    lines = [f"{gate} — {why}", "", f"  Device      {dev} ({v})", f"  Max risk    {pf['max_risk']}",
             f"  Changes     {len(pf['changes'])}"]
    if pf["compliance"]["regressions"]:
        lines.append("  Regresses   " + "; ".join(pf["compliance"]["regressions"]))
    if pf["compliance"]["fixes"]:
        lines.append("  Fixes       " + "; ".join(pf["compliance"]["fixes"]))
    if pf["blast"]:
        lines.append("  Blast radius:")
        lines += [f"    {name}: shares {', '.join(shared)}" for name, shared in pf["blast"]]
    elif others:
        lines.append("  Blast radius: none of the other devices share a subnet or VLAN with this one")
    if pf["changes"]:
        lines += ["", "Changes:"]
        for c in pf["changes"]:
            lines.append(f"  [{c['risk']}] {c.get('summary', '')}")
    lines += ["", pf["rollback"]]
    return "\n".join(lines)


# ---------------------------------------------------------------- sanitise

@server.tool(
    name="sanitize_config",
    description="Scrub a config before it goes anywhere: passwords, secrets, RADIUS/TACACS keys, IPsec PSKs, SNMP "
                "communities, MD5 digests, Wi-Fi PSKs, key/certificate blocks and hashes are redacted; IPv4 addresses are "
                "mapped consistently to RFC 5737 documentation ranges (same address, same placeholder, so the logic still "
                "reads), IPv6 to 2001:db8::, MACs to the RFC 7042 range, hostnames to ROUTER-n, domains and emails to "
                "example.com. Subnet and wildcard masks are preserved. Returns the clean text and a count per category.",
)
def sanitize_config(config: str) -> str:
    if not (config or "").strip():
        return "Paste the config to sanitise."
    clean, counts = sanitize(config)
    total = sum(counts.values())
    summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "nothing matched"
    note = f"{total} item{'s' if total != 1 else ''} scrubbed ({summary}). Heuristic — read the output before you paste it anywhere."
    return f"{note}\n\n{clean.rstrip()}"


# ---------------------------------------------------------------- brand

@server.tool(
    name="latest_field_note",
    description="The most recent This Week in NetOps episodes — what changed in networking, cloud and automation this "
                "week and what to do about it. The only tool here that touches the network besides check_tls_endpoint; "
                "it reads a public RSS feed.",
)
def latest_field_note(count: int = 3) -> str:
    n = max(1, min(10, int(count or 3)))
    try:
        req = urllib.request.Request("https://netopsfieldnotes.com/podcast/feed.xml", headers={"User-Agent": "netops-field-notes-mcp"})
        with urllib.request.urlopen(req, timeout=10) as r:
            xml = r.read().decode("utf-8", "replace")
        items = []
        for item in ET.fromstring(xml).iter("item"):
            title = (item.findtext("title") or "").strip()
            date = (item.findtext("pubDate") or "").strip()
            desc = re.sub(r"<[^>]+>", " ", item.findtext("description") or "")
            desc = re.sub(r"\s+", " ", desc).strip()[:300]
            items.append(f"{re.sub(r' \\d{2}:\\d{2}:\\d{2}.*$', '', date)} — {title}\n  {desc}")
            if len(items) >= n:
                break
        if not items:
            return "No episodes in the feed right now."
        return "Latest from This Week in NetOps:\n\n" + "\n\n".join(items)
    except Exception as e:  # noqa: BLE001 — a feed hiccup is not a tool failure
        return f"Could not reach the feed ({e})."


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
