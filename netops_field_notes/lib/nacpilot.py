#!/usr/bin/env python3
"""NACpilot — read-only 802.1X / NAC troubleshooting copilot.

Paste the RADIUS/ISE auth log + the switchport config + (optionally) the supplicant
log for a port that won't authenticate, and NACpilot reconstructs the timeline, names
the root cause, decodes the ISE failure code, and prints the exact fix on the switch
AND in the ISE/RADIUS policy. Rule-based (no ML, no key), read-only (it reads logs/
configs; it never logs into anything).

  python3 nacpilot.py demo                                  # 3 worked examples, no setup
  python3 nacpilot.py diagnose --radius r.log --switchport gi0_5.cfg --supplicant s.log
  python3 nacpilot.py diagnose --radius r.log --html out.html
  python3 nacpilot.py diagnose --radius r.log --json

The moat is the named-failure-mode + ISE-code knowledge base below, not a model.
"""
from __future__ import annotations
import argparse, datetime, html as _h, json, os, re, sys, textwrap

# --- ISE / RADIUS failure-code knowledge base (the product's curated brain) ---
ISE_CODES = {
    "5400": ("Authentication failed", "Generic auth failure — see the more specific step code alongside it.",
             "Find the paired 1xxxx/2xxxx step code; it carries the real reason."),
    "5411": ("Supplicant stopped responding", "The endpoint went silent mid-EAP — often a supplicant/timer/cert-prompt issue, not a policy reject.",
             "Check the supplicant config + dot1x tx-period/timers; a user dismissing a cert prompt also causes this."),
    "5440": ("Endpoint abandoned the EAP session", "The endpoint restarted EAP before finishing — flapping link or supplicant retry.",
             "Check the port for link flaps and the supplicant for a half-configured profile."),
    "11007": ("Could not locate the Network Device / AAA client", "ISE has no NAD entry for this switch's IP — or the shared secret/IP doesn't match.",
              "Add/fix the Network Device in ISE for this NAS-IP and confirm the RADIUS shared secret matches the switch."),
    "11036": ("Message-Authenticator attribute invalid", "The RADIUS shared secret on the switch and ISE do not match.",
              "Re-enter the SAME RADIUS key on the switch (`radius server` / `key`) and in the ISE NAD definition."),
    "11514": ("EAP-TLS handshake failed (TLS alert)", "The TLS handshake for EAP-TLS/PEAP broke — usually a cert trust/chain problem.",
              "Verify both ends' certs and that ISE trusts the issuing CA chain (root + intermediates)."),
    "12508": ("EAP-TLS handshake failed (peer)", "The peer rejected the EAP-TLS handshake — wrong/expired cert or no client cert.",
              "Confirm the client has a valid, in-date cert and the supplicant is set to EAP-TLS (or allow PEAP in policy)."),
    "12514": ("EAP-TLS failed — UNKNOWN CA in the chain", "ISE (or the NAD) doesn't trust the CA that signed the presented certificate; the chain is incomplete.",
              "Import the FULL issuing CA chain (root + intermediates) into ISE Administration > Certificates > Trusted Certificates."),
    "12321": ("PEAP handshake failed", "The PEAP outer TLS tunnel failed — server cert not trusted by the supplicant, or protocol mismatch.",
              "Make the supplicant trust ISE's EAP server cert (or uncheck 'validate server cert' for a lab), and confirm PEAP is allowed."),
    "22056": ("Subject not found in the identity store", "Auth succeeded cryptographically but the user/MAC isn't in the configured ID source.",
              "Add the endpoint/user to the right identity store, or fix the ISE identity-source-sequence for this rule."),
    "15039": ("Rejected by authorization profile", "Authentication passed but an authorization rule explicitly denied or returned DenyAccess.",
              "Review the matching ISE authorization rule/profile for this device; it's returning a deny."),
}


def _read(p):
    return open(p, encoding="utf-8", errors="replace").read() if p and os.path.isfile(p) else ""


def _first(pat, text, flags=re.I):
    m = re.search(pat, text, flags)
    return m.group(1).strip() if m else None


def _has(pat, text, flags=re.I):
    return re.search(pat, text, flags) is not None


def _norm_eap(m):
    m = (m or "").strip().upper()
    return m if m.startswith("EAP-") else "EAP-" + m


# --- parsers ---
def parse_radius(text):
    return {
        "access_reject": _has(r"Access-Reject", text), "access_accept": _has(r"Access-Accept", text),
        "server_eap": _first(r"server\s*=\s*(EAP-[A-Z0-9]+)", text) or _first(r"proposed\s+(EAP-[A-Z0-9]+)", text),
        "supplicant_eap": _first(r"supplicant\s*=\s*(EAP-[A-Z0-9]+)", text),
        "eap_mismatch": _has(r"EAP method (?:mismatch|negotiation failed)|no common method", text),
        "reject_reason": _first(r'reason="([^"]+)"', text),
        "mab_used": _has(r"\bMAB\b|service-type=Call-Check", text),
        "mab_group": _first(r'matched endpoint group "([^"]+)"', text),
        "authz_profile": _first(r'authorization-profile="([^"]+)"', text),
        "dynamic_vlan": _first(r"Tunnel-Private-Group-ID\s*[=:]\s*(\S+)", text),
        "no_dynamic_vlan": _has(r"NO Tunnel-Private-Group-ID|no dynamic VLAN", text),
        "expected_vlan": _first(r"Expected\s+\w*\s*vlan\s+(\d+)", text) or _first(r"QUARANTINE\s+vlan\s+(\d+)", text),
        "fallback_vlan": _first(r"configured access vlan\s+(\d+)", text) or _first(r"access vlan\s+(\d+)", text),
        "calling_station": _first(r"calling-station-id=([0-9A-Fa-f:.\-]+)", text),
        "nas_ip": _first(r"nas-ip=([0-9.]+)", text),
        "ise_codes": [c for c in ISE_CODES if re.search(rf"\b{c}\b", text)],
        # extra named modes:
        "coa_sent": _has(r"CoA-Request|CoA sent", text),
        "coa_nak": _has(r"CoA-NAK", text),
        "coa_port": _first(r"CoA.*?port\s+(\d+)", text),
        "shared_secret_issue": _has(r"Message-Authenticator.*invalid|shared secret|unknown NAS|locate.*Network Device", text),
        "dacl_bad": _first(r"(permit\s+any\s+any\s+eq\s+\d+)", text),  # missing protocol = invalid dACL
    }


def parse_supplicant(text):
    return {"configured_eap": _first(r"EAP type configured:\s*([A-Za-z0-9\-]+)", text),
            "no_client_cert": _has(r"[Nn]o client certificate", text),
            "fell_to_mab": _has(r"fall(?:ing)? (?:through|back) to MAB", text)}


def parse_switchport(text):
    text = "\n".join(l.lstrip("! ").strip() if re.match(r"!\s*vlan\s+\d+\s+\w+", l.lstrip())
                     else l for l in text.splitlines() if not (l.lstrip().startswith("!") and not re.match(r"!\s*vlan\s+\d+\s+\w+", l.lstrip())))
    return {"interface": _first(r"interface\s+(\S+)", text),
            "access_vlan": _first(r"switchport access vlan\s+(\d+)", text),
            "host_mode": _first(r"authentication host-mode\s+(\S+)", text) or _first(r"access-session host-mode\s+(\S+)", text),
            "order": _first(r"authentication order\s+(.+)", text),
            "port_control": _first(r"authentication port-control\s+(\S+)", text) or _first(r"access-session port-control\s+(\S+)", text),
            "mab": _has(r"^\s*mab\s*$", text, re.I | re.M),
            "dot1x_authenticator": _has(r"dot1x pae authenticator", text),
            "fail_action_vlan": _first(r"authentication event fail action authorize vlan\s+(\d+)", text),
            "server_dead_vlan": _first(r"authentication event server dead action authorize vlan\s+(\d+)", text),
            "critical_vlan": _has(r"critical(?:-auth)? vlan", text),
            "system_auth_control": _has(r"dot1x system-auth-control", text),
            "quarantine_vlan": _first(r"vlan\s+(\d+)\s+QUARANTINE", text) or _first(r"QUARANTINE\s+vlan\s+(\d+)", text)}


# --- diagnosis ---
def diagnose(rad, sup, sp):
    findings, steps, fixes = [], [], []

    def F(sev, title, detail):
        findings.append({"severity": sev, "title": title, "detail": detail})

    if sp.get("order"):
        steps.append(f"Port {sp.get('interface') or '(unknown)'} auth order: {sp['order']}.")

    # ISE failure codes (the knowledge base in action)
    for c in rad.get("ise_codes", []):
        name, meaning, fix = ISE_CODES[c]
        F("INFO", f"ISE code {c}: {name}", meaning)
        if c in ("11007", "11036", "12514", "12321") and fix not in fixes:
            fixes.append(fix)

    # EAP mismatch
    se, supp = rad.get("server_eap"), rad.get("supplicant_eap") or sup.get("configured_eap")
    if rad.get("eap_mismatch") or (se and supp and se.upper() != _norm_eap(supp)):
        F("CRITICAL", "802.1X EAP method mismatch",
          f"Server required {se or 'EAP-TLS'} but the supplicant offered {supp or 'a different method'} — no common method, so dot1x cannot complete.")
        steps.append(f"dot1x failed: server wanted {se or 'EAP-TLS'}, supplicant offered {supp or 'PEAP'}.")
        if sup.get("no_client_cert"):
            steps.append("Supplicant confirms: no client certificate installed, so it cannot do EAP-TLS.")
        fixes.append(f"Align EAP: either enroll a client cert + set the supplicant to {se or 'EAP-TLS'}, OR allow {supp or 'PEAP'} in the ISE auth policy for this port. Make both ends match.")
    elif rad.get("reject_reason") and rad.get("access_reject"):
        F("CRITICAL", "RADIUS Access-Reject", f"dot1x rejected: {rad['reject_reason']}.")
        steps.append(f"Access-Reject: {rad['reject_reason']}.")

    # MAB fallback
    if (rad.get("mab_used") or sup.get("fell_to_mab")) and (rad.get("access_reject") or rad.get("eap_mismatch")):
        steps.append("After dot1x failed, the port fell through to MAB.")
        if rad.get("mab_group"):
            steps.append(f'MAB matched endpoint group "{rad["mab_group"]}".')

    # authorization / dynamic VLAN
    if rad.get("access_accept") and (rad.get("no_dynamic_vlan") or not rad.get("dynamic_vlan")):
        exp, land = rad.get("expected_vlan") or sp.get("quarantine_vlan"), rad.get("fallback_vlan") or sp.get("access_vlan")
        F("CRITICAL", "Authorization returned no dynamic VLAN",
          f"The Access-Accept carries no Tunnel-Private-Group-ID, so the endpoint stays on static VLAN {land or '(configured)'}" + (f" instead of VLAN {exp}." if exp else "."))
        steps.append("Access-Accept had NO VLAN attributes (Tunnel-Private-Group-ID) → no dynamic VLAN pushed.")
        if rad.get("authz_profile"):
            fixes.append(f'Fix the ISE authorization profile "{rad["authz_profile"]}": add Tunnel-Type=VLAN(13), Tunnel-Medium-Type=802(6), Tunnel-Private-Group-ID={exp or "<quarantine-vlan>"}.')

    # CoA failure
    if rad.get("coa_nak"):
        port = rad.get("coa_port")
        F("CRITICAL", "CoA failed (NAK)",
          f"A Change-of-Authorization was rejected by the switch" + (f" (CoA sent to port {port})." if port else "."))
        if port == "1700":
            fixes.append("CoA port mismatch: the switch expects RFC 5176 CoA on UDP 3799, but it was sent to legacy 1700. Set ISE's NAD CoA port to 3799 (or `aaa server radius dynamic-author` `port 3799` on the switch) and match both sides.")
        else:
            fixes.append("Confirm `aaa server radius dynamic-author` is configured on the switch, the CoA client = ISE's IP, and the shared secret matches.")

    # shared-secret / unknown NAD
    if rad.get("shared_secret_issue") and "11036" not in rad.get("ise_codes", []):
        F("CRITICAL", "RADIUS shared-secret / NAD mismatch", "The switch and ISE disagree on the RADIUS shared secret, or ISE has no Network Device entry for this switch.")
        fixes.append("Re-enter the identical RADIUS key on the switch and the ISE NAD, and confirm the switch's source IP matches the ISE Network Device definition.")

    # invalid dACL
    if rad.get("dacl_bad"):
        F("WARN", "Invalid downloadable ACL (dACL)", f'The dACL line "{rad["dacl_bad"]}" is missing a protocol — IOS rejects `permit any any eq 443`; it must be `permit tcp any any eq 443`.')
        fixes.append('Fix the dACL in ISE: `permit any any eq 443` is invalid — use `permit tcp any any eq 443` (a protocol is required before `eq`).')

    # switchport backstops
    if not sp.get("fail_action_vlan") and sp.get("interface"):
        q = sp.get("quarantine_vlan") or rad.get("expected_vlan")
        F("WARN", "No auth-fail VLAN on the switchport", "The port has no `authentication event fail action authorize vlan` guardrail, so a failed/unprofiled endpoint isn't locally contained.")
        fixes.append(f"On the access port add: `authentication event fail action authorize vlan {q or '<quarantine>'}` as a local backstop.")
    if not sp.get("system_auth_control") and sp.get("dot1x_authenticator"):
        F("WARN", "dot1x not globally enabled", "The port runs dot1x but `dot1x system-auth-control` may be missing globally — 802.1X won't actually enforce.")
        fixes.append("Add the global `dot1x system-auth-control` (802.1X is inert without it).")
    if sp.get("port_control") and sp["port_control"] != "auto":
        F("WARN", "Port-control not 'auto'", f"authentication port-control is '{sp['port_control']}' — 802.1X isn't actively enforced (expected 'auto').")

    findings.sort(key=lambda f: {"CRITICAL": 0, "WARN": 1, "INFO": 2}.get(f["severity"], 9))
    return {"root_cause": _root_cause(rad, sup, sp, findings), "steps": steps, "fixes": fixes,
            "findings": findings, "facts": {"radius": rad, "supplicant": sup, "switchport": sp}}


def _root_cause(rad, sup, sp, findings):
    titles = {f["title"] for f in findings}
    if "802.1X EAP method mismatch" in titles and "Authorization returned no dynamic VLAN" in titles:
        exp = rad.get("expected_vlan") or sp.get("quarantine_vlan") or "the quarantine VLAN"
        land = rad.get("fallback_vlan") or sp.get("access_vlan") or "the static access VLAN"
        return (f"Two defects: (1) dot1x failed on an EAP mismatch ({rad.get('server_eap') or 'EAP-TLS'} vs {rad.get('supplicant_eap') or sup.get('configured_eap') or 'PEAP'}); "
                f"(2) MAB then Accepted with NO dynamic VLAN, so the endpoint landed on VLAN {land} instead of VLAN {exp}.")
    if "CoA failed (NAK)" in titles:
        return "A Change-of-Authorization was rejected by the switch — the post-auth VLAN/posture change never applied."
    if "EAP-TLS failed — UNKNOWN CA in the chain" in (ISE_CODES.get(c, ("", "", ""))[0] for c in rad.get("ise_codes", [])) or "12514" in rad.get("ise_codes", []):
        return "EAP-TLS failed because the certificate chain isn't trusted (unknown CA) — ISE/the NAD is missing the issuing CA's intermediates/root."
    if "802.1X EAP method mismatch" in titles:
        return f"802.1X failed: EAP method mismatch ({rad.get('server_eap') or 'server'} vs {rad.get('supplicant_eap') or sup.get('configured_eap') or 'supplicant'})."
    if "RADIUS shared-secret / NAD mismatch" in titles:
        return "RADIUS shared-secret or NAD mismatch — ISE isn't accepting requests from this switch."
    if rad.get("reject_reason"):
        return f"RADIUS Access-Reject: {rad['reject_reason']}."
    return "No definitive NAC failure detected in the supplied inputs."


# --- render ---
def render_text(d, src):
    rad, sp = d["facts"]["radius"], d["facts"]["switchport"]
    L = ["=" * 74, "802.1X / NAC TRIAGE — NACpilot", "=" * 74,
         f"endpoint : mac={rad.get('calling_station') or '?'} port={sp.get('interface') or '?'} nas={rad.get('nas_ip') or '?'}",
         "", "ROOT CAUSE", "-" * 74, textwrap.fill(d["root_cause"], 74), "", "WHAT HAPPENED", "-" * 74]
    L += [textwrap.fill(f"{i}. {s}", 74, subsequent_indent="   ") for i, s in enumerate(d["steps"], 1)] or ["  (no sequence)"]
    L += ["", "FINDINGS", "-" * 74]
    for f in d["findings"]:
        L.append(f"  [{f['severity']:<8}] {f['title']}")
        L.append(textwrap.fill(f["detail"], 74, initial_indent=" " * 13, subsequent_indent=" " * 13))
    L += ["", "RECOMMENDED FIX", "-" * 74]
    L += [textwrap.fill(f"{i}. {fx}", 74, subsequent_indent="   ") for i, fx in enumerate(d["fixes"], 1)] or ["  (none)"]
    return "\n".join(L + ["=" * 74])


_RC = {"CRITICAL": ("#cc2f2f", "#fdecec"), "WARN": ("#d9822b", "#fdf3e7"), "INFO": ("#3a4660", "#eef1f6")}


def render_html(d, src):
    rad, sp = d["facts"]["radius"], d["facts"]["switchport"]
    e = lambda x: _h.escape(str(x if x is not None else ""))
    find = "".join(f'<div class=f><span class=b style="color:{_RC[x["severity"]][0]};background:{_RC[x["severity"]][1]}">{x["severity"]}</span> '
                   f'<b>{e(x["title"])}</b><div class=d>{e(x["detail"])}</div></div>' for x in d["findings"])
    steps = "".join(f"<li>{e(s)}</li>" for s in d["steps"])
    fixes = "".join(f"<li>{e(fx)}</li>" for fx in d["fixes"]) or "<li>None.</li>"
    return f"""<!DOCTYPE html><html><head><meta charset=utf-8><title>NACpilot triage</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:820px;margin:0 auto;padding:20px;color:#16202e;line-height:1.5}}
.hero{{background:linear-gradient(180deg,#0f1729,#16223e);color:#eef3fb;padding:20px;border-radius:12px}}
h2{{font-size:17px;border-bottom:2px solid #1f6feb;padding-bottom:4px;margin-top:24px}}
.rc{{background:#fff7f7;border-left:4px solid #cc2f2f;padding:12px 14px;border-radius:6px;font-size:15px}}
.f{{border:1px solid #e6eaf2;border-radius:8px;padding:10px 12px;margin:8px 0;background:#f5f8fc}}
.b{{font-weight:800;font-size:11px;padding:2px 8px;border-radius:6px;margin-right:6px}}.d{{color:#67738c;font-size:13.5px;margin-top:4px}}
code{{background:#eef1f6;padding:1px 5px;border-radius:4px;font-size:13px}}</style></head><body>
<div class=hero><div style="font-size:13px;opacity:.8">802.1X / NAC triage</div>
<h1 style="margin:4px 0;font-size:23px">NACpilot</h1>
<div style="opacity:.85;font-size:13px">mac {e(rad.get('calling_station') or '?')} · port {e(sp.get('interface') or '?')} · nas {e(rad.get('nas_ip') or '?')}</div></div>
<h2>Root cause</h2><div class=rc>{e(d['root_cause'])}</div>
<h2>What happened</h2><ol>{steps or '<li>(no sequence)</li>'}</ol>
<h2>Findings</h2>{find or '<p>None.</p>'}
<h2>Recommended fix</h2><ol>{fixes}</ol>
<p style="color:#999;font-size:11px;margin-top:24px">Read-only diagnosis from logs you provided. NACpilot — NetOps shared pipeline.</p>
</body></html>"""


# --- demo (3 embedded scenarios; synthetic, RFC5737/fake) ---
_DEMO = [
    ("EAP-TLS vs PEAP + MAB lands on the wrong VLAN", {
        "radius": "2026-06-30 RADIUS Access-Request nas-ip=192.0.2.10 calling-station-id=00:11:22:33:44:55\n"
                  "EAP: server = EAP-TLS, supplicant = EAP-PEAP -- no common method\n"
                  'Step 12508 Access-Reject reason="12508 EAP-TLS handshake failed (no client certificate)"\n'
                  'MAB service-type=Call-Check matched endpoint group "Unknown"\n'
                  'Access-Accept authorization-profile="MAB_Guest" -- NO Tunnel-Private-Group-ID\n'
                  "Expected QUARANTINE vlan 30; configured access vlan 10",
        "supplicant": "Wired AutoConfig EAP type configured: PEAP\nNo client certificate present\nAuthentication failed; falling back to MAB",
        "switchport": "interface GigabitEthernet0/5\n switchport access vlan 10\n authentication host-mode multi-auth\n"
                      " authentication order dot1x mab\n authentication port-control auto\n mab\n dot1x pae authenticator\n! vlan 30 QUARANTINE"}),
    ("EAP-TLS unknown CA (trust chain)", {
        "radius": "RADIUS Access-Request nas-ip=192.0.2.11 calling-station-id=00:aa:bb:cc:dd:ee\n"
                  "EAP: server = EAP-TLS, supplicant = EAP-TLS\n"
                  'Step 12514 EAP-TLS failed SSL/TLS handshake because of an unknown CA in the certificate chain\n'
                  'Access-Reject reason="12514 unknown CA"',
        "supplicant": "", "switchport": "interface GigabitEthernet0/8\n switchport access vlan 20\n authentication port-control auto\n dot1x pae authenticator\n"}),
    ("Posture CoA rejected on the legacy port", {
        "radius": "RADIUS Access-Accept for 00:de:ad:be:ef:01 authorization-profile=\"Posture_Compliant\" nas-ip=192.0.2.12\n"
                  "CoA-Request sent to nas port 1700\n"
                  'CoA-NAK received reason="unsupported (NAS expects 3799)"',
        "supplicant": "", "switchport": "interface GigabitEthernet0/12\n switchport access vlan 50\n authentication port-control auto\n authentication event fail action authorize vlan 30\n dot1x system-auth-control\n dot1x pae authenticator\n"}),
]


def cmd_demo(html_path):
    blocks = []
    for i, (name, s) in enumerate(_DEMO, 1):
        d = diagnose(parse_radius(s["radius"]), parse_supplicant(s["supplicant"]), parse_switchport(s["switchport"]))
        print(f"\n{'#'*74}\n# SCENARIO {i}: {name}\n{'#'*74}")
        print(render_text(d, {}))
        blocks.append(f"<h1 style='font-size:18px;margin-top:30px'>Scenario {i}: {_h.escape(name)}</h1>" + render_html(d, {}))
    if html_path:
        open(html_path, "w").write("<!DOCTYPE html><meta charset=utf-8><body style='font-family:sans-serif'>" + "".join(blocks))
        print(f"\nHTML: {html_path}")


def main():
    ap = argparse.ArgumentParser(description="Read-only 802.1X/NAC troubleshooting copilot.")
    ap.add_argument("cmd", choices=["diagnose", "demo"])
    ap.add_argument("--radius"); ap.add_argument("--supplicant"); ap.add_argument("--switchport")
    ap.add_argument("--html"); ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.cmd == "demo":
        cmd_demo(a.html); return
    if not (a.radius or a.supplicant or a.switchport):
        ap.error("give NACpilot something: --radius/--supplicant/--switchport FILE (or run `demo`)")
    d = diagnose(parse_radius(_read(a.radius)), parse_supplicant(_read(a.supplicant)), parse_switchport(_read(a.switchport)))
    src = {"radius": a.radius, "supplicant": a.supplicant, "switchport": a.switchport}
    print(json.dumps({"sources": src, **d}, indent=2) if a.json else render_text(d, src))
    if a.html:
        open(a.html, "w").write(render_html(d, src)); print(f"\nHTML: {a.html}", file=sys.stderr)
    return 1 if any(f["severity"] == "CRITICAL" for f in d["findings"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
