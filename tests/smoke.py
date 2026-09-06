"""Spawns the real server over stdio and exercises every tool with a positive and a
negative case. Run: python tests/smoke.py"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import sys

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters


def _selfsigned_pem(bits: int, days: int, cn: str = "lab-switch.example.net") -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=400))
            .not_valid_after(now + dt.timedelta(days=days)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


EDGEOS_BEFORE = """firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            destination { port 443 }
        }
    }
}
interfaces {
    ethernet eth0 {
        address 203.0.113.10/24
    }
    ethernet eth1 {
        address 10.0.5.1/24
        vif 30 { address 10.0.30.1/24 }
    }
}
service {
    ssh { port 22 }
}
system {
    host-name edge-rtr-1
    ntp { server 0.pool.ntp.org }
    syslog { host 10.0.5.50 { } }
    login { user admin { authentication { encrypted-password $6$abc } } }
}"""
EDGEOS_AFTER = EDGEOS_BEFORE.replace(
    "destination { port 443 }\n        }",
    "destination { port 443 }\n        }\n        rule 15 {\n            action accept\n            source { address 0.0.0.0/0 }\n            destination { port 22 }\n        }")
EDGEOS_PEER = """interfaces {
    ethernet eth0 { address 10.0.5.2/24 }
    ethernet eth2 { address 10.0.9.1/24 }
}
system { host-name access-sw-2 }"""

OPN_RULE = """        <rule uuid="{uuid}">
          <enabled>1</enabled>
          <sequence>{seq}</sequence>
          <action>{action}</action>
          <quick>1</quick>
          <interface>wan</interface>
          <direction>in</direction>
          <ipprotocol>inet</ipprotocol>
          <protocol>TCP</protocol>
          <source_net>any</source_net>
          <destination_net>any</destination_net>
          <destination_port>{port}</destination_port>
          <description>{descr}</description>
        </rule>
"""
OPN = """<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw1</hostname><domain>example.net</domain>{extra}</system>
  <interfaces>
    <wan><if>vtnet0</if><descr>WAN</descr><ipaddr>203.0.113.5</ipaddr><subnet>24</subnet><enable>1</enable></wan>
    <lan><if>vtnet1</if><descr>LAN</descr><ipaddr>10.0.5.1</ipaddr><subnet>24</subnet><enable>1</enable></lan>
  </interfaces>
  <filter/>
  <OPNsense>
    <Firewall>
      <Filter version="1.0.5" persisted_at="{t}">
        <rules>
{rules}        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
  <revision>
    <time>{t}</time>
    <description>{who}</description>
  </revision>
</opnsense>
"""
_r1 = OPN_RULE.format(uuid="11111111-1111-1111-1111-111111111111", seq="1", action="pass", descr="allow web", port="443")
_r2 = OPN_RULE.format(uuid="22222222-2222-2222-2222-222222222222", seq="2", action="pass", descr="ssh from anywhere", port="22")
OPN_BEFORE = OPN.format(extra="", rules=_r1, t="1786500838.87", who="/api/firewall/filter/addRule made changes")
OPN_AFTER = OPN.format(extra="", rules=_r1 + _r2, t="1786507111.02", who="/api/firewall/filter/addRule made changes")
OPN_NOISE = OPN.format(extra="", rules=_r1, t="1786599999.11", who="/api/firewall/filter/savepoint made changes")

IOS_BAD = """hostname core-sw01
no service password-encryption
username admin password admin
snmp-server community public RO
line vty 0 4
 transport input telnet
ip http server
"""
IOS_GOOD = """hostname core-sw01
service password-encryption
enable secret 5 $1$abcd$efghijklmnopqrstuvwxyz1
aaa new-model
aaa authentication login default group radius local
radius server ise1
 address ipv4 10.0.5.20
snmp-server community Qx9!zP RO
ntp server 10.0.5.9
logging host 10.0.5.50
banner motd ^Authorized use only^
line vty 0 4
 transport input ssh
"""

CERT_PEM_WEAK = _selfsigned_pem(1024, -5)
IOS_WITH_CERT = "hostname edge-fw\ncrypto pki certificate chain LAB\n certificate ca 01\n" + CERT_PEM_WEAK + " quit\n"
OPN_WITH_CRT = OPN.format(extra=f"<cert><crt>{base64.b64encode(_selfsigned_pem(2048, 400).encode()).decode()}</crt></cert>", rules=_r1, t="1", who="x")

DEMO = {name: s for name, s in __import__("netops_field_notes.lib.nacpilot", fromlist=["_DEMO"])._DEMO}
D1, D2, D3 = (DEMO[k] for k in DEMO)

CASES = [
    ["explain_config_diff", {"before": EDGEOS_BEFORE, "after": EDGEOS_AFTER, "device": "edge-rtr-1"}, ["1 change", "edgeos", "high", "rule 15"]],
    ["explain_config_diff", {"before": EDGEOS_BEFORE, "after": EDGEOS_BEFORE}, ["No drift"]],
    ["explain_config_diff", {"before": OPN_BEFORE, "after": OPN_NOISE}, ["No drift"]],
    ["check_config_compliance", {"config": IOS_BAD}, ["FAIL", "telnet", "SNMP", "default credentials"]],
    ["check_config_compliance", {"config": IOS_GOOD}, ["10/10 checks pass"]],
    ["diagnose_dot1x", {"radius_log": D1["radius"], "switchport_config": D1["switchport"], "supplicant_log": D1["supplicant"]}, ["Two defects", "EAP", "Tunnel-Private-Group-ID"]],
    ["diagnose_dot1x", {"radius_log": D2["radius"], "switchport_config": D2["switchport"]}, ["unknown CA", "12514", "Trusted Certificates"]],
    ["diagnose_dot1x", {"radius_log": D3["radius"], "switchport_config": D3["switchport"]}, ["Change-of-Authorization", "3799"]],
    ["diagnose_dot1x", {}, ["at least one"]],
    ["lookup_ise_failure_code", {"code": "12514"}, ["UNKNOWN CA", "Trusted Certificates"]],
    ["lookup_ise_failure_code", {"code": "99999"}, ["not in the table", "Live Logs"]],
    ["find_certs_in_config", {"config": IOS_WITH_CERT}, ["1 certificate", "EXPIRED", "weak-key", "1024", "self-signed"]],
    ["find_certs_in_config", {"config": OPN_WITH_CRT}, ["1 certificate", "opnsense", "days left"]],
    ["find_certs_in_config", {"config": "hostname r1\n"}, ["No certificates found"]],
    ["check_tls_endpoint", {"host": "www.cloudflare.com"}, ["www.cloudflare.com:443", "verify", "days left"]],
    ["check_tls_endpoint", {"host": "10.0.0.1"}, ["refused"]],
    ["extract_device_facts", {"config": EDGEOS_BEFORE}, ["edge-rtr-1", "router", "10.0.5.1/24", "10.0.30.0/24", "VLANs (1): 30"]],
    ["infer_topology", {"devices": [{"name": "edge-rtr-1", "config": EDGEOS_BEFORE}, {"name": "access-sw-2", "config": EDGEOS_PEER}]}, ["1 shared segment", "10.0.5.0/24: access-sw-2, edge-rtr-1", "graph LR"]],
    ["explain_firewall_change", {"before": OPN_BEFORE, "after": OPN_AFTER, "device": "fw1"}, ["fw1", "22", "high"]],
    ["explain_firewall_change", {"before": OPN_BEFORE, "after": OPN_NOISE, "device": "fw1"}, ["No drift"]],
    ["explain_firewall_change", {"before": EDGEOS_BEFORE, "after": EDGEOS_AFTER}, ["reads OPNsense"]],
    ["preflight_change", {"current": IOS_GOOD, "proposed": IOS_GOOD.replace("transport input ssh", "transport input telnet ssh"), "device": "core-sw01"}, ["REVIEW REQUIRED", "Regresses", "Cleartext"]],
    ["preflight_change", {"current": EDGEOS_BEFORE, "proposed": EDGEOS_AFTER, "device": "edge-rtr-1", "fleet": [{"name": "access-sw-2", "config": EDGEOS_PEER}]}, ["Blast radius", "access-sw-2: shares 10.0.5.0/24"]],
    ["preflight_change", {"current": IOS_GOOD, "proposed": IOS_GOOD}, ["NO CHANGE"]],
    ["sanitize_config", {"config": "hostname core-sw01\nenable secret 5 $1$abcd$efgh1234\nsnmp-server community S3cret RO\nip route 0.0.0.0 0.0.0.0 10.0.5.254\ninterface Vlan5\n ip address 10.0.5.1 255.255.255.0\n"}, ["<REDACTED>", "203.0.113.", "255.255.255.0", "ROUTER", "scrubbed"]],
    ["latest_field_note", {"count": 2}, ["NetOps"]],
]


async def main() -> int:
    params = StdioServerParameters(command=sys.executable, args=["-m", "netops_field_notes.server"])
    failed = 0
    async with Client(params) as client:
        tools = (await client.list_tools()).tools
        print(f"tools advertised: {len(tools)} — {', '.join(t.name for t in tools)}\n")
        for name, args, expect in CASES:
            res = await client.call_tool(name, args)
            text = "\n".join(getattr(c, "text", "") for c in res.content)
            missing = [e for e in expect if e.lower() not in text.lower()]
            label = f"{name}({', '.join(args)})"
            if missing:
                failed += 1
                print(f"FAIL {label}\n  missing: {' | '.join(missing)}\n  got:\n" + "\n".join("    " + l for l in text.splitlines()) + "\n")
            else:
                print(f"pass {label}")
    print(f"\n{failed} case(s) failed" if failed else f"\nall {len(CASES)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
