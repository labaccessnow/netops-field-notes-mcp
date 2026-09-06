"""CIS / PCI starter pack — ten deterministic checks over one device config.

Regex over the raw text, multi-vendor (Cisco IOS/NX-OS, MikroTik RouterOS, EdgeOS,
OPNsense). Deterministic on purpose: an auditor re-running it gets the same result.
A floor, not a certification.
"""
from __future__ import annotations
import re


def _has(pat: str, text: str) -> bool:
    return re.search(pat, text, re.IGNORECASE) is not None


def _any(pats, text, flags=re.IGNORECASE | re.MULTILINE) -> bool:
    return any(re.search(p, text, flags) for p in pats)


def chk_plaintext_mgmt(text: str, vendor: str) -> bool:
    """Compliant when NO cleartext management plane (telnet/http) is enabled."""
    bad = [
        r"transport input[^\n]*\btelnet\b",          # cisco IOS vty
        r"^\s*feature telnet\b",                     # cisco NX-OS
        r"/ip service set telnet[^\n]*disabled=no",  # mikrotik
        r"/ip service set www[^\n]*disabled=no",     # mikrotik http
        r"^\s*telnet\s*\{",                          # edgeos service telnet
        r"ip telnet server enable",
        r"<protocol>\s*http\s*</protocol>",          # opnsense webgui http
        r"^\s*ip http server\b",                     # cisco http server
    ]
    return not _any(bad, text)


def chk_ssh_enabled(text: str, vendor: str) -> bool:
    """Compliant when encrypted SSH management is present."""
    return _any([
        r"transport input[^\n]*\bssh\b", r"/ip service set ssh[^\n]*disabled=no", r"^\s*ssh\s*\{",
        r"<ssh>\s*<enabled>", r"\bfeature ssh\b", r"\bip ssh\b", r"crypto key generate rsa",
    ], text)


def chk_snmp_community(text: str, vendor: str) -> bool:
    """Compliant when no default 'public'/'private' SNMP community is present."""
    return not _any([
        r"snmp-server community\s+(public|private)\b", r"\bname=(public|private)\b",
        r"<rocommunity>\s*(public|private)\s*</rocommunity>", r"community\s+(public|private)\s*\{",
    ], text)


def chk_aaa_auth(text: str, vendor: str) -> bool:
    """Compliant when centralized AAA (RADIUS/TACACS+) authentication is set."""
    if _has(r"\bno aaa new-model\b", text) and not _has(r"\bradius\b", text):
        return False
    return _any([r"aaa authentication", r"^\s*aaa new-model\b", r"\bgroup radius\b", r"^\s*radius server\b", r"tacacs"], text)


def chk_logging_host(text: str, vendor: str) -> bool:
    """Compliant when a remote syslog / logging host is configured."""
    return _any([r"logging host", r"logging server", r"remote=\d", r"<remoteserver>", r"syslog\s*\{[^}]*host", r"set system syslog"],
                text, re.IGNORECASE | re.DOTALL)


def chk_ntp_sync(text: str, vendor: str) -> bool:
    """Compliant when NTP/time-sync is configured AND not explicitly disabled."""
    if vendor == "mikrotik" or "/system ntp client" in text:
        if _has(r"/system ntp client[^\n]*enabled=no", text):
            return False
        return _has(r"/system ntp client[^\n]*enabled=yes", text) or _has(r"/system ntp client\b.*server", text)
    if vendor == "opnsense" or "<opnsense" in text[:600]:
        return _has(r"<timeservers>\s*\S", text)
    return _any([r"^\s*ntp server\s+\S", r"^\s*sntp\s+server\s+\S", r"^\s*ntp peer\s+\S", r"^\s*ntp\s*\{", r"^\s*set system ntp"], text)


def chk_pw_encryption(text: str, vendor: str) -> bool:
    """Compliant when stored credentials are hashed/encrypted (no cleartext)."""
    if _has(r"no service password-encryption", text):
        return False
    return _any([r"service password-encryption", r"encrypted-password\s+\$\d", r"\$1\$", r"\$5\$", r"\$6\$",
                 r"secret\s+[589]\s+\$", r"argon2", r"bcrypt", r"pbkdf2"], text)


def chk_default_creds(text: str, vendor: str) -> bool:
    """Compliant when NO empty or well-known default credential is present."""
    return not _any([
        r'password=""', r"password\s+(cisco|admin|password)\b", r"secret\s+(cisco|admin)\b",
        r"username\s+admin\s+password\s+admin\b", r"<password>\s*</password>",
    ], text)


def chk_mgmt_exposure(text: str, vendor: str) -> bool:
    """Compliant when the management plane is NOT permitted from any source."""
    if re.search(r"permit\s+tcp\s+any\s+.*\beq\s+(22|443|23)\b", text, re.IGNORECASE):
        return False
    if re.search(r"<source>\s*<any>\s*1\s*</any>\s*</source>.{0,400}?<port>\s*(22|443)\s*</port>", text, re.IGNORECASE | re.DOTALL):
        return False
    return True


def chk_login_banner(text: str, vendor: str) -> bool:
    """Compliant when a login / MOTD warning banner is configured."""
    return _any([r"^\s*banner\b", r"banner motd", r"login-banner", r"pre-login", r"<motd>", r"message-of-the-day"], text)


CHECKS = [
    dict(id="plaintext-mgmt", fw="CIS/PCI", ref="CIS NDM 2.1 / PCI-DSS 2.2.5", sev="high",
         title="Cleartext management (telnet/HTTP) disabled", fn=chk_plaintext_mgmt,
         remediation="Disable telnet/HTTP; allow only SSH/HTTPS for device management."),
    dict(id="ssh-enabled", fw="CIS", ref="CIS NDM 1.1.2", sev="medium",
         title="Encrypted SSH management enabled", fn=chk_ssh_enabled,
         remediation="Enable SSHv2 and restrict VTY/transport input to ssh only."),
    dict(id="snmp-community", fw="PCI", ref="PCI-DSS 2.1", sev="high",
         title="No default SNMP community (public/private)", fn=chk_snmp_community,
         remediation="Remove public/private; use SNMPv3 auth+priv or a unique community."),
    dict(id="aaa-auth", fw="CIS", ref="CIS NDM 1.5", sev="high",
         title="Centralized AAA (RADIUS/TACACS+) authentication", fn=chk_aaa_auth,
         remediation="Enable AAA and point authentication at RADIUS/TACACS+ servers."),
    dict(id="logging-host", fw="PCI", ref="PCI-DSS 10.5.3", sev="medium",
         title="Remote syslog / logging host configured", fn=chk_logging_host,
         remediation="Configure a remote syslog/logging host for off-box audit trails."),
    dict(id="ntp-sync", fw="CIS", ref="CIS NDM 8.5", sev="low",
         title="NTP / time synchronization enabled", fn=chk_ntp_sync,
         remediation="Configure and enable NTP servers so log timestamps are trustworthy."),
    dict(id="pw-encryption", fw="PCI", ref="PCI-DSS 8.3.1", sev="high",
         title="Stored credentials hashed/encrypted", fn=chk_pw_encryption,
         remediation="Enable password-encryption and use strong secret hashes; remove cleartext."),
    dict(id="default-creds", fw="PCI", ref="PCI-DSS 2.1", sev="high",
         title="No empty or default credentials", fn=chk_default_creds,
         remediation="Set a strong unique password for every local account; remove empty/defaults."),
    dict(id="mgmt-exposure", fw="CIS", ref="CIS NDM 3.1", sev="high",
         title="Management plane not exposed to any source", fn=chk_mgmt_exposure,
         remediation="Restrict SSH/mgmt ACL source to trusted admin subnets, not any."),
    dict(id="login-banner", fw="CIS", ref="CIS NDM 1.2", sev="low",
         title="Login / MOTD warning banner present", fn=chk_login_banner,
         remediation="Add an authorized-use login banner (legal/MOTD) on console and VTY."),
]


def run_checks(text: str, vendor: str = "") -> list[dict]:
    """Every check with pass/fail. Same shape whatever the vendor."""
    out = []
    for c in CHECKS:
        ok = bool(c["fn"](text or "", vendor or ""))
        out.append({"check_id": c["id"], "framework": c["fw"], "ref": c["ref"], "title": c["title"],
                    "severity": c["sev"], "status": "pass" if ok else "fail", "remediation": c["remediation"]})
    return out
