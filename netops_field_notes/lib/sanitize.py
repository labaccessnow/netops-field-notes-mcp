#!/usr/bin/env python3
"""
sanitize-config — scrub a network config BEFORE you paste it into a public AI tool.

Anonymizes, consistently (same value -> same placeholder, so the config still makes sense to the AI):
  - IPv4 addresses  -> RFC-5737 documentation IPs (203.0.113.x / 198.51.100.x / 192.0.2.x)
  - IPv6 addresses  -> 2001:db8::redacted
  - MAC addresses   -> RFC-7042 doc range (00:00:5e:00:53:xx / 0000.5e00.53xx)
  - hostnames       -> ROUTER / ROUTER-2 / ...
  - domain names    -> example.com         email addresses -> user@example.com
  - secrets: passwords, enable/user secrets, RADIUS/TACACS keys, IPsec PSKs, SNMP communities (incl. on
    snmp-server host), OSPF/BGP/NTP md5 digests, key-strings, Wi-Fi PSKs -> <REDACTED>
Subnet / wildcard masks (255.255.255.0, 0.0.0.255, 0.0.0.0 ...) are PRESERVED so the logic survives.

Usage:
  python3 sanitize_config.py router.cfg                 # -> sanitized config to stdout
  cat router.cfg | python3 sanitize_config.py           # from stdin
  python3 sanitize_config.py router.cfg -o clean.cfg     # to a file
  python3 sanitize_config.py router.cfg --report         # also print a scrub summary (to stderr)

This is a fast heuristic, NOT a guarantee. ALWAYS eyeball the output before you paste, and never run it
on your only copy of a secret. Part of "AI Prompts for Network Engineers" — labaccessnow.com
"""
import argparse
import re
import sys

_MASK_OCTETS = {0, 128, 192, 224, 240, 248, 252, 254, 255}


def _is_mask(ip):
    o = [int(x) for x in ip.split(".")]
    return all(0 <= x <= 255 for x in o) and all(x in _MASK_OCTETS for x in o)


def sanitize(text):
    counts = {}
    def bump(k):
        counts[k] = counts.get(k, 0) + 1

    # ---- multi-line key / certificate blocks FIRST (scrub the WHOLE block) ----
    def _block(m):
        bump("keyblock"); return m.group(1) + "\n<REDACTED-KEY/CERT-BLOCK>\n" + m.group(2)
    text = re.sub(r"(?s)(-----BEGIN [^-\n]+-----).*?(-----END [^-\n]+-----)", _block, text)
    text = re.sub(r"(?ims)(^[ \t]*certificate\b[^\n]*\n).*?(\n[ \t]*quit)", _block, text)
    text = re.sub(r"(?m)^[ \t]*[0-9A-Fa-f]{32,}[ \t]*$", "  <REDACTED-HEX>", text)

    # ---- IPv4 (skip masks/wildcards; map consistently to documentation ranges) ----
    doc_nets = ["203.0.113.", "198.51.100.", "192.0.2."]
    ip_map = {}
    def repl_ipv4(m):
        ip = m.group(0)
        if any(int(o) > 255 for o in ip.split(".")):
            return ip
        if ip in ("0.0.0.0", "255.255.255.255") or _is_mask(ip):
            return ip
        if ip not in ip_map:
            n = len(ip_map)
            ip_map[ip] = doc_nets[min(n // 254, len(doc_nets) - 1)] + str((n % 254) + 1)
            bump("ipv4")
        return ip_map[ip]
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", repl_ipv4, text)

    # ---- IPv6 (full 8-group OR anything containing ::) ----
    def repl_ipv6(m):
        bump("ipv6"); return "2001:db8::redacted"
    text = re.sub(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b", repl_ipv6, text)
    text = re.sub(r"\b[A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{0,4}){0,6}::[A-Fa-f0-9:]*\b", repl_ipv6, text)

    # ---- MAC addresses (colon/dash and Cisco dotted) -> RFC-7042 documentation range ----
    mac_map = {}
    def _mac(orig, dotted):
        if orig not in mac_map:
            v = (len(mac_map) % 254) + 1
            mac_map[orig] = ("0000.5e00.53%02x" % v) if dotted else ("00:00:5e:00:53:%02x" % v)
            bump("mac")
        return mac_map[orig]
    text = re.sub(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", lambda m: _mac(m.group(0), False), text)
    text = re.sub(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b", lambda m: _mac(m.group(0), True), text)

    # ---- hostnames ----
    def repl_host(m):
        bump("hostname")
        n = counts["hostname"]
        return m.group(1) + ("ROUTER" if n == 1 else "ROUTER-%d" % n)
    text = re.sub(r"(?im)^(\s*hostname\s+)\S+", repl_host, text)

    # ---- domain names & emails ----
    text = re.sub(r"(?im)(\b(?:ip\s+)?domain[- ]name\s+)\S+",
                  lambda m: (bump("domain"), m.group(1) + "example.com")[1], text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                  lambda m: (bump("email"), "user@example.com")[1], text)

    # ---- secrets / keys / communities (broad, ordered) ----
    secret_patterns = [
        r"(?im)(\busername\s+\S+\s+(?:privilege\s+\d+\s+)?(?:password|secret)\s+(?:\d+\s+)?)\S+",
        r"(?im)((?:^|\s)[\w-]*(?:password|passwd|secret|key-string)\s+(?:enc\s+)?(?:\d+\s+)?)\S+",  # incl. encrypted-password, Forti 'passwd ENC'
        r"(?im)((?:radius-server|tacacs-server|tacacs)\b[^\n]*?\bkey\s+(?:\d+\s+)?)\S+",   # RADIUS/TACACS key
        r"(?im)((?:isakmp\s+key|pre-shared-key|presharedkey|ppk)\s+(?:address\s+)?(?:\d+\s+)?)\S+",  # IPsec PSK
        r"(?im)((?:md5|hmac-sha[\w-]*)\s+(?:\d+\s+)?)\S+",                                 # OSPF/BGP/NTP digest
        r"(?im)((?:wpa-psk|psk|set-key)\s+(?:ascii|hex)\s+\d+\s+)\S+",                     # Wi-Fi PSK
        r"(?im)(\bkey\s+(?:0|7|ascii|hex)\s+)\S+",                                          # key <enc> SECRET
        r"(?im)(\bsnmp-server\s+community\s+)\S+",                                          # SNMP community
        r"(?im)(^\s*snmp-server\s+host\s+.*\s)\S+\s*$",                                     # snmp host trailing community
    ]
    for pat in secret_patterns:
        text = re.sub(pat, lambda m: (bump("secret"), m.group(1) + "<REDACTED>")[1], text)

    # ---- unix/crypt hashes ($1$/$5$/$6$/$2y$/$9$...), PA 'phash', XML secret elements ----
    text = re.sub(r"\$\w{1,3}\$[^\s\"'<>]{4,}", lambda m: (bump("hash"), "<REDACTED-HASH>")[1], text)
    text = re.sub(r"(?im)(\bphash\s+)\S+", lambda m: (bump("secret"), m.group(1) + "<REDACTED>")[1], text)
    text = re.sub(r"(?is)<(phash|secret|key|md5|passwd|psk)>.*?</\1>",
                  lambda m: (bump("secret"), "<%s>REDACTED</%s>" % (m.group(1), m.group(1)))[1], text)

    return text, counts


def main():
    ap = argparse.ArgumentParser(description="Scrub a network config before pasting it into a public AI tool.")
    ap.add_argument("file", nargs="?", help="config file (default: stdin)")
    ap.add_argument("-o", "--out", help="write sanitized config here (default: stdout)")
    ap.add_argument("--report", action="store_true", help="print a scrub summary to stderr")
    a = ap.parse_args()

    raw = open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
    clean, counts = sanitize(raw)

    (open(a.out, "w", encoding="utf-8").write(clean) if a.out else sys.stdout.write(clean))
    if a.report or a.out:
        total = sum(counts.values())
        summary = ", ".join("%s:%d" % (k, v) for k, v in sorted(counts.items())) or "nothing matched"
        sys.stderr.write("\n[sanitized] %d item(s) scrubbed (%s). "
                         "Eyeball the output before you paste — this is a heuristic.\n" % (total, summary))


if __name__ == "__main__":
    main()
