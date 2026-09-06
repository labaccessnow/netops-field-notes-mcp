"""CertHerd findings engine — deterministic rules over a cert record, producing
risk-tagged findings. Severity is CONTEXT-AWARE (a self-signed cert on an internal
switch GUI is info; on a public endpoint it's high). Under-alert before over-alert:
every finding carries a confidence, and unknown fields are reported, never guessed."""
from __future__ import annotations
import time

# Compliance floors (fact-checked): RSA-2048/SHA-256 (NIST SP 800-131A);
# SHA-1/MD5 deprecated; public cert validity cap 398d heading to 47d by 2029 (cabforum.org).
WEAK_SIG = {"MD5", "SHA1"}
EXPIRY_SEVERITY = [(-10**9, "high"), (0, "high"), (7, "high"), (14, "medium"), (30, "low")]


def days_left(rec, now=None):
    return int(((rec["not_after"]) - (now or time.time())) // 86400)


def _f(cat, risk, rec, summary, remediation, why, days, endpoint, confidence=0.9):
    return {"category": cat, "risk": risk, "summary": summary, "remediation": remediation,
            "why": why, "days_left": days, "endpoint": endpoint, "confidence": confidence,
            "fingerprint": rec["fingerprint"], "subject": rec.get("subject_cn") or "(no CN)"}


def _san_match(host: str, names) -> bool:
    host = host.lower().strip(".")
    if not host or not names:
        return False
    for n in names:
        n = n.lower().strip(".")
        if n == host:
            return True
        if n.startswith("*."):  # single-label wildcard
            base = n[2:]
            if host.endswith("." + base) and host.count(".") == base.count(".") + 1:
                return True
    return False


def findings_for(rec: dict, role: str = "", endpoint: str | None = None,
                 verify_ok=None, now=None) -> list[dict]:
    """Return all findings for one cert. `endpoint` set => it was actively served
    (raises self-signed/SAN severity); None => discovered in a config."""
    now = now or time.time()
    role = (role or "").lower()
    public_facing = bool(endpoint) and any(k in role for k in ("edge", "wan", "firewall", "fw", "vpn", "lb"))
    out, d = [], days_left(rec, now)

    if d <= 30:
        sev = next(s for thr, s in EXPIRY_SEVERITY if d <= thr)
        state = "EXPIRED" if d < 0 else f"expires in {d}d"
        out.append(_f("expiry", sev, rec, f"{rec.get('subject_cn') or 'cert'} {state}",
                      "Renew/rotate before expiry; confirm the serving daemon reloads the new cert.",
                      "An expired cert breaks TLS/auth — on gear like ISE one cert can drop all 802.1X.",
                      d, endpoint, 0.98))

    if rec.get("key_type") == "RSA" and rec.get("key_bits") and rec["key_bits"] < 2048:
        out.append(_f("weak-key", "high", rec, f"Weak RSA key ({rec['key_bits']}-bit) — {rec.get('subject_cn')}",
                      "Reissue with RSA-2048+ or ECDSA P-256.",
                      "Sub-2048 RSA is below the NIST floor and fails PCI/CIS crypto checks.", d, endpoint))

    sig = (rec.get("sig_algo") or "").replace("-", "").upper()
    if sig in WEAK_SIG:
        out.append(_f("weak-sig", "high", rec, f"Weak signature algorithm ({rec.get('sig_algo')}) — {rec.get('subject_cn')}",
                      "Reissue with a SHA-256+ signature.",
                      "MD5/SHA-1 signatures are forgeable and distrusted by modern clients.", d, endpoint))

    if rec.get("self_signed") and not rec.get("is_ca"):
        if public_facing:
            sev, conf = "high", 0.9
        elif endpoint:
            sev, conf = "medium", 0.8
        else:
            sev, conf = "low", 0.6  # config-only internal self-signed is often intentional
        out.append(_f("self-signed", sev, rec, f"Self-signed certificate — {rec.get('subject_cn')}",
                      "Replace with a CA-issued cert on anything externally reachable; allowlist known internal CAs.",
                      "Self-signed certs can't be validated by clients and mask MITM.", d, endpoint, conf))

    if endpoint and verify_ok is False:
        host = endpoint.rsplit(":", 1)[0]
        names = set(rec.get("sans") or []) or ({rec["subject_cn"]} if rec.get("subject_cn") else set())
        if host and not _san_match(host, names):
            out.append(_f("san-mismatch", "high", rec, f"Served hostname '{host}' not in cert SANs {sorted(names)}",
                          "Add the hostname to the SAN, or serve the matching cert on this endpoint.",
                          "A name mismatch means clients get cert errors (or the wrong service answered).",
                          d, endpoint))

    if rec.get("is_ca") and d <= 90:
        out.append(_f("ca-expiry", "high", rec, f"Internal CA expiring in {d}d — {rec.get('subject_cn')}",
                      "Plan CA renewal/cross-sign now; an expiring root/intermediate invalidates everything it signed.",
                      "A silent CA expiry is a fleet-wide outage, not a single-cert one.", d, endpoint, 0.95))
    return out
