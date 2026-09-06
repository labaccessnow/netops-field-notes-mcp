"""CertHerd cert plumbing — decode a cert (DER) into a uniform record, and pull
certs out of device configs. STDLIB-FIRST: expiry/subject/issuer/SANs via the
stdlib ssl decoder (zero-install); key-bits/sig-algo/is_ca via `cryptography`
ONLY if it's installed (graceful 'unknown' otherwise — never silently wrong)."""
from __future__ import annotations
import base64, hashlib, re, ssl, os, tempfile

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def der_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def pem_to_der(pem: str) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem)


def _first_cn(rdn_seq) -> str:
    """subject/issuer from the ssl decoder = ((((k,v),),),...). Prefer CN, else O."""
    cn = org = ""
    for rdn in rdn_seq or ():
        for k, v in rdn:
            if k == "commonName" and not cn:
                cn = v
            elif k == "organizationName" and not org:
                org = v
    return cn or org or ""


def record_from_der(der: bytes) -> dict | None:
    """Decode DER bytes into a uniform cert record, or None if undecodable."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            os.write(fd, pem.encode())
            os.close(fd)
            info = ssl._ssl._test_decode_cert(path)  # stdlib, zero-install
        finally:
            os.unlink(path)
    except Exception:
        return None
    try:
        nb = ssl.cert_time_to_seconds(info["notBefore"])
        na = ssl.cert_time_to_seconds(info["notAfter"])
    except Exception:
        return None
    sans = sorted({v for t, v in info.get("subjectAltName", ()) if t == "DNS"})
    rec = {
        "fingerprint": der_sha256(der),
        "subject_cn": _first_cn(info.get("subject")),
        "issuer_cn": _first_cn(info.get("issuer")),
        "serial": info.get("serialNumber", ""),
        "not_before": nb, "not_after": na, "sans": sans,
        "self_signed": info.get("subject") == info.get("issuer"),
        "key_type": None, "key_bits": None, "sig_algo": None, "is_ca": None,
    }
    _enrich(der, rec)
    return rec


def _enrich(der: bytes, rec: dict) -> None:
    """Optional fidelity via `cryptography`: key type/bits, sig algo, CA flag."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        c = x509.load_der_x509_certificate(der)
        pk = c.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            rec["key_type"], rec["key_bits"] = "RSA", pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            rec["key_type"], rec["key_bits"] = "EC", pk.curve.key_size
        elif isinstance(pk, dsa.DSAPublicKey):
            rec["key_type"], rec["key_bits"] = "DSA", pk.key_size
        try:
            rec["sig_algo"] = c.signature_hash_algorithm.name.upper()
        except Exception:
            rec["sig_algo"] = None
        try:
            rec["is_ca"] = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except Exception:
            rec["is_ca"] = False
    except Exception:
        pass  # cryptography absent → key/sig stay None (reported as 'unknown')


def certs_from_config(text: str, vendor: str = "") -> list[bytes]:
    """Best-effort: pull every cert out of a device config snapshot as DER.
    Handles inline PEM (most vendors) + OPNsense XML <crt> base64-of-PEM."""
    ders, seen = [], set()

    def _add(der):
        h = der_sha256(der)
        if der and h not in seen:
            seen.add(h); ders.append(der)

    for pem in _PEM_RE.findall(text):
        try:
            _add(pem_to_der(pem))
        except Exception:
            pass
    if "opnsense" in (vendor or "").lower() or "<opnsense" in text[:600]:
        for blob in re.findall(r"<crt>([A-Za-z0-9+/=\s]+)</crt>", text):
            try:
                decoded = base64.b64decode(blob.strip()).decode("utf-8", "ignore")
                for pem in _PEM_RE.findall(decoded):
                    _add(pem_to_der(pem))
            except Exception:
                pass
    return ders
