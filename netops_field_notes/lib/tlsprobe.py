"""CertHerd active TLS probe — read the cert a host:port ACTUALLY serves.

Read-only: a TCP connect + a TLS handshake, nothing more. Reads the leaf even
when invalid/expired (unverified context), then does a second verifying pass to
record whether the chain/hostname would validate. Bounded concurrency + strict
per-target timeout. Connects ONLY to explicitly-declared targets (no sweeping)."""
from __future__ import annotations
import socket, ssl
from concurrent.futures import ThreadPoolExecutor


def _split(endpoint: str) -> tuple[str, int]:
    host, _, port = endpoint.rpartition(":")
    if not host:  # no port given
        return endpoint, 443
    return host, int(port)


def probe(endpoint: str, timeout: float = 6.0, sni: str | None = None) -> dict:
    host, port = _split(endpoint)
    sni = sni or host
    res = {"endpoint": endpoint, "host": host, "sni": sni, "ok": False,
           "verify_ok": None, "tls_version": None, "der": None, "error": None}
    lax = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    lax.check_hostname = False
    lax.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with lax.wrap_socket(sock, server_hostname=sni) as ss:
                res["der"] = ss.getpeercert(binary_form=True)
                res["tls_version"] = ss.version()
                res["ok"] = True
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"[:140]
        return res
    # second pass: would it validate (chain + hostname)?
    try:
        with socket.create_connection((host, port), timeout=timeout) as s2:
            with ssl.create_default_context().wrap_socket(s2, server_hostname=sni):
                res["verify_ok"] = True
    except ssl.SSLCertVerificationError:
        res["verify_ok"] = False
    except Exception:
        res["verify_ok"] = None  # transient / non-TLS reason; don't claim a verdict
    return res


def probe_many(endpoints, timeout: float = 6.0, workers: int = 32) -> list[dict]:
    endpoints = list(dict.fromkeys(endpoints))  # dedupe, keep order
    if not endpoints:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(endpoints))) as ex:
        return list(ex.map(lambda e: probe(e, timeout), endpoints))
