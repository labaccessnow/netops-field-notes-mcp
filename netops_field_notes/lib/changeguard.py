"""Read-only pre-flight for a proposed config change: what changes, how risky, which
compliance checks regress, and who else shares the affected segments. Nothing here
touches a device — the write path stays with the product.
"""
from __future__ import annotations
from . import inventory
from .checks import run_checks
from .pipeline import explain, structured_diff

_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def compliance_delta(current: str, proposed: str, vendor: str) -> dict:
    """Checks that pass now but fail after (regressions), and the reverse (fixes)."""
    def fails(text):
        return {f["check_id"] for f in run_checks(text, vendor) if f["status"] == "fail"}
    bf, af = fails(current), fails(proposed)
    titles = {f["check_id"]: f["title"] for f in run_checks(proposed, vendor)}
    return {"regressions": [titles.get(c, c) for c in sorted(af - bf)],
            "fixes": [titles.get(c, c) for c in sorted(bf - af)]}


def blast_radius(device: str, current: str, fleet: dict[str, str] | None) -> list[tuple[str, list[str]]]:
    """Other devices that share this device's L2/L3 segments — who a mistake here could
    also affect. `fleet` is {name: config_text} for the other devices you know about."""
    if not fleet:
        return []
    me = inventory.extract(current, "", device)
    my_nets, my_vlans = set(me.get("nets") or []), set(me.get("vlans") or [])
    if not (my_nets or my_vlans):
        return []
    hits = []
    for name, text in fleet.items():
        if name == device or not text:
            continue
        f = inventory.extract(text, "", name)
        shared = (my_nets & set(f.get("nets") or [])) | {f"VLAN {v}" for v in (my_vlans & set(f.get("vlans") or []))}
        if shared:
            hits.append((name, sorted(str(s) for s in shared)))
    return hits


def preflight(current: str, proposed: str, device: str, vendor: str, fleet: dict[str, str] | None = None,
              explain_fn=None) -> dict:
    explain_fn = explain_fn or (lambda h: explain(h, device, vendor))
    hunks = structured_diff(current, proposed, vendor)
    changes, max_risk = [], "low"
    for h in hunks:
        ex = explain_fn(h) or explain(h, device, vendor)
        changes.append({**h, **ex})
        if _RANK.get(ex["risk"], 0) > _RANK.get(max_risk, 0):
            max_risk = ex["risk"]
    comp = compliance_delta(current, proposed, vendor)
    blast = blast_radius(device, current, fleet)
    if max_risk == "critical":
        gate = ("BLOCK", "Critical-risk change — do not apply without senior review and a maintenance window.")
    elif max_risk == "high" or comp["regressions"]:
        gate = ("REVIEW REQUIRED", "High-risk change and/or a compliance regression — needs approval and a rollback ready.")
    elif changes:
        gate = ("PROCEED WITH CARE", "Lower-risk change — apply in a window with the rollback snapshot ready.")
    else:
        gate = ("NO CHANGE", "The proposed config is identical to the current one once volatile lines are removed.")
    return {"device": device, "vendor": vendor, "max_risk": max_risk, "gate": gate, "changes": changes,
            "compliance": comp, "blast": blast,
            "rollback": f"The current config ({len((current or '').splitlines())} lines) is the rollback: keep it where you can restore it before you apply."}
