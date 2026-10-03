"""Risk engine: a transparent 0-100 score with itemised factors."""
from __future__ import annotations

from typing import Any, Dict, List

from .detection import SEVERITY_ORDER, max_severity

SEVERITY_THRESHOLDS = ((85, "critical"), (70, "high"), (45, "medium"), (20, "low"))

FACTOR_POINTS = {
    "repeated_auth_failures": 25,
    "success_after_failures": 20,
    "privilege_escalation": 20,
    "sensitive_data_access": 20,
    "suspicious_external_ip": 15,
}

# points awarded for factors the spec does not list, capped so the total stays honest
EXTRA_POINTS = {
    "reconnaissance": 8,
    "data_exfiltration": 25,
    "secret_exposure": 10,
}

SECRET_MARKERS = ("credential", "secret", "password", "token", "keyvault", "etc/shadow", ".env")


def severity_from_score(score: int) -> str:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "info"


def calculate(incident_ctx: Dict[str, Any]) -> Dict[str, Any]:
    dets: List[Dict[str, Any]] = incident_ctx["detections"]
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for d in dets:
        by_type.setdefault(d["type"], []).append(d)

    factors: List[Dict[str, Any]] = []

    def add(name: str, points: int, evidence: str, detection_ids: List[str] | None = None) -> None:
        factors.append(
            {
                "name": name,
                "points": points,
                "max_points": points,
                "evidence": evidence,
                "detection_ids": detection_ids or [],
            }
        )

    if "brute_force" in by_type:
        d = by_type["brute_force"][0]
        n = len(d["event_ids"])
        add("Repeated authentication failures", FACTOR_POINTS["repeated_auth_failures"],
            d["evidence"][0] if d["evidence"] else f"{n} failed attempts", [d["id"]])

    if "account_compromise" in by_type:
        d = by_type["account_compromise"][0]
        user = d.get("username") or "an account"
        add("Successful login after repeated failures", FACTOR_POINTS["success_after_failures"],
            f"Account {user} authenticated successfully immediately after the failed attempts", [d["id"]])

    if "privilege_escalation" in by_type:
        d = by_type["privilege_escalation"][0]
        add("Privilege escalation", FACTOR_POINTS["privilege_escalation"],
            d["evidence"][0] if d["evidence"] else "Administrative privileges obtained", [d["id"]])

    if "sensitive_data_access" in by_type:
        d = by_type["sensitive_data_access"][0]
        add("Sensitive data access", FACTOR_POINTS["sensitive_data_access"],
            d["description"], [d["id"]])

    if "suspicious_source_ip" in by_type:
        d = by_type["suspicious_source_ip"][0]
        ip = d.get("source_ip") or "external address"
        add("Suspicious external source IP", FACTOR_POINTS["suspicious_external_ip"],
            f"{ip} is an external address and the origin of the detected activity", [d["id"]])

    if "reconnaissance" in by_type:
        d = by_type["reconnaissance"][0]
        add("Pre-attack reconnaissance", EXTRA_POINTS["reconnaissance"],
            d["evidence"][0] if d["evidence"] else "Scanning activity observed", [d["id"]])

    if "data_exfiltration" in by_type:
        d = by_type["data_exfiltration"][0]
        add("Bulk outbound data transfer", EXTRA_POINTS["data_exfiltration"],
            " / ".join(d["evidence"][:2]), [d["id"]])

    # credential/secret exposure is scored separately from the data-store access
    secret_events = [
        e for e in incident_ctx["events"]
        if any(m in (str(e.get("raw_message") or "") + " " + " ".join(f"{k}={v}" for k, v in (e.get("extra") or {}).items())).lower()
               for m in SECRET_MARKERS)
    ]
    if secret_events:
        add("Credential or secret exposure", EXTRA_POINTS["secret_exposure"],
            f"{len(secret_events)} event(s) touch credentials, secrets or protected files",
            [f"{secret_events[0]['id']}"])

    raw = sum(f["points"] for f in factors)
    score = max(0, min(100, raw))

    confidence = 0.0
    if dets:
        weighted = [SEVERITY_ORDER.get(d["severity"], 1) + 1 for d in dets]
        total_w = sum(weighted)
        confidence = sum(d["confidence"] * w for d, w in zip(dets, weighted)) / total_w
    confidence = round(min(0.99, max(0.05, confidence)), 2)

    band = severity_from_score(score)
    severity = band
    # An incident is never rated milder than its strongest single finding: a
    # confirmed account compromise is critical even if the additive score is not
    # yet in the critical band. The explanation below states when this applies.
    for d in dets:
        severity = max_severity(severity, d["severity"])

    return {
        "score": score,
        "raw_score": raw,
        "capped": raw > 100,
        "severity": severity,
        "confidence": confidence,
        "factors": factors,
        "band": band,
        "severity_floor_applied": SEVERITY_ORDER[severity] > SEVERITY_ORDER[band],
        "explanation": _explain(score, raw, factors, severity, band),
    }


def _explain(score: int, raw: int, factors: List[Dict[str, Any]], severity: str, band: str) -> str:
    if not factors:
        return "No risk factors were triggered: nothing in this log matched a detection rule."
    parts = [f"{f['name']} (+{f['points']})" for f in factors]
    text = "Risk is the sum of the triggered factors: " + ", ".join(parts) + f". Raw total {raw}"
    if raw > 100:
        text += ", clamped to the 100-point maximum."
    else:
        text += "."
    text += f" Final score {score}/100."
    if severity != band:
        text += (
            f" The score falls in the {band} band, but severity is raised to {severity} because the"
            " incident contains a finding of that severity (a confirmed compromise outranks the additive score)."
        )
    else:
        text += f" Severity {severity}."
    return text
