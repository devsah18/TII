"""Response plan generator.

Recommendations only. TRACE never executes a security action (spec section 14).
"""
from __future__ import annotations

from typing import Any, Dict, List

PRIORITY_META = {
    "IMMEDIATE": {"label": "IMMEDIATE", "icon": "🔴", "colour": "critical",
                  "timeframe": "Within the next 15 minutes"},
    "INVESTIGATE": {"label": "INVESTIGATE", "icon": "🟠", "colour": "warning",
                    "timeframe": "Within the next few hours"},
    "MONITOR": {"label": "MONITOR", "icon": "🟢", "colour": "safe",
                "timeframe": "Ongoing"},
}


def _action(priority: str, action: str, reason: str, evidence: List[str]) -> Dict[str, Any]:
    meta = PRIORITY_META[priority]
    return {
        "priority": priority,
        "priority_label": meta["label"],
        "icon": meta["icon"],
        "colour": meta["colour"],
        "timeframe": meta["timeframe"],
        "action": action,
        "reason": reason,
        "evidence": [e for e in evidence if e],
        "executed": False,
    }


def build_response_plan(incident_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    dets: List[Dict[str, Any]] = incident_ctx["detections"]
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for d in dets:
        by_type.setdefault(d["type"], []).append(d)

    out: List[Dict[str, Any]] = []
    src_ip = incident_ctx.get("source_ip")
    user = incident_ctx.get("username") or (incident_ctx.get("affected_users") or [None])[0]

    if "brute_force" in by_type and src_ip:
        d = by_type["brute_force"][0]
        out.append(_action(
            "IMMEDIATE",
            f"Block source IP {src_ip} at the perimeter",
            "The address is the confirmed origin of the authentication attack and is still a live threat vector.",
            d["evidence"][:2] + [f"External IP {src_ip}"],
        ))

    if "account_compromise" in by_type and user:
        d = by_type["account_compromise"][0]
        out.append(_action(
            "IMMEDIATE",
            f"Disable account {user} and force a password reset",
            "The account authenticated successfully after the brute-force burst, so it must be treated as controlled by the attacker.",
            d["evidence"][:3],
        ))
        out.append(_action(
            "IMMEDIATE",
            f"Revoke all active sessions and tokens for {user}",
            "An attacker holding valid credentials keeps access through existing sessions even after a password reset.",
            ["Successful authentication recorded before containment", f"Account {user} has elevated activity in this incident"],
        ))

    if "privilege_escalation" in by_type:
        d = by_type["privilege_escalation"][0]
        out.append(_action(
            "IMMEDIATE",
            "Revoke the newly granted privileged access",
            "Administrative or root privileges were obtained; leaving them in place allows full host compromise.",
            d["evidence"][:3],
        ))

    if "sensitive_data_access" in by_type:
        d = by_type["sensitive_data_access"][0]
        out.append(_action(
            "INVESTIGATE",
            "Review and audit the sensitive data access",
            "Determine exactly which records were read so the breach scope and notification obligations are known.",
            d["evidence"][:3],
        ))
        out.append(_action(
            "INVESTIGATE",
            "Rotate credentials and secrets for the touched systems",
            "Any credential reachable from the compromised account should be considered disclosed.",
            ["Sensitive resource access detected", "Credentials may have been exposed to the attacker"],
        ))

    if "data_exfiltration" in by_type:
        d = by_type["data_exfiltration"][0]
        out.append(_action(
            "INVESTIGATE",
            "Trace the outbound transfer and confirm what left the network",
            "Bulk outbound traffic indicates collection followed by exfiltration.",
            d["evidence"][:3],
        ))

    if user:
        out.append(_action(
            "INVESTIGATE",
            f"Check authentication history for {user} across all systems",
            "Establish whether the same credentials were reused elsewhere and when the anomaly began.",
            [f"Account {user} is the suspected compromised identity"],
        ))

    if src_ip:
        out.append(_action(
            "INVESTIGATE",
            f"Correlate {src_ip} against threat intelligence and VPN logs",
            "Identify whether the address is a known malicious host and whether it reached other services.",
            [f"{src_ip} appears in the auth and network logs"],
        ))

    if "reconnaissance" in by_type:
        d = by_type["reconnaissance"][0]
        out.append(_action(
            "MONITOR",
            "Watch for renewed scanning from the same source",
            "Reconnaissance usually repeats before a second attempt.",
            d["evidence"][:2],
        ))

    out.append(_action(
        "MONITOR",
        "Increase alerting sensitivity on authentication failures",
        "Early warning on renewed bursts shortens detection time for a repeat attempt.",
        ["Brute-force pattern detected in this incident"],
    ))
    if src_ip:
        out.append(_action(
            "MONITOR",
            "Monitor related external IP addresses and destinations",
            "Attacker infrastructure is often rotated within the same address range.",
            [f"{src_ip} is the primary malicious source"],
        ))

    # de-duplicate while keeping priority order
    seen = set()
    unique: List[Dict[str, Any]] = []
    for a in out:
        key = a["action"].lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(a)
    rank = {"IMMEDIATE": 0, "INVESTIGATE": 1, "MONITOR": 2}
    unique.sort(key=lambda a: rank.get(a["priority"], 3))
    for idx, a in enumerate(unique):
        a["id"] = f"ACT-{idx + 1:03d}"
    return unique
