"""MITRE ATT&CK mapping.

Techniques are only emitted when the detection evidence genuinely supports
them (spec section 12).
"""
from __future__ import annotations

from typing import Any, Dict, List

TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "url": "https://attack.mitre.org/techniques/T1110/"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access / Persistence / Privilege Escalation",
              "url": "https://attack.mitre.org/techniques/T1078/"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
              "url": "https://attack.mitre.org/techniques/T1068/"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
              "url": "https://attack.mitre.org/techniques/T1548/"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection",
              "url": "https://attack.mitre.org/techniques/T1005/"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "Collection",
              "url": "https://attack.mitre.org/techniques/T1213/"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "url": "https://attack.mitre.org/techniques/T1046/"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "url": "https://attack.mitre.org/techniques/T1041/"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "url": "https://attack.mitre.org/techniques/T1021/"},
}

SUDO_MARKERS = ("sudo", "su -", "/bin/bash", "runas", "setuid")


def _entry(tid: str, confidence: float, evidence: List[str], detection_ids: List[str]) -> Dict[str, Any]:
    meta = TECHNIQUES[tid]
    return {
        "id": tid,
        "name": meta["name"],
        "tactic": meta["tactic"],
        "url": meta["url"],
        "confidence": round(confidence, 2),
        "evidence": [e for e in evidence if e],
        "detection_ids": detection_ids,
    }


def map_techniques(incident_ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    dets: List[Dict[str, Any]] = incident_ctx["detections"]
    events: List[Dict[str, Any]] = incident_ctx["events"]
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for d in dets:
        by_type.setdefault(d["type"], []).append(d)

    out: List[Dict[str, Any]] = []
    seen: set[str] = set()

    def push(entry: Dict[str, Any]) -> None:
        if entry["id"] in seen:
            return
        seen.add(entry["id"])
        out.append(entry)

    if "brute_force" in by_type:
        d = by_type["brute_force"][0]
        push(_entry("T1110", d["confidence"], d["evidence"][:3], [d["id"]]))

    if "account_compromise" in by_type:
        d = by_type["account_compromise"][0]
        push(_entry("T1078", d["confidence"],
                    ["Valid account used to authenticate after brute force", d["evidence"][0]], [d["id"]]))

    if "privilege_escalation" in by_type:
        d = by_type["privilege_escalation"][0]
        push(_entry("T1068", d["confidence"], d["evidence"][:3], [d["id"]]))
        cmds = [str((e.get("extra") or {}).get("command", "")) for e in events]
        if any(m in " ".join(cmds).lower() or m in " ".join(str(e.get("raw_message")) for e in events).lower()
               for m in SUDO_MARKERS):
            push(_entry("T1548", min(0.95, d["confidence"] + 0.02),
                        ["sudo / su elevation controls abused", "Elevated command execution observed"], [d["id"]]))

    if "sensitive_data_access" in by_type:
        d = by_type["sensitive_data_access"][0]
        push(_entry("T1005", d["confidence"], d["evidence"][:3], [d["id"]]))
        db_markers = ["select * from", "db=", "database", "postgres", "mysql", "mongodb"]
        blob = " ".join(
            str(e.get("raw_message")) + " " + " ".join(f"{k}={v}" for k, v in (e.get("extra") or {}).items())
            for e in events
        ).lower()
        if any(m in blob for m in db_markers):
            push(_entry("T1213", min(0.9, d["confidence"]),
                        ["Query executed against a production database", "Customer data retrieved"], [d["id"]]))

    if "reconnaissance" in by_type:
        d = by_type["reconnaissance"][0]
        push(_entry("T1046", d["confidence"], d["evidence"][:2], [d["id"]]))

    if "data_exfiltration" in by_type:
        d = by_type["data_exfiltration"][0]
        push(_entry("T1041", d["confidence"], d["evidence"][:3], [d["id"]]))

    return out
