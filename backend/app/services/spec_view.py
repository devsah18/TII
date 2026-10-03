"""Spec view adapter.

TRACE already builds rich incident objects in ``app.engines.incident``. This
module adds the *additional* field names required by the hackathon contract to
an incident dict WITHOUT removing or renaming any existing key, so the running
frontend keeps working while the spec-shaped fields are also present.

Nothing here runs an LLM or a network call: it is a pure, deterministic
projection of an already-computed incident.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _time_display(ts: Optional[str]) -> Optional[str]:
    return ts[11:19] if ts and len(ts) >= 19 else ts


def _initial_event(incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    events = incident.get("events") or []
    stamped = [e for e in events if e.get("timestamp")]
    if not stamped:
        return None
    first = min(stamped, key=lambda e: e["timestamp"])
    return {
        "event_id": first.get("id"),
        "time": first.get("timestamp"),
        "type": first.get("event_type"),
        "description": first.get("raw_message"),
        "source_ip": first.get("source_ip"),
        "username": first.get("username"),
    }


def _affected_resource(incident: Dict[str, Any]) -> Optional[str]:
    """First sensitive resource / destination touched by the incident."""
    for ev in incident.get("events") or []:
        extra = ev.get("extra") or {}
        name = extra.get("db") or extra.get("file") or extra.get("resource")
        if name:
            return str(name)
    for node in (incident.get("attack_graph") or {}).get("nodes", []):
        if node.get("type") == "resource":
            return node.get("label")
    hosts = incident.get("affected_hosts") or []
    return hosts[0] if hosts else None


def _evidence(incident: Dict[str, Any]) -> List[str]:
    """Event ids that make up the incident timeline (spec: evidence -> [event_id])."""
    return [t.get("event_id") for t in incident.get("timeline", []) if t.get("event_id")]


def _timeline(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Spec shape: [{time, type, description}]."""
    out: List[Dict[str, Any]] = []
    for t in incident.get("timeline", []):
        out.append(
            {
                "time": t.get("timestamp"),
                "type": t.get("event_type"),
                "description": t.get("description") or t.get("label"),
                "event_id": t.get("event_id"),
                "severity": t.get("severity"),
                "suspicious": t.get("suspicious"),
            }
        )
    return out


def _attack_chain(incident: Dict[str, Any]) -> List[str]:
    """Spec shape: attack_chain is a list of stage-label strings."""
    return [c.get("stage_label") or c.get("title") for c in incident.get("attack_chain", [])]


def _risk_breakdown(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Spec shape: [{factor, points, reason}] mapped from risk_factors."""
    out: List[Dict[str, Any]] = []
    for f in incident.get("risk_factors", []):
        evidence = f.get("evidence")
        if isinstance(evidence, list):
            reason = "; ".join(str(e) for e in evidence if e)
        else:
            reason = str(evidence or "")
        out.append(
            {
                "factor": f.get("name"),
                "points": f.get("points", 0),
                "reason": reason,
            }
        )
    return out


def _mitre(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Spec shape: [{technique_id, name, tactic, evidence_event_ids}].

    ``evidence_event_ids`` are resolved from the technique's detection ids back
    to the concrete event ids those detections cover.
    """
    det_by_id = {d.get("id"): d for d in incident.get("detections", [])}
    out: List[Dict[str, Any]] = []
    for t in incident.get("mitre_techniques", []):
        event_ids: List[str] = []
        for did in t.get("detection_ids", []):
            det = det_by_id.get(did)
            if det:
                event_ids.extend(det.get("event_ids") or [])
        # stable, de-duplicated, ordered
        seen: set[str] = set()
        deduped = [eid for eid in event_ids if not (eid in seen or seen.add(eid))]
        out.append(
            {
                "technique_id": t.get("id"),
                "name": t.get("name"),
                "tactic": t.get("tactic"),
                "evidence_event_ids": deduped,
                "confidence": t.get("confidence"),
                "evidence": t.get("evidence", []),
            }
        )
    return out


_PRIORITY_TO_GROUP = {"IMMEDIATE": "immediate", "INVESTIGATE": "investigation", "MONITOR": "monitoring"}


def _recommended_actions(incident: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Spec shape: {immediate:[], investigation:[], monitoring:[]}."""
    groups: Dict[str, List[Dict[str, Any]]] = {"immediate": [], "investigation": [], "monitoring": []}
    for a in incident.get("response_actions", []):
        key = _PRIORITY_TO_GROUP.get(a.get("priority"))
        if not key:
            continue
        groups[key].append(
            {
                "action": a.get("action"),
                "priority": a.get("priority"),
                "reason": a.get("reason"),
                "evidence": a.get("evidence", []),
            }
        )
    return groups


def add_spec_fields(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Return the SAME incident dict, enriched with spec-shaped alias fields.

    Existing keys are preserved untouched. Only new/aliased keys are added.
    Mutates and returns ``incident`` so the in-memory store keeps the enriched
    object for subsequent GETs.
    """
    if incident.get("_spec_view"):
        return incident

    incident["initial_event"] = _initial_event(incident)
    incident["affected_account"] = incident.get("affected_user")
    incident["affected_resource"] = _affected_resource(incident)
    incident["evidence"] = _evidence(incident)
    incident["timeline_spec"] = _timeline(incident)
    incident["attack_chain_spec"] = _attack_chain(incident)
    incident["risk_breakdown"] = _risk_breakdown(incident)
    incident["mitre"] = _mitre(incident)
    incident["recommended_actions"] = _recommended_actions(incident)
    incident["_spec_view"] = True
    return incident