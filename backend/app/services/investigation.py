"""Investigation orchestrator: parse -> detect -> correlate -> risk -> incident."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..engines import correlation, detection, incident as incident_engine, parser
from ..utils.store import store


class InvestigationError(ValueError):
    pass


def analyze_events(
    events: List[Dict[str, Any]],
    *,
    source_file: Optional[Dict[str, Any]] = None,
    thresholds: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    detections = detection.detect(events, thresholds)
    detection.annotate_events(events, detections)

    if not detections:
        # still return a valid, honest incident object so the UI never breaks
        result = incident_engine.build_incident(
            incident_id=store.next_incident_id(),
            cluster={
                "detections": [],
                "event_ids": [e["id"] for e in events],
                "source_ip": None,
                "username": None,
                "affected_users": [],
                "first_seen": min((e["timestamp"] for e in events if e.get("timestamp")), default=None),
                "last_seen": max((e["timestamp"] for e in events if e.get("timestamp")), default=None),
            },
            events=events,
            source_file=source_file,
        )
        result["severity"] = "info"
        result["risk_score"] = 0
        result["confidence"] = 0.0
        result["risk_factors"] = []
        result["risk_explanation"] = (
            "No detection rule matched any event in this log. The absence of findings is not proof of "
            "a clean environment — review the parsed events manually if this is unexpected."
        )
        result["no_findings"] = True
        return result

    clusters = correlation.correlate(detections)
    primary = clusters[0]
    extra_clusters = clusters[1:]

    result = incident_engine.build_incident(
        incident_id=store.next_incident_id(),
        cluster=primary,
        events=events,
        source_file=source_file,
    )
    result["related_incidents"] = [
        {
            "cluster_index": idx + 2,
            "severity": c["severity"],
            "detection_types": c["detection_types"],
            "source_ip": c["source_ip"],
            "event_count": len(c["event_ids"]),
            "first_seen": c["first_seen"],
        }
        for idx, c in enumerate(extra_clusters)
    ]
    result["correlation"] = {
        "clusters_found": len(clusters),
        "detections_total": len(detections),
        "detections_correlated": len(primary["detections"]),
        "note": (
            f"{len(detections)} detection(s) were correlated into {len(clusters)} incident(s); "
            "detections sharing a source IP, account or destination were merged."
        ),
    }
    return result


def investigate_file(file_id: str) -> Dict[str, Any]:
    record = store.get_file(file_id)
    if not record:
        raise InvestigationError(
            f"Unknown file_id {file_id!r}. Upload the log again or start from a demo scenario."
        )
    if record.get("parsed_error"):
        raise InvestigationError(record["parsed_error"])

    # Idempotency: if this file was already investigated (POST /api/upload now
    # auto-generates the incident), return the SAME incident instead of creating
    # a duplicate. This keeps the UI flow (upload then investigate) consistent.
    existing_id = record.get("incident_id")
    if existing_id:
        existing = store.get_incident(existing_id)
        if existing:
            return existing

    events = record.get("events")
    if not events:
        raise InvestigationError("No events were available for this file. Re-upload the log to parse it again.")

    result = analyze_events(events, source_file={"file_id": file_id, "filename": record.get("filename")})
    store.put_incident(result)
    record["incident_id"] = result["incident_id"]
    store.log_activity(
        "investigation",
        f"Investigation {result['incident_id']} opened from {record.get('filename')}",
        {"incident_id": result["incident_id"], "risk_score": result["risk_score"]},
    )
    return result
