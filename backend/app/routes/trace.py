"""HTTP routes. The paths here are the contract from spec section 16."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from ..config import ALLOWED_EXTENSIONS, LLM_API_KEY, MAX_UPLOAD_BYTES, SERVICE_NAME, VERSION
from ..engines import demo, parser, pcap
from ..models.schemas import (
    ChatRequest,
    HealthResponse,
    InvestigateQuestionRequest,
    InvestigateRequest,
    SimulateRequest,
    UploadResponse,
)
from ..services import chat as chat_service
from ..services import investigation as investigation_service
from ..services import live_capture as live_service
from ..utils.security import UploadValidationError, sanitize_filename, validate_upload
from ..utils.store import store

router = APIRouter(prefix="/api", tags=["trace"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service=SERVICE_NAME, version=VERSION)


# ---------------------------------------------------------------------------
# upload
# ---------------------------------------------------------------------------
@router.post("/upload", response_model=UploadResponse)
async def upload(file: UploadFile = File(...)) -> UploadResponse:
    raw = await file.read()
    size = len(raw)
    safe_name = sanitize_filename(file.filename)

    try:
        validate_upload(safe_name, size, raw)
    except UploadValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    file_id = store.next_file_id("FILE")
    is_pcap = Path(safe_name).suffix.lower() in pcap.PCAP_EXTENSIONS

    try:
        if is_pcap:
            # Packet capture: tshark -> normalized network events.
            events = pcap.parse_pcap_bytes(raw, safe_name)
        else:
            text = raw.decode("utf-8", errors="replace")
            events = parser.parse_log(text, safe_name)
    except parser.ParseError as exc:
        store.put_file(
            file_id,
            {"filename": safe_name, "size_bytes": size, "events": [], "parsed_error": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc))

    summary = parser.summarize_parse(events)
    store.put_file(
        file_id,
        {
            "filename": safe_name,
            "size_bytes": size,
            "events": events,
            "summary": summary,
            "parsed_error": None,
        },
    )
    store.log_activity("upload", f"Uploaded {safe_name}", {"file_id": file_id, "events": len(events)})

    # Auto-generate an incident from the uploaded log so a single upload call
    # both parses AND reconstructs the incident (spec Feature 1). The file is
    # still stored above, so a later POST /api/investigate {file_id} also works.
    incident = investigation_service.analyze_events(
        events, source_file={"file_id": file_id, "filename": safe_name}
    )
    store.put_incident(incident)
    # Link the file to its incident so a later POST /api/investigate {file_id}
    # returns THIS incident instead of creating a duplicate.
    record = store.get_file(file_id)
    if record is not None:
        record["incident_id"] = incident["incident_id"]
    store.record_run(
        source="pcap" if is_pcap else "upload",
        label=safe_name,
        incident_id=incident["incident_id"],
        risk_score=incident["risk_score"],
        severity=incident["severity"],
        event_count=len(events),
        detection_count=incident.get("detection_count", 0),
        mitre_count=len(incident.get("mitre_techniques", [])),
        stages=_pipeline_stages(
            len(events), incident.get("detection_count", 0),
            len(incident.get("mitre_techniques", [])), incident["incident_id"],
        ),
        extra={"file_id": file_id, "filename": safe_name},
    )
    store.log_activity(
        "investigation",
        f"Investigation {incident['incident_id']} opened from {safe_name}",
        {"incident_id": incident["incident_id"], "risk_score": incident["risk_score"]},
    )

    return UploadResponse(
        success=True,
        file_id=file_id,
        filename=safe_name,
        event_count=len(events),
        size_bytes=size,
        parsing_status="parsed",
        incident=incident,
    )


# ---------------------------------------------------------------------------
# investigate
# ---------------------------------------------------------------------------
@router.post("/investigate")
def investigate(payload: InvestigateQuestionRequest) -> Dict[str, Any]:
    """Reconstruct an incident and/or answer a question about it.

    - ``{file_id}``               -> rebuild the incident for an uploaded file
    - ``{incident_id}``           -> re-open a stored incident
    - ``{incident_id, question}`` -> AI investigator answer (Feature 3)

    The AI answer is grounded ONLY in the stored incident JSON; with no API key
    (or on error) a deterministic template answerer replies instead.
    """
    incident = None

    if payload.incident_id:
        incident = store.get_incident(payload.incident_id)
        if not incident:
            raise HTTPException(
                status_code=404, detail=f"Incident {payload.incident_id!r} not found."
            )
    elif payload.file_id:
        try:
            incident = investigation_service.investigate_file(payload.file_id)
        except investigation_service.InvestigationError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}")

    question = (payload.question or "").strip()

    # Question-only or question+incident -> AI investigator answer.
    if question and incident:
        result = chat_service.answer_question(incident, question)
        return {
            "success": True,
            "incident": incident,
            "answer": result["answer"],
            "sources": result["sources"],
            "mode": result.get("mode"),
            "intent": result.get("intent"),
        }

    if incident is None:
        raise HTTPException(
            status_code=400,
            detail="Provide file_id or incident_id (and optionally a question).",
        )

    return {"success": True, "incident": incident}


@router.post("/reanalyze")
def reanalyze(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Re-run detection on a stored file with tuned thresholds.

    Body: ``{"file_id": "...", "thresholds": {"brute_force_min_failures": 3}}``

    This is the Detection Rule Tuning feature: the analyst can move the
    thresholds and immediately see the incident (and its risk score) change.
    The underlying rules are the same deterministic code — only the knobs move.
    """
    file_id = payload.get("file_id")
    thresholds = payload.get("thresholds") or {}
    if not file_id:
        raise HTTPException(status_code=400, detail="file_id is required.")
    record = store.get_file(file_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"File {file_id!r} not found.")
    events = record.get("events") or []
    if not events:
        raise HTTPException(status_code=400, detail="No events available for this file.")

    incident = investigation_service.analyze_events(
        events,
        source_file={"file_id": file_id, "filename": record.get("filename")},
        thresholds=thresholds,
    )
    incident["tuned_thresholds"] = thresholds
    store.put_incident(incident)
    store.record_run(
        source="reanalyze",
        label=f"Tuning on {record.get('filename')}",
        incident_id=incident["incident_id"],
        risk_score=incident["risk_score"],
        severity=incident["severity"],
        event_count=len(events),
        detection_count=incident.get("detection_count", 0),
        mitre_count=len(incident.get("mitre_techniques", [])),
        stages=_pipeline_stages(
            len(events), incident.get("detection_count", 0),
            len(incident.get("mitre_techniques", [])), incident["incident_id"],
        ),
        extra={"thresholds": thresholds, "file_id": file_id},
    )
    return {"success": True, "incident": incident, "thresholds": thresholds}


# ---------------------------------------------------------------------------
# simulate
# ---------------------------------------------------------------------------
@router.get("/simulate")
def simulate_catalog() -> Dict[str, Any]:
    return {"success": True, "scenarios": demo.scenario_catalog()}


@router.post("/simulate")
def simulate(payload: SimulateRequest) -> Dict[str, Any]:
    scenario = (payload.scenario or "brute_force").strip().lower()
    if scenario not in demo.SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario {scenario!r}. Available: {', '.join(demo.SCENARIOS)}.",
        )

    text = demo.generate_log_text(scenario)
    events = parser.parse_log(text, f"demo_{scenario}.log")
    file_id = store.next_file_id("DEMO")
    store.put_file(
        file_id,
        {
            "filename": f"demo_{scenario}.log",
            "size_bytes": len(text.encode()),
            "events": events,
            "summary": parser.summarize_parse(events),
            "parsed_error": None,
            "scenario": scenario,
            "raw_text": text,
        },
    )

    incident = investigation_service.analyze_events(
        events, source_file={"file_id": file_id, "filename": f"demo_{scenario}.log", "scenario": scenario}
    )
    store.put_incident(incident)
    record = store.get_file(file_id)
    if record is not None:
        record["incident_id"] = incident["incident_id"]
    store.log_activity(
        "simulation",
        f"Simulated {demo.SCENARIOS[scenario]['name']}",
        {"file_id": file_id, "incident_id": incident["incident_id"], "risk_score": incident["risk_score"]},
    )
    store.record_run(
        source="simulation",
        label=demo.SCENARIOS[scenario]["name"],
        incident_id=incident["incident_id"],
        risk_score=incident["risk_score"],
        severity=incident["severity"],
        event_count=len(events),
        detection_count=incident.get("detection_count", 0),
        mitre_count=len(incident.get("mitre_techniques", [])),
        stages=_pipeline_stages(
            len(events), incident.get("detection_count", 0),
            len(incident.get("mitre_techniques", [])), incident["incident_id"],
        ),
        extra={"scenario": scenario, "file_id": file_id},
    )
    return {
        "success": True,
        "file_id": file_id,
        "scenario": scenario,
        "scenario_name": demo.SCENARIOS[scenario]["name"],
        "event_count": len(events),
        "incident": incident,
    }


@router.get("/scenarios")
def list_scenarios() -> Dict[str, Any]:
    """List the built-in demo scenarios (spec Feature 1)."""
    return {"success": True, "scenarios": demo.scenario_catalog()}


@router.post("/scenarios/{name}/load")
def load_scenario(name: str) -> Dict[str, Any]:
    """Generate, parse and reconstruct an incident for a named scenario.

    Thin wrapper over ``demo.generate_log_text`` plus the existing pipeline, so
    the deterministic detection/correlation/risk/MITRE engines are reused as-is.
    """
    scenario = (name or "").strip().lower()
    if scenario not in demo.SCENARIOS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario {scenario!r}. Available: {', '.join(demo.SCENARIOS)}.",
        )

    text = demo.generate_log_text(scenario)
    events = parser.parse_log(text, f"demo_{scenario}.log")
    file_id = store.next_file_id("DEMO")
    store.put_file(
        file_id,
        {
            "filename": f"demo_{scenario}.log",
            "size_bytes": len(text.encode()),
            "events": events,
            "summary": parser.summarize_parse(events),
            "parsed_error": None,
            "scenario": scenario,
            "raw_text": text,
        },
    )
    incident = investigation_service.analyze_events(
        events,
        source_file={"file_id": file_id, "filename": f"demo_{scenario}.log", "scenario": scenario},
    )
    store.put_incident(incident)
    record = store.get_file(file_id)
    if record is not None:
        record["incident_id"] = incident["incident_id"]
    store.log_activity(
        "simulation",
        f"Loaded scenario {demo.SCENARIOS[scenario]['name']}",
        {"file_id": file_id, "incident_id": incident["incident_id"], "risk_score": incident["risk_score"]},
    )
    store.record_run(
        source="simulation",
        label=demo.SCENARIOS[scenario]["name"],
        incident_id=incident["incident_id"],
        risk_score=incident["risk_score"],
        severity=incident["severity"],
        event_count=len(events),
        detection_count=incident.get("detection_count", 0),
        mitre_count=len(incident.get("mitre_techniques", [])),
        stages=_pipeline_stages(
            len(events), incident.get("detection_count", 0),
            len(incident.get("mitre_techniques", [])), incident["incident_id"],
        ),
        extra={"scenario": scenario, "file_id": file_id},
    )
    return {
        "success": True,
        "file_id": file_id,
        "scenario": scenario,
        "scenario_name": demo.SCENARIOS[scenario]["name"],
        "event_count": len(events),
        "incident": incident,
    }


# ---------------------------------------------------------------------------
# incidents
# ---------------------------------------------------------------------------
@router.get("/incidents")
def list_incidents() -> Dict[str, Any]:
    incidents = store.list_incidents()
    return {
        "success": True,
        "count": len(incidents),
        "incidents": [
            {
                "incident_id": i["incident_id"],
                "title": i["title"],
                "headline": i.get("headline"),
                "severity": i["severity"],
                "risk_score": i["risk_score"],
                "confidence": i["confidence"],
                "source_ip": i.get("source_ip"),
                "affected_user": i.get("affected_user"),
                "first_seen": i.get("first_seen"),
                "last_seen": i.get("last_seen"),
                "event_count": i.get("event_count"),
                "detection_count": i.get("detection_count"),
                "detected_stages": i.get("detected_stages", []),
                "mitre_count": len(i.get("mitre_techniques", [])),
                "status": i.get("status"),
            }
            for i in incidents
        ],
    }


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> Dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found.")
    return incident


# ---------------------------------------------------------------------------
# dashboard aggregates
# ---------------------------------------------------------------------------
@router.get("/stats")
def stats() -> Dict[str, Any]:
    incidents = store.list_incidents()
    incidents_by_severity: Dict[str, int] = {}
    suspicious_events = 0
    for inc in incidents:
        incidents_by_severity[inc["severity"]] = incidents_by_severity.get(inc["severity"], 0) + 1
        suspicious_events += sum(1 for e in inc.get("events", []) if e.get("suspicious"))

    # Total events = everything parsed from every tracked file (superset).
    # Suspicious events = only those inside correlated incidents that matched a
    # detection rule. These are deliberately different numbers.
    total_events = store.total_file_events()
    if total_events < suspicious_events:
        total_events = suspicious_events

    latest = incidents[0] if incidents else None
    return {
        "success": True,
        "total_events": total_events,
        "suspicious_events": suspicious_events,
        "active_incidents": len(incidents),
        "critical_incidents": incidents_by_severity.get("critical", 0),
        "high_incidents": incidents_by_severity.get("high", 0),
        "incidents_by_severity": incidents_by_severity,
        "latest_investigation": (
            {
                "incident_id": latest["incident_id"],
                "title": latest["title"],
                "severity": latest["severity"],
                "risk_score": latest["risk_score"],
                "affected_user": latest.get("affected_user"),
                "source_ip": latest.get("source_ip"),
                "first_seen": latest.get("first_seen"),
            }
            if latest
            else None
        ),
        "recent_activity": store.activity()[:12],
        "system_status": {
            "api": "operational",
            "parser": "operational",
            "detection": "operational",
            "correlation": "operational",
            "ai_investigator": "llm" if LLM_API_KEY else "deterministic-fallback",
            "storage": "in-memory",
            "service": SERVICE_NAME,
            "version": VERSION,
        },
    }


@router.get("/alerts")
def list_alerts(limit: int = 30) -> Dict[str, Any]:
    """Live alert feed: one alert per incident plus one per detection."""
    alerts = store.alerts(limit=limit)
    return {
        "success": True,
        "count": len(alerts),
        "unacknowledged": sum(1 for a in alerts if not a.get("acknowledged")),
        "alerts": alerts,
    }


@router.post("/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: str) -> Dict[str, Any]:
    ok = store.acknowledge_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found.")
    return {"success": True, "alert_id": alert_id, "acknowledged": True}


# ---------------------------------------------------------------------------
# live capture (tshark)
# ---------------------------------------------------------------------------


def _pipeline_stages(event_count: int, detection_count: int, mitre_count: int, incident_id: str) -> List[Dict[str, Any]]:
    """Describe the deterministic pipeline stages for a completed run.

    Purely descriptive: the numbers come from the actual finished analysis, so
    the UI can render a truthful stage-by-stage record of what ran.
    """
    return [
        {"id": "ingest", "label": "Ingest", "detail": f"{event_count} event(s)", "status": "done"},
        {"id": "normalize", "label": "Normalize", "detail": "schema applied", "status": "done"},
        {"id": "detect", "label": "Detect", "detail": f"{detection_count} detection(s)", "status": "done"},
        {"id": "correlate", "label": "Correlate", "detail": "entities merged", "status": "done"},
        {"id": "reconstruct", "label": "Reconstruct", "detail": incident_id, "status": "done"},
        {"id": "mitre", "label": "MITRE map", "detail": f"{mitre_count} technique(s)", "status": "done"},
        {"id": "respond", "label": "Response", "detail": "plan generated", "status": "done"},
    ]


@router.get("/history")
def analysis_history(limit: int = 50) -> Dict[str, Any]:
    """Chronological history of every automatic analysis run."""
    runs = store.runs(limit=limit)
    return {"success": True, "count": len(runs), "runs": runs}

@router.get("/live/status")
def live_status() -> Dict[str, Any]:
    """Current live-capture state plus the interfaces that can be captured."""
    return {"success": True, **live_service.live_capture.status()}


@router.post("/live/start")
def live_start(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Start streaming packets from an interface into the pipeline.

    Body: ``{"interface": "\\Device\\NPF_{...}", "bpf_filter": "tcp port 22"}``
    Requires tshark + Npcap; on Windows the backend must run as Administrator.
    """
    interface = (payload or {}).get("interface") or ""
    bpf = (payload or {}).get("bpf_filter") or ""
    result = live_service.live_capture.start(interface, bpf)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Could not start capture.")
    store.log_activity("live", f"Live capture started on {result.get('interface')}", {"bpf": bpf})
    return {"success": True, **result}


@router.post("/live/stop")
def live_stop() -> Dict[str, Any]:
    result = live_service.live_capture.stop()
    store.log_activity("live", "Live capture stopped", {"packets": result.get("packets")})
    return {"success": True, **result}


@router.get("/files/{file_id}")
def get_file(file_id: str) -> Dict[str, Any]:
    record = store.get_file(file_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"File {file_id!r} not found.")
    return {
        "success": True,
        "file_id": file_id,
        "filename": record.get("filename"),
        "size_bytes": record.get("size_bytes"),
        "event_count": len(record.get("events") or []),
        "parsing_status": "failed" if record.get("parsed_error") else "parsed",
        "summary": record.get("summary") or {},
        "scenario": record.get("scenario"),
    }


# ---------------------------------------------------------------------------
# chat
# ---------------------------------------------------------------------------
@router.get("/chat/suggestions")
def chat_suggestions() -> Dict[str, Any]:
    return {"success": True, "questions": chat_service.SUGGESTED_QUESTIONS}


@router.post("/chat")
def chat(payload: ChatRequest) -> Dict[str, Any]:
    incident = store.get_incident(payload.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {payload.incident_id!r} not found.")
    result = chat_service.answer_question(incident, payload.question)
    return {
        "success": True,
        "answer": result["answer"],
        "sources": result["sources"],
        "mode": result.get("mode"),
        "intent": result.get("intent"),
    }


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------
@router.get("/config")
def client_config() -> Dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "version": VERSION,
        "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
        "pcap_supported": pcap.tshark_available(),
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "ai_mode": "llm" if LLM_API_KEY else "deterministic-fallback",
    }


@router.post("/reset")
def reset() -> Dict[str, Any]:
    store.reset()
    return {"success": True, "message": "In-memory state cleared."}


@router.post("/report/{incident_id}")
def report(incident_id: str) -> Dict[str, Any]:
    """Server-side assembly of the printable incident report payload."""
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found.")
    return {"success": True, "report_id": f"RPT-{uuid.uuid4().hex[:8].upper()}", "incident": incident}
