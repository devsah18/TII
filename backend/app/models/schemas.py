"""Pydantic request/response models for the TRACE API."""
from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class UploadResponse(BaseModel):
    success: bool
    file_id: str
    filename: str
    event_count: int
    size_bytes: int | None = None
    parsing_status: str | None = None
    incident: Dict[str, Any] | None = None


class InvestigateRequest(BaseModel):
    file_id: str = Field(..., min_length=1)


class InvestigateQuestionRequest(BaseModel):
    """Spec Feature 3 + upload-driven flow.

    Either ``file_id`` (investigate an uploaded/loaded file) or ``incident_id``
    (re-open an existing incident) may be supplied. When ``question`` is present
    the AI investigator answers it against the incident evidence.
    """

    file_id: str | None = None
    incident_id: str | None = None
    question: str | None = None
    thresholds: Dict[str, Any] | None = None


class SimulateRequest(BaseModel):
    scenario: str = "brute_force"


class ChatRequest(BaseModel):
    incident_id: str = Field(..., min_length=1)
    question: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    success: bool
    answer: str
    sources: List[str] = []


class IncidentResponse(BaseModel):
    success: bool
    incident: Dict[str, Any]
