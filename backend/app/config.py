"""TRACE configuration.

All secrets come from the environment. Nothing sensitive is ever shipped to the
frontend.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- upload safety -----------------------------------------------------------
MAX_UPLOAD_BYTES = int(os.getenv("TRACE_MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}
MAX_EVENTS = int(os.getenv("TRACE_MAX_EVENTS", "20000"))

# --- http --------------------------------------------------------------------
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "TRACE_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if o.strip()
]

# --- optional LLM provider (fully optional; deterministic fallback exists) ----
LLM_API_KEY = os.getenv("TRACE_LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
LLM_BASE_URL = os.getenv("TRACE_LLM_BASE_URL", "https://api.openai.com/v1")
LLM_MODEL = os.getenv("TRACE_LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = float(os.getenv("TRACE_LLM_TIMEOUT", "12"))

SERVICE_NAME = "TRACE"
VERSION = "1.0.0"

# Year assumed when a log line only carries a syslog-style timestamp
DEFAULT_LOG_YEAR = int(os.getenv("TRACE_DEFAULT_LOG_YEAR", "2026"))
