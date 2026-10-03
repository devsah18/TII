"""Upload validation and filename sanitization.

A log file is treated as hostile input: it is never executed, never passed to a
shell, and never used to build a filesystem path.
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from ..config import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class UploadValidationError(ValueError):
    """Raised when an upload fails validation. Carries a user-facing message."""


def sanitize_filename(raw: str | None) -> str:
    """Reduce an arbitrary client-supplied name to a safe basename."""
    name = (raw or "upload.log").strip().replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFKD", name)
    name = _SAFE_NAME_RE.sub("_", name).lstrip(".")
    if not name:
        name = "upload.log"
    return name[:120]


def validate_upload(filename: str, size: int, content: bytes) -> None:
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UploadValidationError(
            "The uploaded file could not be parsed. Supported formats: LOG, TXT, CSV, JSON."
        )
    if size > MAX_UPLOAD_BYTES:
        raise UploadValidationError(
            f"File is too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
        )
    if size == 0:
        raise UploadValidationError("The uploaded file is empty.")
    if b"\x00" in content[:4096]:
        raise UploadValidationError(
            "The uploaded file does not look like a text log (binary content detected). "
            "Supported formats: LOG, TXT, CSV, JSON."
        )
