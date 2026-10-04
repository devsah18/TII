"""TRACE backend entrypoint.

Run:  uvicorn app.main:app --reload --port 8000   (from the backend/ directory)
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import BASE_DIR, CORS_ORIGINS, MAX_UPLOAD_BYTES, SERVICE_NAME, VERSION
from .routes.trace import router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("trace")

app = FastAPI(
    title="TRACE API",
    description="Threat Reconstruction & Analysis Cybersecurity Engine — AI-assisted incident investigation.",
    version=VERSION,
    docs_url="/docs",
    redoc_url=None,
)

FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
def _startup() -> None:
    logger.info("%s v%s ready — upload cap %.1f MB", SERVICE_NAME, VERSION, MAX_UPLOAD_BYTES / 1024 / 1024)


@app.get("/")
def root():
    if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
        return FileResponse(FRONTEND_DIST / "index.html")
    return {
        "service": SERVICE_NAME,
        "version": VERSION,
        "docs": "/docs",
        "endpoints": [
            "GET  /api/health",
            "POST /api/upload",
            "POST /api/investigate",
            "POST /api/simulate",
            "GET  /api/incidents/{incident_id}",
            "POST /api/chat",
        ],
    }


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Always return a JSON body with a human-readable `detail`."""
    detail = exc.detail
    if isinstance(detail, dict):
        detail = detail.get("message") or str(detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "error": str(detail), "detail": str(detail), "path": request.url.path},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": "The request body was not valid. Check that the required fields are present.",
            "detail": exc.errors(),
            "path": request.url.path,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "TRACE encountered an internal error while processing the request.",
            "detail": str(exc),
            "path": request.url.path,
        },
    )


if FRONTEND_DIST.exists() and (FRONTEND_DIST / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIST / "assets")), name="static_assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        target = FRONTEND_DIST / full_path
        if full_path and target.is_file():
            return FileResponse(target)
        return FileResponse(FRONTEND_DIST / "index.html")

