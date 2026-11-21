"""FastAPI backend and static workbench server for ForensicLens."""

from __future__ import annotations

import base64
import json
import logging
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.config import (
    ALLOWED_EXTENSIONS,
    DEFAULT_INDEX,
    MAX_UPLOAD_BYTES,
    OLLAMA_MODEL,
    OLLAMA_URL,
    STATIC_DIR,
    get_cors_origins,
    get_opensearch_client,
)
from src.ingest import ensure_forensic_index, ingest_file
from src.query_cli import ask_forensic_copilot
from src.sigma_triage import SIGMA_RULES, run_sigma_triage

logger = logging.getLogger("forensiclens")

DOC_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
INDEX_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

app = FastAPI(
    title="ForensicLens API",
    description="Local AI-powered Windows DFIR & Sigma triage workbench",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ChatHistoryTurn(BaseModel):
    role: str = Field(..., pattern="^(user|assistant)$")
    content: str = Field(..., min_length=1, max_length=4000)


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=1500)
    index_name: str = Field(default=DEFAULT_INDEX)
    top_k: int = Field(default=8, ge=1, le=20)
    mode: str = Field(default="investigate", pattern="^(investigate|hunt|remediate|sigma_rule)$")
    history: list[ChatHistoryTurn] = Field(default_factory=list, max_length=12)


class TriageRequest(BaseModel):
    index_name: str = Field(default=DEFAULT_INDEX)
    sync_security_analytics: bool = Field(default=True)


def _validate_index_name(index_name: str) -> str:
    if not INDEX_PATTERN.match(index_name):
        raise HTTPException(status_code=400, detail="Invalid case index name.")
    return index_name


@app.get("/", include_in_schema=False)
def serve_workbench() -> FileResponse:
    """Serve the zero-build single-page ForensicLens UI."""
    index_html = STATIC_DIR / "index.html"
    if not index_html.exists():
        raise HTTPException(status_code=404, detail="Workbench UI not found.")
    return FileResponse(path=str(index_html), media_type="text/html")


@app.get("/api/health")
def health_check(index_name: str = Query(default=DEFAULT_INDEX)) -> dict[str, Any]:
    """Verify OpenSearch cluster, Ollama service, and active index status."""
    safe_index = _validate_index_name(index_name)

    os_ok = False
    os_version = "unavailable"
    doc_count = 0
    try:
        client = get_opensearch_client()
        info = client.info()
        os_ok = True
        os_version = info.get("version", {}).get("number", "unknown")
        if client.indices.exists(index=safe_index):
            doc_count = int(client.count(index=safe_index).get("count", 0))
    except Exception:
        os_ok = False

    ollama_ok = False
    try:
        with httpx.Client(timeout=3.0) as http:
            resp = http.get(f"{OLLAMA_URL.rstrip('/')}/api/tags")
            ollama_ok = resp.status_code == 200
    except Exception:
        ollama_ok = False

    return {
        "status": "ok" if os_ok else "degraded",
        "opensearch_connected": os_ok,
        "opensearch_version": os_version,
        "ollama_connected": ollama_ok,
        "ollama_model": OLLAMA_MODEL,
        "index_name": safe_index,
        "total_events": doc_count,
    }


@app.get("/api/stats")
def get_case_stats(index_name: str = Query(default=DEFAULT_INDEX)) -> dict[str, Any]:
    """Return case telemetry: total events, Sigma alert counts, and severity breakdown."""
    safe_index = _validate_index_name(index_name)
    client = get_opensearch_client()

    if not client.indices.exists(index=safe_index):
        return {
            "index_name": safe_index,
            "total_events": 0,
            "flagged_events": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "rules_catalog": [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "severity": r.severity,
                    "mitre_tactic": r.mitre_tactic,
                    "mitre_technique": r.mitre_technique,
                }
                for r in SIGMA_RULES
            ],
        }

    agg_res = client.search(
        index=safe_index,
        body={
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "sigma_severity"}},
                "flagged": {"filter": {"term": {"sigma_flagged": True}}},
            },
        },
    )

    total_events = int(agg_res.get("hits", {}).get("total", {}).get("value", 0))
    flagged_events = int(agg_res.get("aggregations", {}).get("flagged", {}).get("doc_count", 0))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for bucket in (
        agg_res.get("aggregations", {})
        .get("by_severity", {})
        .get("buckets", [])
    ):
        key = str(bucket.get("key", "")).lower()
        if key in severity_counts:
            severity_counts[key] = int(bucket.get("doc_count", 0))

    return {
        "index_name": safe_index,
        "total_events": total_events,
        "flagged_events": flagged_events,
        "severity_counts": severity_counts,
        "rules_catalog": [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity,
                "mitre_tactic": r.mitre_tactic,
                "mitre_technique": r.mitre_technique,
            }
            for r in SIGMA_RULES
        ],
    }


@app.post("/api/upload")
async def upload_log_artifact(
    file: UploadFile = File(...),
    index_name: str = Query(default=DEFAULT_INDEX),
) -> dict[str, Any]:
    """Ingest a dragged-and-dropped .evtx or .jsonl artifact and run Sigma triage."""
    safe_index = _validate_index_name(index_name)
    original_name = Path(file.filename or "artifact.jsonl").name
    suffix = Path(original_name).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload a .evtx, .jsonl, or .json log file.",
        )

    temp_dir = Path(tempfile.mkdtemp(prefix="forensiclens_")).resolve()
    safe_target = (temp_dir / f"{uuid.uuid4().hex}{suffix}").resolve()
    if not safe_target.is_relative_to(temp_dir):
        raise HTTPException(status_code=400, detail="Invalid upload path.")

    total_bytes = 0
    try:
        with safe_target.open("wb") as out_stream:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.",
                    )
                out_stream.write(chunk)

        ingest_summary = ingest_file(
            safe_target,
            index_name=safe_index,
            source_label=original_name,
        )
        triage_summary = run_sigma_triage(index_name=safe_index, sync_sa=False)

        return {
            "filename": original_name,
            "bytes_processed": total_bytes,
            "ingest": ingest_summary,
            "triage": triage_summary,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Log upload and ingestion failed")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to ingest log artifact ({type(exc).__name__}). Check OpenSearch connectivity.",
        ) from exc
    finally:
        await file.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/triage")
def trigger_sigma_triage(payload: TriageRequest) -> dict[str, Any]:
    """Execute automated Sigma detection rules across the active case index."""
    safe_index = _validate_index_name(payload.index_name)
    try:
        client = get_opensearch_client()
        ensure_forensic_index(client, safe_index)
        return run_sigma_triage(
            index_name=safe_index,
            sync_sa=payload.sync_security_analytics,
        )
    except Exception as exc:
        logger.exception("Sigma triage failed")
        raise HTTPException(
            status_code=500,
            detail=f"Sigma triage execution failed ({type(exc).__name__}).",
        ) from exc


@app.get("/api/alerts")
def list_alerts(
    index_name: str = Query(default=DEFAULT_INDEX),
    severity: Optional[str] = Query(default=None),
    flagged_only: bool = Query(default=True),
    q: Optional[str] = Query(default=None, max_length=300),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Return Sigma-flagged alerts (or all logs) with optional severity & text filters."""
    safe_index = _validate_index_name(index_name)
    client = get_opensearch_client()

    if not client.indices.exists(index=safe_index):
        return {"events": [], "total": 0}

    must_clauses: list[dict[str, Any]] = []
    if flagged_only:
        must_clauses.append({"term": {"sigma_flagged": True}})
    if severity and severity.lower() in {"critical", "high", "medium", "low"}:
        must_clauses.append({"term": {"sigma_severity": severity.lower()}})
    if q and q.strip():
        must_clauses.append(
            {
                "multi_match": {
                    "query": q.strip(),
                    "fields": [
                        "command_line^3",
                        "process_name^2",
                        "message^2",
                        "user",
                        "host",
                        "event_id",
                        "source_ip",
                    ],
                }
            }
        )

    query_dsl: dict[str, Any] = (
        {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}
    )

    res = client.search(
        index=safe_index,
        body={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": {"excludes": ["command_embedding", "raw_event"]},
            "query": query_dsl,
        },
    )

    events: list[dict[str, Any]] = []
    for hit in res.get("hits", {}).get("hits", []):
        events.append({"doc_id": hit.get("_id"), **hit.get("_source", {})})

    total = int(res.get("hits", {}).get("total", {}).get("value", len(events)))
    return {"events": events, "total": total}


def _decode_encoded_powershell(command_line: str) -> Optional[str]:
    """Extract and decode UTF-16LE Base64 payloads from PowerShell -EncodedCommand flags."""
    if not command_line:
        return None
    match = re.search(
        r"(?:-EncodedCommand|-enc|-ec|-e)\s+([A-Za-z0-9+/=]{16,})",
        command_line,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    b64_payload = match.group(1)
    try:
        raw_bytes = base64.b64decode(b64_payload, validate=True)
        decoded = raw_bytes.decode("utf-16-le", errors="ignore").strip("\x00\r\n ")
        return decoded or None
    except Exception:
        return None


@app.get("/api/events/{doc_id}")
def get_event_detail(
    doc_id: str,
    index_name: str = Query(default=DEFAULT_INDEX),
) -> dict[str, Any]:
    """Retrieve the full forensic document and raw EVTX/JSONL payload for a cited log."""
    safe_index = _validate_index_name(index_name)
    if not DOC_ID_PATTERN.match(doc_id):
        raise HTTPException(status_code=400, detail="Invalid document identifier.")

    client = get_opensearch_client()
    try:
        doc = client.get(
            index=safe_index,
            id=doc_id,
            _source_excludes=["command_embedding"],
        )
        source = doc.get("_source", {})
        decoded_ps = _decode_encoded_powershell(str(source.get("command_line", "")))
        return {
            "doc_id": doc.get("_id"),
            **source,
            "decoded_powershell": decoded_ps,
        }
    except Exception as exc:
        raise HTTPException(status_code=404, detail="Cited log event not found.") from exc


@app.get("/api/export")
def export_incident_report(
    index_name: str = Query(default=DEFAULT_INDEX),
    flagged_only: bool = Query(default=True),
) -> Response:
    """Download flagged Sigma findings and timeline as a portable JSON incident report."""
    safe_index = _validate_index_name(index_name)
    client = get_opensearch_client()
    if not client.indices.exists(index=safe_index):
        payload = {"index": safe_index, "total_events": 0, "events": []}
    else:
        query_dsl: dict[str, Any] = (
            {"term": {"sigma_flagged": True}} if flagged_only else {"match_all": {}}
        )
        res = client.search(
            index=safe_index,
            body={
                "size": 500,
                "sort": [{"timestamp": {"order": "asc", "unmapped_type": "date"}}],
                "_source": {"excludes": ["command_embedding", "raw_event"]},
                "query": query_dsl,
            },
        )
        events = [
            {"doc_id": h.get("_id"), **h.get("_source", {})}
            for h in res.get("hits", {}).get("hits", [])
        ]
        payload = {
            "index": safe_index,
            "total_events": len(events),
            "events": events,
        }

    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_index}-report.json"'
        },
    )


@app.post("/api/chat")
def copilot_chat(payload: ChatRequest) -> dict[str, Any]:
    """Answer an investigator question via Hybrid Search + Ollama with clickable citations."""
    safe_index = _validate_index_name(payload.index_name)
    try:
        return ask_forensic_copilot(
            question=payload.question.strip(),
            index_name=safe_index,
            size=payload.top_k,
            mode=payload.mode,
            history=[{"role": h.role, "content": h.content} for h in payload.history],
        )
    except Exception as exc:
        logger.exception("Copilot query failed")
        raise HTTPException(
            status_code=500,
            detail=f"ForensicLens Copilot query failed ({type(exc).__name__}).",
        ) from exc


@app.delete("/api/case")
def clear_case_history(index_name: str = Query(default=DEFAULT_INDEX)) -> dict[str, Any]:
    """Delete all indexed events from the active case and recreate a clean index."""
    safe_index = _validate_index_name(index_name)
    client = get_opensearch_client()
    try:
        if client.indices.exists(index=safe_index):
            client.indices.delete(index=safe_index)
        ensure_forensic_index(client, safe_index)
        return {"cleared": True, "index_name": safe_index}
    except Exception as exc:
        logger.exception("Failed to clear case index")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clear case index ({type(exc).__name__}).",
        ) from exc
