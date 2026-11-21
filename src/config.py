"""Shared configuration and client factories for ForensicLens."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from opensearchpy import OpenSearch
from sentence_transformers import SentenceTransformer

BASE_DIR: Path = Path(__file__).resolve().parent.parent
STATIC_DIR: Path = BASE_DIR / "static"

load_dotenv(BASE_DIR / ".env")

OPENSEARCH_URL: str = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
OPENSEARCH_USER: str = os.getenv("OPENSEARCH_USER", "")
OPENSEARCH_PASSWORD: str = os.getenv("OPENSEARCH_PASSWORD", "")
DEFAULT_INDEX: str = os.getenv("FORENSIC_INDEX", "forensic-case-001")

OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.2")
EMBEDDING_MODEL_NAME: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DIMS: int = 384

MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))
ALLOWED_EXTENSIONS: set[str] = {".evtx", ".jsonl", ".json"}


def get_cors_origins() -> list[str]:
    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000",
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@lru_cache(maxsize=1)
def get_opensearch_client() -> OpenSearch:
    """Create a cached OpenSearch client configured from environment variables."""
    http_auth: Optional[tuple[str, str]] = None
    if OPENSEARCH_USER and OPENSEARCH_PASSWORD:
        http_auth = (OPENSEARCH_USER, OPENSEARCH_PASSWORD)

    use_ssl = OPENSEARCH_URL.lower().startswith("https://")
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_auth=http_auth,
        use_ssl=use_ssl,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
        max_retries=2,
        retry_on_timeout=True,
    )


@lru_cache(maxsize=1)
def get_embedder() -> SentenceTransformer:
    """Lazy-load the 384-dim all-MiniLM-L6-v2 embedding model once per process."""
    return SentenceTransformer(EMBEDDING_MODEL_NAME)
