"""ForensicLens log ingestion pipeline for Windows .evtx and .jsonl artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import xmltodict
from Evtx.Evtx import Evtx
from opensearchpy import OpenSearch, helpers
from rich.console import Console

from src.config import (
    DEFAULT_INDEX,
    EMBEDDING_DIMS,
    get_embedder,
    get_opensearch_client,
)

console = Console()


def ensure_forensic_index(client: OpenSearch, index_name: str = DEFAULT_INDEX) -> None:
    """Create the OpenSearch k-NN index with forensic field mappings if missing."""
    if client.indices.exists(index=index_name):
        return

    mapping: dict[str, Any] = {
        "settings": {
            "index": {
                "knn": True,
                "number_of_shards": 1,
                "number_of_replicas": 0,
            }
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date", "ignore_malformed": True},
                "ingested_at": {"type": "date"},
                "source_file": {"type": "keyword"},
                "channel": {"type": "keyword"},
                "event_id": {"type": "keyword"},
                "host": {"type": "keyword"},
                "user": {"type": "keyword"},
                "process_name": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
                },
                "parent_process": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
                },
                "command_line": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}},
                },
                "target_image": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
                },
                "granted_access": {"type": "keyword"},
                "logon_type": {"type": "keyword"},
                "source_ip": {"type": "ip", "ignore_malformed": True},
                "destination_ip": {"type": "ip", "ignore_malformed": True},
                "destination_port": {"type": "integer", "ignore_malformed": True},
                "message": {"type": "text"},
                "command_embedding": {
                    "type": "knn_vector",
                    "dimension": EMBEDDING_DIMS,
                    "method": {
                        "name": "hnsw",
                        "space_type": "cosinesimil",
                        "engine": "lucene",
                    },
                },
                "sigma_flagged": {"type": "boolean"},
                "sigma_severity": {"type": "keyword"},
                "sigma_rule_ids": {"type": "keyword"},
                "sigma_alerts": {
                    "type": "nested",
                    "properties": {
                        "rule_id": {"type": "keyword"},
                        "title": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "mitre_tactic": {"type": "keyword"},
                        "mitre_technique": {"type": "keyword"},
                        "description": {"type": "text"},
                    },
                },
                "triage_timestamp": {"type": "date"},
                "raw_event": {"type": "object", "enabled": False},
            }
        },
    }
    client.indices.create(index=index_name, body=mapping)


def _extract_event_data(raw: dict[str, Any]) -> dict[str, str]:
    """Flatten Windows EVTX EventData/Data name-value pairs into a flat dict."""
    extracted: dict[str, str] = {}
    event_node = raw.get("Event", raw)
    event_data = event_node.get("EventData") or event_node.get("UserData") or {}

    if isinstance(event_data, dict):
        data_items = event_data.get("Data")
        if isinstance(data_items, list):
            for idx, item in enumerate(data_items):
                if isinstance(item, dict):
                    key = str(item.get("@Name") or f"Data_{idx}")
                    val = str(item.get("#text") or "")
                    extracted[key] = val
                elif item is not None:
                    extracted[f"Data_{idx}"] = str(item)
        elif isinstance(data_items, dict):
            key = str(data_items.get("@Name") or "Data_0")
            extracted[key] = str(data_items.get("#text") or "")
        else:
            for k, v in event_data.items():
                if isinstance(v, (str, int, float)):
                    extracted[str(k)] = str(v)

    return extracted


def _normalize_record(raw: dict[str, Any], source_file: str, record_idx: int) -> dict[str, Any]:
    """Normalize either an EVTX-derived dict or JSONL event object into our schema."""
    event_node = raw.get("Event", raw)
    system_node = event_node.get("System", {}) if isinstance(event_node, dict) else {}
    flat_data = _extract_event_data(raw)

    def pick(*keys: str, default: str = "") -> str:
        for key in keys:
            for source in (flat_data, raw, system_node):
                if isinstance(source, dict) and key in source and source[key] not in (None, ""):
                    val = source[key]
                    if isinstance(val, dict) and "#text" in val:
                        return str(val["#text"])
                    return str(val)
        return default

    # Timestamp resolution
    time_created = system_node.get("TimeCreated", {}) if isinstance(system_node, dict) else {}
    raw_ts = ""
    if isinstance(time_created, dict):
        raw_ts = str(time_created.get("@SystemTime") or "")
    if not raw_ts:
        raw_ts = pick("timestamp", "@timestamp", "UtcTime", "TimeCreated", "time")
    if not raw_ts:
        raw_ts = datetime.now(timezone.utc).isoformat()

    event_id_raw = system_node.get("EventID") if isinstance(system_node, dict) else None
    if isinstance(event_id_raw, dict):
        event_id = str(event_id_raw.get("#text") or "")
    elif event_id_raw is not None:
        event_id = str(event_id_raw)
    else:
        event_id = pick("event_id", "EventID", "EventId", default="0")

    host = pick("host", "Computer", "ComputerName", "hostname", default="WIN-WORKSTATION")
    user = pick(
        "user",
        "TargetUserName",
        "SubjectUserName",
        "User",
        "AccountName",
        default="SYSTEM",
    )
    process_name = pick("process_name", "Image", "NewProcessName", "ProcessName")
    parent_process = pick("parent_process", "ParentImage", "ParentProcessName")
    command_line = pick("command_line", "CommandLine", "ProcessCommandLine", "ScriptBlockText")
    target_image = pick("target_image", "TargetImage")
    granted_access = pick("granted_access", "GrantedAccess")
    logon_type = pick("logon_type", "LogonType")
    source_ip = pick("source_ip", "IpAddress", "SourceIp", "SrcIp") or None
    destination_ip = pick("destination_ip", "DestinationIp", "DestIp") or None
    dest_port_str = pick("destination_port", "DestinationPort", "DestPort")
    dest_port = int(dest_port_str) if dest_port_str.isdigit() else None
    channel = pick("channel", "Channel", default="Security")
    message = pick("message", "Message", "Details")

    if not message:
        parts = [p for p in [f"EventID {event_id}", process_name, command_line, target_image] if p]
        message = " | ".join(parts)

    stable_seed = f"{source_file}:{record_idx}:{raw_ts}:{event_id}:{command_line}:{user}"
    doc_id = hashlib.sha256(stable_seed.encode("utf-8", errors="ignore")).hexdigest()[:24]

    return {
        "_id": doc_id,
        "timestamp": raw_ts,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "source_file": source_file,
        "channel": channel,
        "event_id": event_id,
        "host": host,
        "user": user,
        "process_name": process_name,
        "parent_process": parent_process,
        "command_line": command_line,
        "target_image": target_image,
        "granted_access": granted_access,
        "logon_type": logon_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": dest_port,
        "message": message,
        "sigma_flagged": False,
        "sigma_severity": "none",
        "sigma_rule_ids": [],
        "sigma_alerts": [],
        "raw_event": raw,
    }


def parse_evtx_file(file_path: Path) -> Iterable[dict[str, Any]]:
    """Stream and parse records from a Windows .evtx binary log file."""
    source_name = file_path.name
    with Evtx(str(file_path)) as log:
        for idx, record in enumerate(log.records()):
            try:
                parsed = xmltodict.parse(record.xml())
                yield _normalize_record(parsed, source_name, idx)
            except Exception:
                continue


def parse_jsonl_file(file_path: Path) -> Iterable[dict[str, Any]]:
    """Stream and parse records from a .jsonl or JSON-array log file."""
    source_name = file_path.name
    content = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content:
        return

    if content.startswith("["):
        data = json.loads(content)
        if isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    yield _normalize_record(item, source_name, idx)
        return

    for idx, line in enumerate(content.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
            if isinstance(item, dict):
                yield _normalize_record(item, source_name, idx)
        except json.JSONDecodeError:
            continue


def ingest_file(
    file_path: str | Path,
    index_name: str = DEFAULT_INDEX,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Parse an .evtx or .jsonl file, embed command lines, and bulk-index into OpenSearch."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log artifact not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".evtx":
        docs = list(parse_evtx_file(path))
    elif suffix in {".jsonl", ".json"}:
        docs = list(parse_jsonl_file(path))
    else:
        raise ValueError(f"Unsupported artifact extension: {suffix}")

    if source_label:
        for doc in docs:
            doc["source_file"] = source_label

    if not docs:
        return {"ingested": 0, "errors": 0, "index": index_name}

    embedder = get_embedder()
    texts = [
        " ".join(
            part
            for part in [
                doc.get("process_name", ""),
                doc.get("command_line", ""),
                doc.get("target_image", ""),
                doc.get("message", ""),
            ]
            if part
        )
        or f"EventID {doc.get('event_id', '0')}"
        for doc in docs
    ]
    vectors = embedder.encode(texts, batch_size=64, normalize_embeddings=True)

    client = get_opensearch_client()
    ensure_forensic_index(client, index_name)

    actions: list[dict[str, Any]] = []
    for doc, vec in zip(docs, vectors):
        doc_id = doc.pop("_id")
        doc["command_embedding"] = [float(x) for x in vec]
        actions.append(
            {
                "_index": index_name,
                "_id": doc_id,
                "_source": doc,
            }
        )

    success_count, errors = helpers.bulk(client, actions, raise_on_error=False)
    client.indices.refresh(index=index_name)

    return {
        "ingested": int(success_count),
        "errors": len(errors) if isinstance(errors, list) else 0,
        "index": index_name,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ForensicLens: Ingest Windows .evtx or .jsonl logs into OpenSearch."
    )
    parser.add_argument("--file", required=True, help="Path to .evtx or .jsonl file")
    parser.add_argument("--index", default=DEFAULT_INDEX, help="Target OpenSearch index")
    args = parser.parse_args()

    result = ingest_file(args.file, index_name=args.index)
    console.print(
        f"[bold green]Ingested[/bold green] {result['ingested']} events "
        f"into [cyan]{result['index']}[/cyan] (errors: {result['errors']})"
    )


if __name__ == "__main__":
    main()
