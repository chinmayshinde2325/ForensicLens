"""Automated Sigma Detection & Triage Engine for ForensicLens.

Integrates with OpenSearch Security Analytics API when available and runs
deterministic Sigma-mapped OpenSearch DSL queries to detect ransomware TTPs:
  1. Volume Shadow Copy Deletion (vssadmin / wmic / bcdedit / wbadmin)
  2. LSASS Process Memory Dumping (Sysmon Event ID 10 / comsvcs.dll / procdump)
  3. Encoded or Obfuscated PowerShell Execution
  4. RDP Lateral Movement & Session Hijacking (Event ID 4624 Type 10 / 4778 / mstsc)
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
from opensearchpy import OpenSearch
from rich.console import Console
from rich.table import Table

from src.config import (
    DEFAULT_INDEX,
    OPENSEARCH_PASSWORD,
    OPENSEARCH_URL,
    OPENSEARCH_USER,
    get_opensearch_client,
)

console = Console()

SEVERITY_RANK: dict[str, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class SigmaRuleDefinition:
    rule_id: str
    title: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    sigma_yaml: str
    dsl_query: dict[str, Any]


SIGMA_RULES: list[SigmaRuleDefinition] = [
    SigmaRuleDefinition(
        rule_id="fl-sigma-001",
        title="Ransomware Shadow Copy & Backup Deletion",
        severity="critical",
        mitre_tactic="Impact",
        mitre_technique="T1490",
        description=(
            "Detects execution of vssadmin, wmic shadowcopy, bcdedit recovery disabling, "
            "or wbadmin catalog deletion commonly used prior to ransomware encryption."
        ),
        sigma_yaml="""title: Ransomware Shadow Copy Deletion
id: 6c8b7f5a-3b1e-4d5c-9c71-000000000001
status: stable
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection_vss:
    Image|endswith: '\\vssadmin.exe'
    CommandLine|contains: 'delete'
  selection_wmic:
    CommandLine|contains|all: ['shadowcopy', 'delete']
  selection_bcd:
    CommandLine|contains|all: ['bcdedit', 'recoveryenabled', 'no']
  selection_wbadmin:
    CommandLine|contains|all: ['wbadmin', 'delete', 'catalog']
  condition: 1 of selection_*
""",
        dsl_query={
            "bool": {
                "should": [
                    {
                        "bool": {
                            "must": [
                                {"match_phrase": {"command_line": "vssadmin"}},
                                {"match": {"command_line": "delete"}},
                            ]
                        }
                    },
                    {
                        "bool": {
                            "must": [
                                {"match_phrase": {"command_line": "shadowcopy"}},
                                {"match": {"command_line": "delete"}},
                            ]
                        }
                    },
                    {
                        "bool": {
                            "must": [
                                {"match": {"command_line": "bcdedit"}},
                                {"match": {"command_line": "recoveryenabled"}},
                            ]
                        }
                    },
                    {
                        "bool": {
                            "must": [
                                {"match": {"command_line": "wbadmin"}},
                                {"match": {"command_line": "delete"}},
                                {"match": {"command_line": "catalog"}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
    ),
    SigmaRuleDefinition(
        rule_id="fl-sigma-002",
        title="LSASS Memory Dump / Credential Access",
        severity="critical",
        mitre_tactic="Credential Access",
        mitre_technique="T1003.001",
        description=(
            "Detects Sysmon Event ID 10 process access to lsass.exe with memory-read rights "
            "or command lines invoking comsvcs.dll MiniDump, procdump, mimikatz, or nanodump."
        ),
        sigma_yaml="""title: LSASS Process Memory Dump
id: 6c8b7f5a-3b1e-4d5c-9c71-000000000002
status: stable
level: critical
logsource:
  category: process_access
  product: windows
detection:
  selection_sysmon:
    EventID: 10
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess: ['0x1010', '0x1410', '0x143a', '0x1fffff']
  selection_cmdline:
    CommandLine|contains: ['comsvcs.dll', 'MiniDump', 'procdump', 'mimikatz', 'nanodump']
  condition: 1 of selection_*
""",
        dsl_query={
            "bool": {
                "should": [
                    {
                        "bool": {
                            "must": [
                                {"term": {"event_id": "10"}},
                                {"wildcard": {"target_image.keyword": "*lsass.exe"}},
                                {
                                    "terms": {
                                        "granted_access": [
                                            "0x1010",
                                            "0x1410",
                                            "0x143a",
                                            "0x1FFFFF",
                                            "0x1fffff",
                                        ]
                                    }
                                },
                            ]
                        }
                    },
                    {"match_phrase": {"command_line": "comsvcs.dll"}},
                    {"match_phrase": {"command_line": "MiniDump"}},
                    {"match_phrase": {"command_line": "procdump"}},
                    {"match_phrase": {"command_line": "mimikatz"}},
                    {"match_phrase": {"command_line": "nanodump"}},
                    {
                        "bool": {
                            "must": [
                                {"match": {"command_line": "lsass"}},
                                {"match": {"command_line": "dump"}},
                            ]
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
    ),
    SigmaRuleDefinition(
        rule_id="fl-sigma-003",
        title="Encoded or Hidden PowerShell Execution",
        severity="high",
        mitre_tactic="Execution",
        mitre_technique="T1059.001",
        description=(
            "Detects powershell.exe or pwsh.exe launched with Base64 encoded commands "
            "(-EncodedCommand / -enc), hidden windows, or FromBase64String decoding."
        ),
        sigma_yaml="""title: Encoded PowerShell Execution
id: 6c8b7f5a-3b1e-4d5c-9c71-000000000003
status: stable
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection_proc:
    Image|endswith: ['\\powershell.exe', '\\pwsh.exe']
  selection_flags:
    CommandLine|contains: ['-EncodedCommand', '-enc ', '-ec ', 'FromBase64String', '-w hidden', '-WindowStyle Hidden']
  condition: selection_proc and selection_flags
""",
        dsl_query={
            "bool": {
                "must": [
                    {
                        "bool": {
                            "should": [
                                {"match": {"process_name": "powershell"}},
                                {"match": {"process_name": "pwsh"}},
                                {"match": {"command_line": "powershell"}},
                                {"match": {"command_line": "pwsh"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    {
                        "bool": {
                            "should": [
                                {"wildcard": {"command_line.keyword": "*-enc *"}},
                                {"wildcard": {"command_line.keyword": "*-EncodedCommand*"}},
                                {"wildcard": {"command_line.keyword": "*-e *"}},
                                {"match_phrase": {"command_line": "FromBase64String"}},
                                {"match_phrase": {"command_line": "WindowStyle Hidden"}},
                                {"wildcard": {"command_line.keyword": "*-w hidden*"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
    ),
    SigmaRuleDefinition(
        rule_id="fl-sigma-004",
        title="RDP Lateral Movement & Session Hijack",
        severity="high",
        mitre_tactic="Lateral Movement",
        mitre_technique="T1021.001",
        description=(
            "Detects RemoteInteractive (LogonType 10) Security 4624 logons, RDP session "
            "reconnects (4778), or lateral movement utilities (mstsc.exe, tscon.exe, qwinsta.exe)."
        ),
        sigma_yaml="""title: RDP Lateral Movement Activity
id: 6c8b7f5a-3b1e-4d5c-9c71-000000000004
status: stable
level: high
logsource:
  product: windows
  service: security
detection:
  selection_rdp_logon:
    EventID: 4624
    LogonType: 10
  selection_rdp_reconnect:
    EventID: [4778, 4779]
  selection_rdp_tools:
    Image|endswith: ['\\mstsc.exe', '\\tscon.exe', '\\qwinsta.exe']
  condition: 1 of selection_*
""",
        dsl_query={
            "bool": {
                "should": [
                    {
                        "bool": {
                            "must": [
                                {"term": {"event_id": "4624"}},
                                {"term": {"logon_type": "10"}},
                            ]
                        }
                    },
                    {"terms": {"event_id": ["4778", "4779"]}},
                    {"match": {"process_name": "mstsc.exe"}},
                    {"match": {"process_name": "tscon.exe"}},
                    {"match": {"command_line": "mstsc"}},
                    {"match": {"command_line": "tscon"}},
                    {"term": {"destination_port": 3389}},
                ],
                "minimum_should_match": 1,
            }
        },
    ),
    SigmaRuleDefinition(
        rule_id="fl-sigma-005",
        title="Windows Defender / Security Service Tampering",
        severity="critical",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1562.001",
        description=(
            "Detects attempts to disable Windows Defender real-time protection or stop "
            "endpoint security services prior to payload deployment."
        ),
        sigma_yaml="""title: Security Tool Tampering
id: 6c8b7f5a-3b1e-4d5c-9c71-000000000005
status: stable
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection_ps:
    CommandLine|contains: ['DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'Add-MpPreference']
  selection_svc:
    CommandLine|contains|all: ['WinDefend']
  condition: 1 of selection_*
""",
        dsl_query={
            "bool": {
                "should": [
                    {"match_phrase": {"command_line": "DisableRealtimeMonitoring"}},
                    {"match_phrase": {"command_line": "DisableBehaviorMonitoring"}},
                    {"match_phrase": {"command_line": "Add-MpPreference"}},
                    {"match_phrase": {"command_line": "WinDefend"}},
                ],
                "minimum_should_match": 1,
            }
        },
    ),
    SigmaRuleDefinition(
        rule_id="fl-sigma-006",
        title="Scheduled Task Persistence Creation",
        severity="medium",
        mitre_tactic="Persistence",
        mitre_technique="T1053.005",
        description=(
            "Detects creation of scheduled tasks via schtasks.exe /create or PowerShell "
            "Register-ScheduledTask commonly abused for persistence."
        ),
        sigma_yaml="""title: Scheduled Task Creation
id: 6c8b7f5a-3b1e-4d5c-9c71-000000000006
status: stable
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection_schtasks:
    CommandLine|contains|all: ['schtasks', '/create']
  selection_ps_task:
    CommandLine|contains: 'Register-ScheduledTask'
  condition: 1 of selection_*
""",
        dsl_query={
            "bool": {
                "should": [
                    {
                        "bool": {
                            "must": [
                                {"match": {"command_line": "schtasks"}},
                                {"match": {"command_line": "create"}},
                            ]
                        }
                    },
                    {"match_phrase": {"command_line": "Register-ScheduledTask"}},
                ],
                "minimum_should_match": 1,
            }
        },
    ),
]


def sync_security_analytics_rules(index_name: str = DEFAULT_INDEX) -> dict[str, Any]:
    """Register Sigma rules & detector via OpenSearch Security Analytics API if enabled."""
    auth = (OPENSEARCH_USER, OPENSEARCH_PASSWORD) if OPENSEARCH_USER else None
    base = OPENSEARCH_URL.rstrip("/")

    try:
        with httpx.Client(timeout=6.0, verify=False, auth=auth) as http:
            probe = http.post(
                f"{base}/_plugins/_security_analytics/rules/_search",
                params={"pre_packaged": "true"},
                json={"size": 1, "query": {"match_all": {}}},
            )
            if probe.status_code >= 400:
                return {"sa_plugin_active": False, "synced_rules": 0}

            synced = 0
            rule_ids: list[str] = []
            for rule in SIGMA_RULES:
                resp = http.post(
                    f"{base}/_plugins/_security_analytics/rules",
                    params={"category": "windows"},
                    json={"rule": rule.sigma_yaml},
                )
                if resp.status_code in (200, 201):
                    synced += 1
                    payload = resp.json()
                    if "_id" in payload:
                        rule_ids.append(payload["_id"])

            detector_created = False
            if rule_ids:
                det_resp = http.post(
                    f"{base}/_plugins/_security_analytics/detectors",
                    json={
                        "name": f"forensiclens-{index_name}",
                        "detector_type": "windows",
                        "enabled": True,
                        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
                        "inputs": [
                            {
                                "detector_input": {
                                    "description": "ForensicLens automated ransomware triage",
                                    "indices": [index_name],
                                    "custom_rules": [{"id": rid} for rid in rule_ids],
                                    "pre_packaged_rules": [],
                                }
                            }
                        ],
                    },
                )
                detector_created = det_resp.status_code in (200, 201)

            return {
                "sa_plugin_active": True,
                "synced_rules": synced,
                "detector_created": detector_created,
            }
    except Exception:
        return {"sa_plugin_active": False, "synced_rules": 0}


def _tag_matching_documents(
    client: OpenSearch,
    index_name: str,
    rule: SigmaRuleDefinition,
    triage_ts: str,
) -> int:
    """Run an idempotent update_by_query to tag documents matching a Sigma rule."""
    alert_obj = {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique,
        "description": rule.description,
    }

    painless_script = """
    if (ctx._source.sigma_rule_ids == null) {
        ctx._source.sigma_rule_ids = [];
    }
    if (ctx._source.sigma_alerts == null) {
        ctx._source.sigma_alerts = [];
    }
    if (!ctx._source.sigma_rule_ids.contains(params.alert.rule_id)) {
        ctx._source.sigma_rule_ids.add(params.alert.rule_id);
        ctx._source.sigma_alerts.add(params.alert);
    }
    ctx._source.sigma_flagged = true;
    ctx._source.triage_timestamp = params.ts;
    def current = ctx._source.sigma_severity != null ? ctx._source.sigma_severity : "none";
    if (params.ranks.getOrDefault(params.alert.severity, 0) >= params.ranks.getOrDefault(current, 0)) {
        ctx._source.sigma_severity = params.alert.severity;
    }
    """

    response = client.update_by_query(
        index=index_name,
        body={
            "query": rule.dsl_query,
            "script": {
                "source": painless_script,
                "lang": "painless",
                "params": {
                    "alert": alert_obj,
                    "ts": triage_ts,
                    "ranks": SEVERITY_RANK,
                },
            },
        },
        conflicts="proceed",
        refresh=True,
    )
    return int(response.get("updated", 0))


def run_sigma_triage(
    index_name: str = DEFAULT_INDEX,
    sync_sa: bool = True,
) -> dict[str, Any]:
    """Scan OpenSearch forensic index for Sigma ransomware TTPs and tag matching events."""
    client = get_opensearch_client()
    if not client.indices.exists(index=index_name):
        return {
            "index": index_name,
            "total_matched": 0,
            "rules_triggered": [],
            "security_analytics": {"sa_plugin_active": False, "synced_rules": 0},
        }

    sa_status = (
        sync_security_analytics_rules(index_name)
        if sync_sa
        else {"sa_plugin_active": False, "synced_rules": 0}
    )

    triage_ts = datetime.now(timezone.utc).isoformat()
    rule_results: list[dict[str, Any]] = []
    total_tagged = 0

    for rule in SIGMA_RULES:
        matched_count = _tag_matching_documents(client, index_name, rule, triage_ts)
        total_tagged += matched_count
        rule_results.append(
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "mitre_tactic": rule.mitre_tactic,
                "mitre_technique": rule.mitre_technique,
                "matched_events": matched_count,
            }
        )

    client.indices.refresh(index=index_name)
    flagged_total = client.count(
        index=index_name,
        body={"query": {"term": {"sigma_flagged": True}}},
    ).get("count", 0)

    return {
        "index": index_name,
        "triage_timestamp": triage_ts,
        "total_rule_hits": total_tagged,
        "flagged_documents": int(flagged_total),
        "rules_triggered": rule_results,
        "security_analytics": sa_status,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ForensicLens: Run automated Sigma triage against OpenSearch logs."
    )
    parser.add_argument("--index", default=DEFAULT_INDEX, help="OpenSearch index name")
    parser.add_argument(
        "--skip-sa-sync",
        action="store_true",
        help="Skip OpenSearch Security Analytics API rule registration",
    )
    args = parser.parse_args()

    summary = run_sigma_triage(index_name=args.index, sync_sa=not args.skip_sa_sync)

    table = Table(title=f"ForensicLens Sigma Triage — {summary['index']}")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("MITRE", style="magenta")
    table.add_column("Detection Title")
    table.add_column("Matched", justify="right")

    for row in summary["rules_triggered"]:
        sev_style = "red" if row["severity"] == "critical" else "yellow"
        table.add_row(
            row["rule_id"],
            f"[{sev_style}]{row['severity'].upper()}[/{sev_style}]",
            f"{row['mitre_tactic']} ({row['mitre_technique']})",
            row["title"],
            str(row["matched_events"]),
        )

    console.print(table)
    console.print(
        f"Total flagged documents in index: [bold]{summary['flagged_documents']}[/bold]"
    )


if __name__ == "__main__":
    main()
