"""Hybrid Search (OpenSearch DSL + k-NN vector similarity) and Ollama Forensic Copilot."""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel

from src.config import (
    DEFAULT_INDEX,
    OLLAMA_MODEL,
    OLLAMA_URL,
    get_embedder,
    get_opensearch_client,
)

console = Console()

DSL_SYSTEM_PROMPT = """You are an OpenSearch Query DSL generator for Windows digital forensics logs.
Available index fields:
- timestamp (date)
- event_id (keyword: e.g. "4624", "4688", "10", "1", "4778")
- host (keyword)
- user (keyword)
- process_name (text + .keyword)
- command_line (text + .keyword)
- target_image (text + .keyword)
- granted_access (keyword)
- logon_type (keyword)
- source_ip (ip)
- sigma_flagged (boolean)
- sigma_severity (keyword: "critical", "high", "medium", "low", "none")
- message (text)

Return ONLY a valid JSON object representing the OpenSearch "query" clause (no markdown fences, no explanation).
If the question is broad, return {"match_all": {}}.
"""

MODE_INSTRUCTIONS = {
    "investigate": (
        "Active Mode: TIMELINE & ROOT CAUSE. Reconstruct the chronological attack chain, "
        "highlight MITRE ATT&CK techniques, compromised users, hosts, and exact commands."
    ),
    "hunt": (
        "Active Mode: THREAT HUNT. Correlate pivot points across hosts, users, parent/child "
        "processes, logon types, and external IPs, and suggest next artifacts to check."
    ),
    "remediate": (
        "Active Mode: CONTAIN & REMEDIATE. Provide immediate host containment, credential "
        "revocation, and forensic preservation steps with exact Windows PowerShell commands."
    ),
    "sigma_rule": (
        "Active Mode: SIGMA RULE BUILDER. Author a Sigma YAML detection rule and matching "
        "OpenSearch DSL query targeting the observed adversary behavior."
    ),
}

SUMMARY_SYSTEM_PROMPT = """You are ForensicLens, a senior DFIR (Digital Forensics & Incident Response) analyst.
Answer the investigator's question strictly using the provided Windows log evidence.
Rules:
1. Cite every factual claim inline using exact citation tokens formatted as [DOC:<doc_id>], e.g. [DOC:9f82a1b4c3d0e1f2a3b4c5d6].
2. Highlight timeline order, MITRE ATT&CK techniques, affected hosts, users, and exact commands.
3. Never invent log entries, IP addresses, or PIDs not present in the evidence.
4. Keep the response crisp, structured, and actionable for incident responders.
5. End with a single line starting with FOLLOWUPS_JSON: followed by a JSON array of 3 concise follow-up questions.
"""


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    """Safely extract a JSON object from an LLM response."""
    cleaned = raw_text.strip()
    fence_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, flags=re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        cleaned = cleaned[start : end + 1]

    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object")
    if "query" in parsed and len(parsed) == 1 and isinstance(parsed["query"], dict):
        return parsed["query"]
    return parsed


def translate_question_to_dsl(question: str) -> dict[str, Any]:
    """Ask local Ollama to convert an investigator question into an OpenSearch query DSL."""
    try:
        with httpx.Client(timeout=20.0) as http:
            resp = http.post(
                f"{OLLAMA_URL.rstrip('/')}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "stream": False,
                    "options": {"temperature": 0.0},
                    "messages": [
                        {"role": "system", "content": DSL_SYSTEM_PROMPT},
                        {"role": "user", "content": question},
                    ],
                },
            )
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
            dsl = _extract_json_object(content)
            return dsl
    except Exception:
        return {
            "multi_match": {
                "query": question,
                "fields": [
                    "command_line^3",
                    "process_name^2",
                    "message^2",
                    "target_image",
                    "user",
                    "host",
                    "event_id",
                ],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        }


def run_hybrid_search(
    question: str,
    index_name: str = DEFAULT_INDEX,
    size: int = 8,
) -> dict[str, Any]:
    """Execute Hybrid Search (DSL filter/boost + 384-dim k-NN vector similarity)."""
    client = get_opensearch_client()
    if not client.indices.exists(index=index_name):
        return {"dsl_query": {"match_all": {}}, "hits": []}

    structured_dsl = translate_question_to_dsl(question)
    embedder = get_embedder()
    query_vec = [float(x) for x in embedder.encode(question, normalize_embeddings=True)]

    hybrid_body: dict[str, Any] = {
        "size": size,
        "_source": {
            "excludes": ["command_embedding", "raw_event"],
        },
        "query": {
            "bool": {
                "should": [
                    structured_dsl,
                    {
                        "knn": {
                            "command_embedding": {
                                "vector": query_vec,
                                "k": size,
                            }
                        }
                    },
                    {
                        "term": {
                            "sigma_flagged": {
                                "value": True,
                                "boost": 1.5,
                            }
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
    }

    try:
        res = client.search(index=index_name, body=hybrid_body)
    except Exception:
        # Fallback to pure k-NN + multi_match if LLM-generated DSL had a field mismatch
        fallback_dsl = {
            "multi_match": {
                "query": question,
                "fields": ["command_line^3", "process_name^2", "message", "user", "host"],
            }
        }
        hybrid_body["query"]["bool"]["should"][0] = fallback_dsl
        structured_dsl = fallback_dsl
        res = client.search(index=index_name, body=hybrid_body)

    hits: list[dict[str, Any]] = []
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        hits.append(
            {
                "doc_id": hit.get("_id"),
                "score": round(float(hit.get("_score") or 0.0), 4),
                **src,
            }
        )

    return {"dsl_query": structured_dsl, "hits": hits}


def ask_forensic_copilot(
    question: str,
    index_name: str = DEFAULT_INDEX,
    size: int = 8,
    mode: str = "investigate",
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Run Hybrid Search and generate a multi-turn, evidence-cited answer via local Ollama."""
    safe_mode = mode if mode in MODE_INSTRUCTIONS else "investigate"
    search_result = run_hybrid_search(question, index_name=index_name, size=size)
    hits = search_result["hits"]

    if not hits:
        return {
            "answer": (
                "No matching log events were found in the active case index. "
                "Upload a Windows .evtx or .jsonl file to begin investigation."
            ),
            "citations": [],
            "dsl_query": search_result["dsl_query"],
            "mitre_techniques": [],
            "follow_ups": [
                "Upload a Windows .evtx or .jsonl file to start",
            ],
        }

    mitre_techniques: list[str] = []
    evidence_lines: list[str] = []
    for item in hits:
        alerts = ", ".join(a.get("title", "") for a in item.get("sigma_alerts", []))
        for alert in item.get("sigma_alerts", []):
            tech = f"{alert.get('mitre_technique', '')} ({alert.get('mitre_tactic', '')})".strip()
            if tech and tech not in mitre_techniques:
                mitre_techniques.append(tech)
        evidence_lines.append(
            f"[DOC:{item['doc_id']}] "
            f"Time={item.get('timestamp', '')} | "
            f"Host={item.get('host', '')} | "
            f"User={item.get('user', '')} | "
            f"EventID={item.get('event_id', '')} | "
            f"Process={item.get('process_name', '')} | "
            f"CommandLine={item.get('command_line', '')} | "
            f"TargetImage={item.get('target_image', '')} | "
            f"SourceIP={item.get('source_ip', '')} | "
            f"SigmaAlerts={alerts or 'None'}"
        )

    history_text = ""
    if history:
        turns = [
            f"{'Investigator' if h.get('role') == 'user' else 'Copilot'}: {h.get('content', '')}"
            for h in history[-8:]
            if h.get("content")
        ]
        if turns:
            history_text = "Previous Conversation:\n" + "\n".join(turns) + "\n\n"

    user_prompt = (
        f"{history_text}"
        f"Investigator Question ({safe_mode.upper()} mode): {question}\n\n"
        f"Retrieved OpenSearch Evidence ({len(hits)} events):\n"
        + "\n".join(evidence_lines)
    )

    system_prompt = f"{SUMMARY_SYSTEM_PROMPT}\n{MODE_INSTRUCTIONS[safe_mode]}"
    follow_ups = [
        "Hunt for lateral movement indicators",
        "Generate containment PowerShell commands",
        "Write a Sigma rule for this attack",
    ]

    try:
        with httpx.Client(timeout=45.0) as http:
            resp = http.post(
                f"{OLLAMA_URL.rstrip('/')}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "stream": False,
                    "options": {"temperature": 0.1},
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                },
            )
            resp.raise_for_status()
            raw_answer = resp.json().get("message", {}).get("content", "").strip()
            if "FOLLOWUPS_JSON:" in raw_answer:
                main_part, tail = raw_answer.split("FOLLOWUPS_JSON:", 1)
                answer = main_part.strip()
                arr_match = re.search(r"\[[\s\S]*\]", tail)
                if arr_match:
                    try:
                        parsed = json.loads(arr_match.group(0))
                        if isinstance(parsed, list):
                            cleaned = [str(x).strip() for x in parsed if str(x).strip()][:3]
                            if cleaned:
                                follow_ups = cleaned
                    except Exception:
                        pass
            else:
                answer = raw_answer
    except Exception as exc:
        cited = "\n".join(
            f"- [DOC:{h['doc_id']}] {h.get('timestamp', '')} — Event {h.get('event_id', '')} "
            f"on {h.get('host', '')}: {h.get('command_line') or h.get('message', '')}"
            for h in hits[:5]
        )
        answer = (
            f"Ollama synthesis is unavailable ({type(exc).__name__}), showing top Hybrid Search "
            f"matches directly from OpenSearch:\n\n{cited}"
        )

    return {
        "answer": answer,
        "citations": hits,
        "dsl_query": search_result["dsl_query"],
        "mitre_techniques": mitre_techniques,
        "follow_ups": follow_ups,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ForensicLens CLI: Natural-language hybrid search + Ollama triage."
    )
    parser.add_argument("question", help="Natural-language forensic investigation question")
    parser.add_argument("--index", default=DEFAULT_INDEX, help="OpenSearch index name")
    parser.add_argument("--top-k", type=int, default=8, help="Number of evidence docs")
    args = parser.parse_args()

    result = ask_forensic_copilot(args.question, index_name=args.index, size=args.top_k)
    console.print(Panel(result["answer"], title="ForensicLens Copilot Summary", border_style="cyan"))


if __name__ == "__main__":
    main()
