# Security Policy

## Local-First Privacy Model

ForensicLens is designed to analyze sensitive incident response artifacts (`.evtx`, `.jsonl`) **100% locally** on the investigator's workstation:
- Log files are parsed locally and indexed into your local OpenSearch instance.
- Semantic embeddings (`all-MiniLM-L6-v2`) and natural-language summarization (`Ollama`) execute locally with no outbound telemetry.

## Built-in Safeguards

- **Upload Confinement**: Uploaded artifacts are validated by file extension (`.evtx`, `.jsonl`, `.json`), size-capped while streaming, written to an isolated temporary directory with resolved-path containment checks, and deleted immediately after indexing.
- **XSS Prevention**: The browser workbench builds all log rows, raw JSON views, decoded scripts, and `[DOC:<id>]` citation buttons using safe DOM `textContent` bindings rather than raw HTML injection.
- **Input Validation**: Case index names and document identifiers are strictly validated before querying OpenSearch.

## Reporting a Vulnerability

Please report security issues privately by opening a GitHub Security Advisory on the repository rather than filing a public issue with exploit details.
