# ForensicLens

**100% Local, AI-Powered Windows Digital Forensics & Sigma Triage Workbench**

ForensicLens helps incident responders and analysts investigate Windows Event Logs (`.evtx` and `.jsonl`) completely offline on Windows 11. It combines **OpenSearch** hybrid search (structured DSL + `all-MiniLM-L6-v2` k-NN vector similarity), automated **Sigma ransomware detection**, automatic **PowerShell Base64 decoding**, and a **local Ollama (`llama3.2`)** copilot with clickable evidence citations.

---

## Key Capabilities

- **Zero-Build Web Workbench (`static/index.html`)**: Served directly by FastAPI—no Node.js/npm build required on Windows.
- **Automated Sigma Triage (`src/sigma_triage.py`)**: Syncs with OpenSearch Security Analytics when active and runs 6 deterministic Sigma-mapped detection rules with MITRE ATT&CK tagging.
- **Hybrid Search + Local AI Copilot (`src/query_cli.py`)**: Translates plain-English questions into OpenSearch DSL, blends results with 384-dim `all-MiniLM-L6-v2` vector search, and cites exact `[DOC:<id>]` log events.
- **Built-in PowerShell Base64 Decoder**: Automatically decodes `-EncodedCommand` / `-enc` UTF-16LE payloads inside the Evidence Inspector.
- **Portable Incident Reports & One-Click Reset**: Export flagged findings via **Export Report** (`GET /api/export`) or wipe case history via **Clear History** (`DELETE /api/case`).

---

## Architecture

```text
+-----------------------------------------------------------------------------+
|  Windows 11 Browser Workbench  (static/index.html - Zero-Build Tailwind)    |
|  [Drag & Drop .evtx/.jsonl]  [Sigma Alert Feed]  [Copilot + Citations]      |
+-------------------------------------+---------------------------------------+
                                      | HTTP (127.0.0.1:8000)
                                      v
+-----------------------------------------------------------------------------+
|  FastAPI Backend (src/app.py)                                               |
|   ├── POST   /api/upload  ──> src/ingest.py (.evtx + all-MiniLM-L6-v2)      |
|   ├── POST   /api/triage  ──> src/sigma_triage.py (Security Analytics + DSL)|
|   ├── POST   /api/chat    ──> src/query_cli.py (Hybrid DSL + k-NN + Ollama) |
|   ├── GET    /api/export  ──> Portable JSON Incident Report                 |
|   └── DELETE /api/case    ──> Clear History & Reset OpenSearch Index        |
+-----------------------+-----------------------------------+-----------------+
                        |                                   |
                        v                                   v
+---------------------------------------+   +---------------------------------+
| OpenSearch 3.x (localhost:9200)       |   | Local Ollama (localhost:11434)  |
|  - knn_vector (HNSW cosinesimil)      |   |  - llama3.2 DSL translation     |
|  - Security Analytics Sigma detectors |   |  - Evidence-cited DFIR summary  |
+---------------------------------------+   +---------------------------------+
```

---

## Automated Sigma Detection Coverage

| Rule ID | Detection | Severity | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| `fl-sigma-001` | Shadow copy & backup deletion (`vssadmin`, `wmic`, `bcdedit`, `wbadmin`) | Critical | Impact (`T1490`) |
| `fl-sigma-002` | LSASS memory dump (`Sysmon Event 10`, `comsvcs.dll`, `procdump`, `mimikatz`) | Critical | Credential Access (`T1003.001`) |
| `fl-sigma-003` | Encoded / hidden PowerShell (`-EncodedCommand`, `-enc`, `FromBase64String`) | High | Execution (`T1059.001`) |
| `fl-sigma-004` | RDP lateral movement (`4624 Type 10`, `4778/4779`, `mstsc.exe`, `tscon.exe`) | High | Lateral Movement (`T1021.001`) |
| `fl-sigma-005` | Windows Defender / security service tampering (`DisableRealtimeMonitoring`, `WinDefend`) | Critical | Defense Evasion (`T1562.001`) |
| `fl-sigma-006` | Scheduled task persistence (`schtasks /create`, `Register-ScheduledTask`) | Medium | Persistence (`T1053.005`) |

---

## Windows 11 Quickstart (PowerShell)

### 1. Start OpenSearch & Ollama Containers

```powershell
docker compose up -d
docker exec -it forensic-ollama ollama pull llama3.2
```

### 2. Create Python Virtual Environment & Install Dependencies

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

### 3. Launch ForensicLens

```powershell
uvicorn src.app:app --host 127.0.0.1 --port 8000 --reload
```

Open **`http://127.0.0.1:8000`** and drag-and-drop any Windows `.evtx` file (e.g., `C:\Windows\System32\winevt\Logs\Security.evtx` or `Microsoft-Windows-Sysmon%4Operational.evtx`) or exported `.jsonl` telemetry.

---

## CLI & Testing

Run unit tests:

```powershell
pytest -v
```

Run standalone ingestion, triage, or CLI investigation:

```powershell
python -m src.ingest --file C:\Windows\System32\winevt\Logs\Security.evtx --index forensic-case-001
python -m src.sigma_triage --index forensic-case-001
python -m src.query_cli "Trace lateral movement and LSASS access across indexed hosts"
```

---

## Open-Source Project Layout

```text
ForensicLens/
├── .github/workflows/ci.yml          # GitHub Actions CI (compile + pytest)
├── docker-compose.yml                # OpenSearch, Dashboards, and Ollama services
├── requirements.txt                  # Python dependencies
├── .env.example                      # Local service endpoints and index defaults
├── CONTRIBUTING.md                   # Contributor & Sigma rule guide
├── SECURITY.md                       # Local-first privacy & security policy
├── LICENSE                           # MIT License
├── README.md
├── static/
│   └── index.html                    # Zero-build workbench UI
├── tests/
│   └── test_forensiclens.py          # Pytest suite
└── src/
    ├── __init__.py
    ├── config.py                     # Windows-safe paths, OpenSearch & embedder cache
    ├── ingest.py                     # .evtx / .jsonl parser + 384-dim embeddings
    ├── sigma_triage.py               # 6 automated Sigma rules & document tagging
    ├── query_cli.py                  # Hybrid Search (DSL + k-NN) + Ollama Copilot
    └── app.py                        # FastAPI server, Base64 decoder, export & reset API
```

---

## Contributing & License

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).  
Licensed under the [MIT License](LICENSE).
