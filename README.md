# ForensicLens

**AI-Powered Windows Digital Forensics, Threat Hunting & Sigma Triage Workbench**

ForensicLens turns raw Windows Event Logs (`.evtx` and `.jsonl`) into an interactive forensic investigation workspace. Designed for **100% offline Windows 11 incident response** (via FastAPI, OpenSearch 3.x, and local Ollama `llama3.2`) as well as **instant browser deployment** (via React, Express, and server-side Gemini streaming).

---

## Key Capabilities

- **Live Animated MITRE Threat Radar & Severity Gauges**: Maps detections across 6 MITRE ATT&CK tactics (*Lateral Movement, Execution, Defense Evasion, Credential Access, Impact, Persistence*) with clickable tactic and radial severity filters.
- **Interactive Attack Timeline & Entity Graph**: Reconstructs chronological sequence steps (`T1..Tn`) and renders a 5-column lateral-movement graph (`Source IP -> Host -> User -> Process -> Target`) with clickable node isolation.
- **Automated Sigma Triage (`src/sigma_triage.py`)**: Syncs with OpenSearch Security Analytics when active and evaluates 6 deterministic Sigma-mapped detection rules with MITRE ATT&CK tagging.
- **Multi-Turn 4-Mode DFIR AI Copilot**: Switch between **Investigate**, **Threat Hunt**, **Contain**, and **Sigma Rule** modes with conversation memory, clickable `[DOC:<id>]` event citations, OpenSearch DSL previews, dynamic follow-ups, and one-click code copy.
- **Built-in PowerShell Base64 Decoder**: Automatically decodes `-EncodedCommand` / `-enc` UTF-16LE payloads inside the slide-over Evidence Inspector.
- **Session Archiving & Portable Exports**: **Clear Chat** archives investigations into **History** so analysts can switch cases or reopen past timelines anytime; **Export Report** outputs clean JSON findings.
- **Dual Runtime Support**:
  - **Offline Windows 11 Workbench**: FastAPI (`src/app.py`) + zero-build UI (`static/index.html`) + OpenSearch k-NN + Ollama.
  - **Live Web Workbench**: React + Vite + Express (`server.ts`) with SSE streaming (`@google/genai`).

---

## Architecture

```text
+----------------------------------------------------------------------------------+
|  ForensicLens Light Ice-Lab UI                                                   |
|  - Web App: React + Vite (src/App.tsx)                                           |
|  - Offline Windows UI: Zero-build HTML/Tailwind (static/index.html)              |
|  [Left Command Rail] [Threat Radar & Gauges] [Attack Graph] [4-Mode AI Copilot]  |
+----------------------------------------+-----------------------------------------+
                                         |
             +---------------------------+---------------------------+
             | Offline Windows 11 Mode                               | Live Web Mode
             v                                                       v
+----------------------------------------+             +---------------------------+
| FastAPI Backend (src/app.py)           |             | Express Server (server.ts)|
|  - POST   /api/upload -> ingest.py     |             |  - POST /api/copilot/     |
|  - POST   /api/triage -> sigma_triage  |             |    stream (SSE + retry/   |
|  - POST   /api/chat   -> query_cli.py  |             |    fallback via Gemini)   |
|  - GET    /api/export -> JSON report   |             +---------------------------+
|  - DELETE /api/case   -> Reset index   |
+-------------------+--------------------+
                    |
        +-----------+-----------+
        v                       v
+-----------------------+  +-----------------------+
| OpenSearch 3.x        |  | Local Ollama          |
| - 384-dim k-NN HNSW   |  | - llama3.2 NL-to-DSL  |
| - Security Analytics  |  | - Cited DFIR triage   |
+-----------------------+  +-----------------------+
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

## Quickstart 1: Offline Windows 11 Stack (FastAPI + OpenSearch + Ollama)

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

Open **`http://127.0.0.1:8000`** and drag-and-drop any Windows `.evtx` file (e.g. `C:\Windows\System32\winevt\Logs\Security.evtx` or `Microsoft-Windows-Sysmon%4Operational.evtx`) or `.jsonl` telemetry.

---

## Quickstart 2: Live Web Workbench (Node.js + React + Gemini)

```bash
npm install
cp .env.example .env   # Add your GEMINI_API_KEY
npm run dev
```

Open **`http://localhost:3000`** and drop a `.jsonl` or `.json` Windows event log export to start triaging.

---

## CLI & Testing

Run Python unit tests:

```powershell
pytest -v
```

Run standalone ingestion, triage, or CLI investigation:

```powershell
python -m src.ingest --file C:\Windows\System32\winevt\Logs\Security.evtx --index forensic-case-001
python -m src.sigma_triage --index forensic-case-001
python -m src.query_cli "Trace lateral movement and LSASS access across indexed hosts"
```

Verify frontend TypeScript & production build:

```bash
npm run lint
npm run build
```

---

## Project Structure

```text
ForensicLens/
├── .github/workflows/ci.yml              # GitHub Actions CI (compile + pytest)
├── docker-compose.yml                    # OpenSearch, Dashboards & Ollama services
├── requirements.txt                      # Python backend dependencies
├── package.json                          # React + Express dependencies & scripts
├── server.ts                             # Express SSE Gemini Copilot server
├── .env.example                          # Environment variables template
├── CONTRIBUTING.md                       # Contributor & Sigma rule guide
├── SECURITY.md                           # Local-first privacy & security policy
├── LICENSE                               # MIT License
├── README.md
├── static/
│   └── index.html                        # Zero-build Light Ice-Lab Windows UI
├── tests/
│   └── test_forensiclens.py              # Pytest suite
└── src/
    ├── __init__.py
    ├── config.py                         # Windows-safe paths, OpenSearch & embedder cache
    ├── ingest.py                         # .evtx / .jsonl parser + 384-dim embeddings
    ├── sigma_triage.py                   # 6 automated Sigma rules & document tagging
    ├── query_cli.py                      # Hybrid Search (DSL + k-NN) + Ollama Copilot
    ├── app.py                            # FastAPI server, Base64 decoder, export & reset API
    ├── App.tsx                           # React Light Ice-Lab workbench
    ├── index.css                         # Tailwind CSS & radar animation styles
    ├── types/
    │   └── forensics.ts                  # Shared forensic telemetry & Copilot types
    └── components/
        ├── ThreatTelemetryHud.tsx        # Animated MITRE Threat Radar & Radial Gauges
        └── AttackGraphPanel.tsx          # Chronological timeline & entity relationship graph
```

---

## Contributing & License

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
Licensed under the [MIT License](LICENSE).
