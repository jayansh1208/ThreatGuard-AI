# ThreatGuard AI

ThreatGuard AI is a multi-tenant security operations workspace for threat intelligence, Windows endpoint evidence, vulnerability review, security documents, and AI-assisted investigations. It uses FastAPI, MongoDB, Streamlit, and an optional Windows endpoint agent.

## Features

- JWT authentication and role-based access, with organization and tenant scope enforced by the API.
- Dark Streamlit SOC dashboard with API-backed threat metrics, stored scan activity, and quick links to existing tools.
- Windows read-only scanner history and an optional local endpoint agent for on-demand host scans.
- CVE, ATT&CK, CAPEC, Sigma, and CISA KEV intelligence search, ingestion, source details, and relationships.
- Tenant-scoped Knowledge Base uploads and semantic retrieval for PDF, TXT, and Markdown references.
- AI Security Assistant with conversation history, Gemini/OpenAI/Ollama provider support, source citations, and authorized stored scan context.
- MongoDB-backed audit, scan, document, intelligence, and conversation records.

## Architecture

| Service | Technology | Local address |
| --- | --- | --- |
| Database | MongoDB 7 | `127.0.0.1:27030` |
| API | FastAPI | `http://127.0.0.1:8000` |
| API docs | Swagger UI | `http://127.0.0.1:8000/docs` |
| Web application | Streamlit | `http://127.0.0.1:8501` |
| Endpoint agent bridge | Python on Windows host | `http://127.0.0.1:8765` |

The app stores tenant records in MongoDB collections including `threats`, `scan_results`, `endpoint_scans`, `kb_documents`, `kb_chunks`, `chat_sessions`, and `audit_logs`. Named `mongo_data` and `embedding_cache` volumes persist across container restarts.

## Quick start with Docker Compose

Use PowerShell from the repository root:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Edit `.env` and set a unique `JWT_SECRET_KEY` with at least 32 characters. Set the AI provider and its key if you want to use the assistant. The template defaults to Gemini; keys are blank until you supply them.

```powershell
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://127.0.0.1:8000/health
```

Create the first administrator only for a new development database. Set the six `THREATGUARD_BOOTSTRAP_*` variables in `.env`, then run this one-time command:

```powershell
docker compose exec backend python -m backend.app.bootstrap_admin --confirm
```

Sign in at the Streamlit address above. The UI and API use the existing authentication and role rules. Compose binds services to loopback for local access. **Do not use `docker compose down -v`** if MongoDB records or the embedding cache must be retained.

## AI provider configuration

Choose one provider in `.env` using `AI_PROVIDER`:

- `gemini`: set `GEMINI_API_KEY`; optional model setting is `GEMINI_MODEL` (default `gemini-2.5-flash`).
- `openai`: set `OPENAI_API_KEY`; optional model setting is `OPENAI_MODEL` (default `gpt-4o-mini`).
- `ollama`: run Ollama separately. For Docker Desktop, set `OLLAMA_BASE_URL=http://host.docker.internal:11434` and install the model named by `OLLAMA_MODEL` yourself.

The application never starts Ollama or exposes provider keys through the UI or API. Use `CHAT_RAG_ENABLED`, `CHAT_RAG_TOP_K`, `CHAT_RAG_MIN_SIMILARITY`, `CHAT_INTELLIGENCE_ENABLED`, `CHAT_INTELLIGENCE_TOP_K`, `CHAT_INTELLIGENCE_RELATIONSHIP_LIMIT`, and `CHAT_SCANNER_CONTEXT_LIMIT` to tune retrieval. AI responses are bounded by configured history, context, token, timeout, and rate limits.

## Windows endpoint agent

The separate agent runs on Windows 10/11 with Python 3.11 or newer. It performs read-only checks and submits bounded reports to the authenticated API. Review [endpoint-agent/README.md](endpoint-agent/README.md) for installation, privacy details, and limitations.

From PowerShell:

```powershell
cd endpoint-agent
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python agent.py --check-connection
python agent.py --serve
```

The bridge runs in the foreground, requires consent, and is not installed as a service or startup task. Use the Endpoint Security page to request an authenticated scan. The dashboard shows actual agent stages while scanning, blocks duplicate requests, and recovers active status from the URL and the agent's persisted state journal after a browser refresh. It reports success only after the backend stores the matching scan ID, then selects and opens that report automatically. Scan History retains earlier reports with per-scan TXT, JSON, and CSV downloads and a full report view. Stop the agent with Ctrl+C. Endpoint scan reports are accessible to their authenticated uploader; legacy scanner records are tenant-scoped. The assistant includes stored scanner and endpoint evidence for the authenticated account when enabled, and reports an empty state when none is available.

## Native Windows scanner

The existing CLI scanner is separate from the agent bridge. It runs on the Windows host and gathers read-only process, network, startup, and Defender observations. It does not execute remediation commands. Incomplete collector coverage is disclosed rather than presented as a clean bill of health; raw inventory observations are not automatically treated as findings.

```powershell
python -m scanner.cli --limit 20
```

The optional `--limit` caps the combined report findings (default 20; zero is allowed). The scanner can export its report as JSON for the authenticated scanner API workflow.

## Knowledge Base and embeddings

The backend uses `sentence-transformers/all-MiniLM-L6-v2` (384-dimensional vectors) by default and stores embeddings in MongoDB. The first embedding request may download the model; Compose stores its cache in the persistent `embedding_cache` volume. CPU is the default device; set `EMBEDDING_DEVICE=cuda` only when the container has a compatible runtime.

The Knowledge Base accepts PDF, UTF-8 TXT, and Markdown files up to `KB_MAX_UPLOAD_BYTES` (10 MiB by default). Retrieval returns tenant-visible excerpts and source metadata. Uploaded documents are parsed as data and are never executed.

## Intelligence data

Threat intelligence datasets are imported through the Intelligence page by a user with write permission. Imports use public upstream datasets and are bounded by settings such as `NVD_INITIAL_MAX_RECORDS`, `NVD_PAGE_SIZE`, `NVD_REQUEST_DELAY`, `INGESTION_BATCH_SIZE`, and `INGESTION_TIMEOUT_SECONDS`. Source and ingestion-job records are retained for the tenant. Dataset imports are not part of container startup.

## Useful API route groups

- `/auth` — login, logout, current user, and user administration.
- `/dashboard/metrics` — tenant dashboard metrics and recent activity.
- `/scanner/scans` — existing scanner report history and details.
- `/endpoint/scans` — authenticated endpoint scan upload, history, and details.
- `/intelligence` — search, statistics, records, relationships, sources, jobs, and imports.
- `/knowledge` — document management and semantic search.
- `/chat` — provider status, conversations, messages, citations, and explanations.
- `/threats`, `/organizations`, and `/tenants` — security records and administration.

Open `/docs` for the API schema. Tenant and organization identifiers are taken from the authenticated user context rather than trusted from arbitrary request bodies.

## Development and tests

Install backend dependencies and run tests from the repository root:

```powershell
python -m pip install -r backend/requirements.txt
python -m pytest -q
```

Frontend dependencies are listed in `frontend/requirements.txt`. Compile the Streamlit application with:

```powershell
python -m compileall frontend
```

Endpoint agent tests and chat tests use mocked collectors/providers and test tenant boundaries without contacting paid AI APIs. The real embedding integration test is opt-in:

```powershell
$env:THREATGUARD_RUN_EMBEDDING_INTEGRATION = "1"
python -m pytest tests/test_phase4a_knowledge.py -q
```

## Security and data notes

- Never commit `.env`, API keys, JWT secrets, agent credentials, scan reports containing host data, or MongoDB volumes.
- `.env.example` contains blank secret fields and safe local defaults. Copy it to `.env` and configure secrets locally.
- Endpoint scans are read-only observations. The agent does not remediate hosts, install persistence, or execute AI-generated commands.
- Knowledge documents and retrieved records are treated as untrusted evidence by the assistant.
- Preserve `mongo_data` when updating the app. Do not use `docker compose down -v` to restart services.

## Repository layout

```text
backend/          FastAPI routes, authentication, database, AI, retrieval, and ingestion
frontend/         Streamlit pages, shared styling, and theme configuration
endpoint-agent/   Optional Windows read-only endpoint scanner and local bridge
scanner/          Existing native scanner
tests/            Backend, endpoint, intelligence, knowledge, and chatbot tests
docker-compose.yml
```
