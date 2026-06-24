# Hexora

**AI-assisted static malware analysis for SOC analysts.**

Hexora is a self-contained web application that performs safe, read-only
static analysis on uploaded files — hashing, MIME/signature detection,
Shannon entropy, format-aware metadata extraction, and an explainable
0–100 heuristic risk score — without ever executing, importing, or
rendering the uploaded sample.

> **Security note:** Hexora performs *static* analysis only. It is a
> triage aid, not a verdict engine — corroborate findings with sandboxed
> dynamic analysis and threat-intelligence lookups before acting on them.

---

## Features

- **Drag-and-drop upload** with progress indicator, 100 MB default limit (configurable).
- **Static analysis**: SHA-256 / SHA-1 / MD5, signature-based MIME & category detection
  (executable / document / archive / image / script), Shannon entropy, and
  format-aware metadata:
  - **PE** (EXE/DLL): machine type, subsystem, characteristics, section table with
    per-section entropy, packer-name detection (UPX, ASPack, Petite), digital-signature presence.
  - **ELF**: format, endianness, machine, entry point.
  - **PDF**: page count, author/producer, JavaScript / OpenAction / Launch-action detection.
  - **Office** (OOXML & legacy OLE2): embedded VBA macro detection.
  - **Archives** (ZIP/JAR/APK): member listing, compression-ratio zip-bomb heuristic,
    encrypted-archive flag — via central-directory listing only, never extraction.
  - **Images**: dimensions, format, EXIF presence (Pillow header parse).
  - **Strings**: 25+ known attacker-tooling patterns (PowerShell encoded commands, LOLBins,
    persistence mechanisms, reverse shells, macro auto-exec, ransomware indicators), plus
    extracted URLs/IPs.
- **Explainable 0–100 risk score** — every point is tied to a stated reason, with
  tailored analyst recommendations.
- **Dashboard**: total scans, high/critical counts, average score, risk & category
  distribution charts, 7-day scan volume, recent uploads table.
- **Scan history**: search by filename/hash, filter by risk level/category/date range,
  sortable columns, pagination.
- **Scan result page**: full identification, risk ledger with point breakdown, format-specific
  metadata, PE section table, one-click hash copy, PDF report download.
- **Branded PDF export** for every scan (reportlab-generated, works offline).
- **Responsive UI**: sidebar nav on desktop, bottom tab bar on mobile.
- **Toasts, keyboard shortcuts** (`/` for global search, `U`/`D`/`H` to navigate pages),
  light/dark theme toggle.
- **Security-hardened by design**: random on-disk filenames (eliminates path traversal),
  sanitized display names, streamed upload size enforcement, parameterized queries,
  uploads stored outside any served path, optional API-key gate for write endpoints.

## Architecture

```text
Hexora/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app, middleware, static frontend mount
│   │   ├── config.py            Env-driven settings
│   │   ├── database.py          SQLAlchemy engine/session/init
│   │   ├── models.py            Scan ORM model
│   │   ├── schemas.py           Pydantic response models
│   │   ├── routers/
│   │   │   ├── scan.py          POST /api/scans, GET /api/scans/{id}
│   │   │   ├── history.py       GET /api/scans (paginated, filtered)
│   │   │   ├── dashboard.py     GET /api/dashboard/stats
│   │   │   └── reports.py       GET /api/scans/{id}/report
│   │   ├── services/
│   │   │   ├── file_ingest.py   Single-pass streaming hash + entropy + safe-write
│   │   │   ├── mime_detect.py   Pure-Python magic-byte MIME/category detection
│   │   │   ├── binary_analyzer.py  Struct-based PE and ELF header parsing
│   │   │   ├── metadata_extractor.py  Format-aware metadata per category
│   │   │   ├── strings_scan.py  Printable-string extraction + pattern matching
│   │   │   ├── risk_engine.py   Explainable heuristic risk scoring
│   │   │   └── pdf_report.py    Branded ReportLab PDF report generator
│   │   └── utils/security.py    Filename sanitization, safe storage names
│   ├── storage/                  DB + uploads (outside web root, gitignored)
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
├── frontend/
│   ├── index.html               Scan page
│   ├── dashboard.html           Dashboard
│   ├── history.html             Scan history
│   ├── result.html              Scan result detail
│   └── assets/
│       ├── css/styles.css       Design system (tokens, layout, components)
│       └── js/
│           ├── api.js           Typed fetch wrappers for all API endpoints
│           ├── common.js        Shell, sidebar, toasts, shortcuts, formatters
│           ├── scan.js          Upload page logic (drag-drop, progress, inline result)
│           ├── dashboard.js     Dashboard page + Chart.js charts
│           ├── history.js       History table, search/filter/sort/paginate
│           ├── result.js        Full result page (gauge, hash copy, metadata tree)
│           └── vendor/chart.umd.js  Chart.js bundled locally (no CDN dependency)
└── docker-compose.yml
```

The FastAPI process serves both the JSON API (`/api/*`) and the static frontend
(everything else), so the entire application is a single deployable unit.

## Quick start — local (no Docker)

Requires Python 3.11+.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000**. The SQLite database and `storage/uploads/` are
created automatically on first run.

## Quick start — Docker

```bash
docker compose up --build
```

Open **http://localhost:8000**. Data persists across restarts in the
`hexora_storage` named volume.

## Configuration

All settings are environment variables (see `backend/.env.example`):

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./storage/hexora.db` | Swap for `postgresql://...` to use Postgres; the ORM is dialect-agnostic. |
| `STORAGE_DIR` | `./storage` | Root for the DB and uploaded files. Keep outside any web-served path. |
| `MAX_UPLOAD_SIZE_MB` | `100` | Hard upload cap, enforced while streaming — not after-the-fact. |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS allow-list; tighten in production. |
| `API_KEY_ENABLED` / `API_KEY` | `false` / unset | Optional shared-secret gate on write endpoints. Recommended before exposing to the internet. |
| `STRINGS_SCAN_LIMIT_BYTES` | `8388608` (8 MiB) | How much of each file is scanned for suspicious strings. |
| `DEFAULT_PAGE_SIZE` | `20` | Default history page size. |

## Deploying to a VPS / cloud host

Hexora runs as a single process on port 8000. Put any TLS-terminating reverse
proxy in front:

**Nginx snippet:**
```nginx
server {
    listen 443 ssl;
    server_name scan.example.com;
    client_max_body_size 110M;      # match MAX_UPLOAD_SIZE_MB + headroom

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Then:
```bash
docker compose up -d --build
```

Set `API_KEY_ENABLED=true` with a strong `API_KEY` in production, and point
`DATABASE_URL` at a managed Postgres instance for multi-node or high-volume use.

## REST API

Interactive docs are auto-generated at:
- **`/docs`** — Swagger UI (try-it-out enabled)
- **`/redoc`** — ReDoc

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/scans` | Upload + analyze a file (multipart `file` field) |
| `GET` | `/api/scans/{id}` | Full scan detail JSON |
| `GET` | `/api/scans` | Paginated history — `?search=`, `risk_level=`, `category=`, `date_from=`, `date_to=`, `sort_by=`, `sort_dir=`, `page=`, `page_size=` |
| `GET` | `/api/scans/{id}/report` | Download branded PDF report |
| `GET` | `/api/dashboard/stats` | Aggregate dashboard statistics |
| `GET` | `/api/health` | Liveness check (`{"status":"ok"}`) |

**Example — scan a file from the command line:**
```bash
curl -X POST http://localhost:8000/api/scans \
     -F "file=@suspicious.exe" | python3 -m json.tool

# Download the report
curl http://localhost:8000/api/scans/<id>/report -o report.pdf

# With API key enabled
curl -X POST http://localhost:8000/api/scans \
     -H "X-API-Key: your-secret" \
     -F "file=@sample.doc"
```

## Security design decisions

| Concern | Mitigation |
| --- | --- |
| Path traversal | User-supplied filename is sanitized for display only; the on-disk name is a UUID generated by the server. |
| Upload flooding / disk exhaustion | Upload size is enforced while streaming; partial files are deleted on limit-exceeded. |
| Malicious archive extraction | Archives are inspected by listing central-directory entries only — no `extractall`, no temp extraction. |
| Code execution of samples | Zero shell-outs, zero `eval`/`exec`, zero `importlib`. Analysis is purely struct-unpacking, regex, and hash computation over raw bytes. |
| SQL injection | All queries go through the SQLAlchemy ORM (parameterized). |
| XSS | All user-controlled strings are passed through `escapeHtml()` before insertion into `innerHTML`; SHA hashes displayed in `textContent` only. |
| Direct sample download | `storage/uploads/` is never mounted under the static file server's root. |
| Unauthenticated write access | Optional `X-API-Key` middleware covers all write endpoints; configurable off by default for local use. |

## Why static-only is the right tradeoff for a triage tool

Dynamic (sandbox) analysis is definitive but heavyweight, slow, and requires
a fully isolated VM. Hexora's static-only approach means:

- **Zero risk of sample execution**, even if Hexora itself runs in a shared
  environment.
- **Instant results** — a 4 MB EXE is fully analyzed in < 200 ms.
- **Air-gap friendly** — the whole stack (including Chart.js, vendored locally)
  runs with zero outbound internet access, fitting analyst lab networks.

The risk engine is deliberately conservative: it over-reports indicators and
tells the analyst *why*, so they can triage and route to sandbox analysis when
the score warrants it.

## Tech stack

| Layer | Technology |
| --- | --- |
| Backend | Python 3.11, FastAPI, SQLAlchemy 2, Uvicorn |
| Storage | SQLite (default) → PostgreSQL (drop-in via `DATABASE_URL`) |
| PDF generation | ReportLab (Platypus layout engine) |
| PDF metadata | pypdf |
| Image metadata | Pillow |
| Frontend | Vanilla HTML + CSS + JS (no framework, no build step) |
| Charts | Chart.js 4.4 (vendored locally) |
| Deployment | Docker + docker-compose |
