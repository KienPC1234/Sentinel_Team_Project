# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Cursor, OpenCode, …) working in this
repository. Read this before changing code. Several rules below are **security invariants**, not
style preferences: this project analyzes malware and personal data.

- **Project:** ShieldCall VN / Sentinel Core — anti-fraud platform for Vietnam
- **Stack:** Django 5.2 + DRF + Channels/Daphne, Celery, MariaDB/MySQL, Redis, Ollama, FAISS,
  Faster-Whisper, VietOCR, Docker sandbox, Next.js 16, Puppeteer (TypeScript)
- **Branch:** `master` · **License:** AGPL-3.0-or-later
- **Start here:** `README.md`, `docs/ARCHITECTURE.md`, `docs/SETUP.md`, `docs/API_REFERENCE.md`,
  `docs/TESTING.md`, `PROJECT_OVERVIEW.md` (Vietnamese feature overview)

---

## 1. Repository map

| Path | Contents |
| :--- | :--- |
| `backend/PKV/` | Django project: settings, ASGI, root URLs, Celery app, server-rendered templates/views |
| `backend/api/core/` | Main app: scans, auth/MFA, reports, trends, forum, trust, MCP views, models, Celery tasks |
| `backend/api/ai_chat/` | AI assistant API and SSE streaming |
| `backend/api/{phone_security,media_analysis,sessions_api,maintenance}/` | Legacy mobile API surface |
| `backend/api/utils/` | Shared engines: `ollama_client`, `ai_agent`, `vector_db`, `sandbox_analyzer`, `trust_guard`, `privacy`, `security`, `tinnhiemmang`, `vn_sources` |
| `backend/mcp_server/` | Standalone MCP server (stdio/SSE) and backend API client |
| `backend/sandbox/` | Zero-trust Docker image (`analyze.py`, `server.py`, YARA rules, ClamAV) |
| `backend/scripts/` | Shared AI service, OCR bridge, evaluations, smoke tests |
| `backend/vector_store/` | FAISS indices (ignored, rebuilt by management command) |
| `frontend/app/` | Next.js App Router routes (mirror Django URL paths, `trailingSlash: true`) |
| `frontend/src/views/` | Page components; `components/`, `lib/` for shared UI and API/SSE clients |
| `puppeteer_host/` | TypeScript headless Chromium cluster with anti-SSRF resolver |
| `docs/` | Architecture, setup, API, testing, evaluation, legal documents |
| `ecosystem.config.js` | PM2 definitions for `pkv-web`, `pkv-celery`, `pkv-celery-beat`, `pkv-ai`, `pkv-puppeteer`, `pkv-frontend` |
| `_minhchung/` | Evaluation dossier (gitignored — never commit or rewrite) |

---

## 2. Golden rules

1. **Never weaken the uncertainty guardrail.** `backend/api/utils/trust_guard.py` owns the canonical
   risk bands (RED ≥ 70, YELLOW ≥ 40, GREEN ≥ 10, otherwise SAFE). Inconclusive evidence must return
   "CHƯA ĐỦ CƠ SỞ XÁC MINH" with verification channels — never a confident "safe" verdict. Every
   verdict must carry structured `evidence[]` and source metadata. Do not invent benchmark numbers.
2. **Redact PII before it leaves the process.** Use `api/utils/privacy.py` (`redact_pii`) before
   logging or sending content to cloud LLMs. Redaction is for logs/egress only — do not strip
   evidence from local analysis results.
3. **Keep the sandbox zero-trust.** Ephemeral containers must keep `--network none`, `--read-only`,
   `--cap-drop ALL`, `--security-opt=no-new-privileges`, tmpfs `/tmp`, and the memory/CPU/PID
   limits. Never add egress, a writable root, or a privileged flag. The long-running daemon on port
   5005 is the only component allowed a bridge network (it accepts inbound HTTP).
4. **Do not bypass SSRF defenses.** `puppeteer_host/src/browser/security.ts` and URL utilities block
   loopback, RFC1918, link-local (`169.254.169.254`), and private IPv6 ranges. Validation happens
   after DNS resolution; do not reorder or short-circuit it.
5. **Never commit secrets or runtime config.** `.env`, `backend/PKV/settings.py`, keys, tokens, and
   database dumps are untracked. Use placeholders in docs. If you add an env var, update
   `docs/SETUP.md` and keep `backend/PKV/settings.py.example` in sync.
6. **Preserve anti-abuse enforcement.** Anonymous scan endpoints require Cloudflare Turnstile;
   only authenticated users and valid API keys are exempt. Do not add header/query bypasses.
7. **Do not edit generated or private data:** `node_modules/`, `.venv*`, `frontend/.next/`,
   `backend/staticfiles/`, `backend/media/`, `backend/vector_store/`, model weights, or `_minhchung/`.
8. **Match existing language and style.** User-facing strings are Vietnamese; keep them and their
   tone. Comments may be Vietnamese or English — match the file you are editing.
9. **Dependency licenses must remain AGPL-compatible.** Check `docs/LEGAL_AND_LICENSE.md` before
   adding a package.

---

## 3. Setup (once)

```bash
# Python 3.11 locally (CI runs 3.12 — keep code compatible with both)
python3.11 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -r backend/requirements.txt
.venv/bin/pip install gdown
.venv/bin/pip install --no-deps vietocr==0.3.13   # shared AI service

# Configuration: create backend/.env (never commit). See docs/SETUP.md for every variable.
# Required locally: SECRET_KEY, ALLOWED_HOSTS, DB_*, REDIS_*, OLLAMA_BASE_URL.

# Frontend
cd frontend && npm install && cd ..

# Headless browser cluster
cd puppeteer_host && npm install && npm run build && cd ..

# Sandbox image (needs Docker)
docker build -t sentinel-sandbox:latest ./backend/sandbox
```

Services: MariaDB/MySQL, Redis, Docker, ClamAV. Optional GPU for Whisper/VietOCR/embeddings; without
it set `WHISPER_DEVICE=cpu`, `VIETOCR_DEVICE=cpu`, `VECTOR_DB_USE_GPU=False`.

---

## 4. Commands

Run from the repository root unless noted. Never activate a shell state you cannot reproduce;
prefer explicit interpreter paths.

### Backend (Django)

```bash
.venv/bin/python backend/manage.py check
.venv/bin/python backend/manage.py makemigrations <app>
.venv/bin/python backend/manage.py migrate
.venv/bin/python backend/manage.py test api.core.tests.test_scan_audit
.venv/bin/python backend/manage.py test api.core.tests api.ai_chat.tests
.venv/bin/python backend/manage.py seed_vn_knowledge   # optional RAG seed

# CI parity (SQLite, no Redis/Celery). Run from backend/.
cd backend && DJANGO_SETTINGS_MODULE=PKV.settings_ci python manage.py test
```

### Frontend (Next.js, cwd `frontend/`)

```bash
npm run dev         # Next dev on :3000, proxies /api to Django
npm run lint        # oxlint
npm run lint:all    # oxlint + eslint
npx tsc --noEmit
npm run build       # build:scripts + next build --webpack
```

### Puppeteer host (cwd `puppeteer_host/`)

```bash
npm run typecheck
npm run build
npm start           # serves :3010; the test suite is an HTTP client for this server
npm test            # deep suite — requires `npm start` running and outbound internet
npm run dev         # tsx watch
```

### Sandbox

```bash
docker build -t sentinel-sandbox:latest ./backend/sandbox
# CI verifies: clean file → SAFE, EICAR → MALICIOUS, daemon healthy on :5005
# See .github/workflows/docker-sandbox.yml
```

### Full stack

```bash
pm2 start ecosystem.config.js
pm2 logs --lines 50
pm2 status
```

---

## 5. Coding conventions

### Backend

- Use Django + DRF (`APIView`/generics). Put validation in `<app>/serializers.py`; avoid hand-rolled
  request parsing when a serializer fits.
- Register API routes in `backend/api/core/urls.py` (mounted under `/api/v1/`). Root-level aliases
  live in `backend/PKV/urls.py`; add one only when an existing client requires it.
- Document new endpoints with `drf_spectacular.utils.extend_schema` and update
  `docs/API_REFERENCE.md`.
- Migrations: one per logical change, never edit an applied migration, always run
  `makemigrations` rather than hand-writing `000N_*.py`.
- Configuration: `os.getenv` with safe defaults. `backend/PKV/settings.py` is untracked — update the
  tracked `settings.py.example` and `docs/SETUP.md`, but don't rely on CI having your local values.
- Heavy work (network scans, OCR, malware analysis, RAG rebuilds) belongs in Celery tasks
  (`backend/api/core/tasks.py`), not the request path. Keep tasks idempotent and retry-safe.
- Log with a module-level `logger` and redacted content; never `print()` in request/task paths.
- Tests live in `backend/api/<app>/tests/test_*.py`. Use `SimpleTestCase` for pure helpers and
  `TestCase` for DB behavior. Mock external calls (Ollama, WHOIS, sandbox daemon, S3) in unit tests.

### Frontend

- Read `frontend/AGENTS.md` first — Next 16 differs from older App Router versions. Consult
  `frontend/node_modules/next/dist/docs/` when unsure.
- Route files go in `frontend/app/<path>/page.tsx` (Django-style URL with trailing slash) and wrap
  content in `<RouteShell>`. Page implementations belong in `frontend/src/views/`.
- Add `'use client'` for hooks, state, or browser APIs. Never touch `window`/`document`/
  `localStorage` during render — Next prerenders and the build will fail.
- Use `frontend/src/lib/api.ts` for REST and `frontend/src/lib/chat/stream.ts` for SSE. Do not
  hardcode API hosts; `NEXT_PUBLIC_API_BASE_URL` defaults to `/api/v1`.
- Keep Tailwind v4 tokens and existing visual language. Internal links use `next/link`; external
  Django pages use `djangoUrl()`.

### Puppeteer

- TypeScript strict mode; validate inputs with `zod` at the route boundary.
- Keep every render behind the anti-SSRF check. Preserve stealth plugins, resource blocking, and
  instance recycling (`MAX_RENDERS_BEFORE_RECYCLE`).
- Extend `scripts/deep_test.js` when behavior changes; the suite must stay green.

---

## 6. Tests and CI

- `.github/workflows/django.yml`: Python 3.12, SQLite via `PKV.settings_ci`, runs the full Django
  test suite on pushes/PRs to `master`.
- `.github/workflows/docker-sandbox.yml`: builds the sandbox when `backend/sandbox/**` or
  `backend/api/utils/sandbox_analyzer.py` changes, then verifies clean/EICAR verdicts and runs
  `api.core.tests.test_sandbox_and_puppeteer`.
- There is no frontend unit-test runner — verify with `oxlint`, `tsc --noEmit`, and `next build`.
- Bug fixes need a regression test. Security-sensitive changes need a test proving the control still
  holds (SSRF, Turnstile, PII redaction, sandbox isolation, trust thresholds).
- Use SQLite-compatible queries in tests; CI does not run MariaDB/MySQL.

---

## 7. Common pitfalls

- **Do not commit `backend/PKV/settings.py`.** It is gitignored and environment-specific.
- **OCR dependency split:** VietOCR is installed with `--no-deps` in `.venv`; `.venv-ocr` is an
  optional fallback used by `backend/scripts/ocr_bridge.py`. Don't add VietOCR/PaddleOCR to
  `requirements.txt`.
- **Ports:** Django :8001, Next :3000, Puppeteer :3010, AI service :5010, sandbox daemon :5005,
  Ollama :11434. `ecosystem.config.js` resolves paths and parses `backend/.env` itself.
- **`npm test` in `puppeteer_host` is not self-contained:** start the server on :3010 first and
  allow internet access to `example.com`.
- **Generated files:** `frontend/AGENTS.md` is recreated by `next dev`; leave its rules block intact.
  `puppeteer_host/dist/`, `frontend/.next/`, and `backend/staticfiles/` are build output.
- **S3 is optional:** local development should run with `USE_S3_MEDIA=false` /
  `USE_S3_STATIC=false`; tests must not require object storage.
- **Do not lower Docker sandbox limits** to make a test pass — adjust the test fixture instead.
- **MCP:** tool definitions live in `backend/mcp_server/` and core MCP views; keep discovery
  (`/api/v1/mcp/`), SSE (`/api/v1/mcp/sse/`), and JSON-RPC (`/api/v1/mcp/messages/`) in sync.

---

## 8. Definition of done

Before reporting a task complete:

- [ ] Change is scoped; no drive-by reformatting of untouched files.
- [ ] `manage.py check` passes after backend changes.
- [ ] Targeted tests pass; broader relevant suites run when feasible.
- [ ] Frontend changes pass `npm run lint`, `npx tsc --noEmit`, and ideally `npm run build`.
- [ ] Sandbox changes pass the Docker workflow checks locally or are flagged as CI-only verification.
- [ ] New routes/tasks/env vars are documented (`docs/API_REFERENCE.md`, `docs/SETUP.md`, README).
- [ ] No secrets, dumps, generated output, or `_minhchung/` content staged.
- [ ] The final message states what changed and exactly which commands were run (and any that could
      not run).

## 9. Commits

Use Conventional Commits, imperative mood, focused diffs:

```text
feat(scan): add bank-account evidence provenance
fix(ci): unbreak Django settings import
docs(agents): document sandbox invariants
```

Do not mix refactors with behavior changes or unrelated formatting in one commit.
