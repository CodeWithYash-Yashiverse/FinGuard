# FinGuard

Plain-language scam awareness for digital payments. Paste a suspicious SMS, UPI request, or payment email and FinGuard highlights warning signs, explains why they matter, and recommends safe next steps.

## Run locally

### Frontend only (built-in TypeScript engine)

```bash
pnpm install
pnpm dev
```

Open http://localhost:3000.

### Frontend + Python backend

Start the Python backend (one terminal):

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Create `.env.local` in the project root (if not already present):

```
FINGUARD_API_URL=http://127.0.0.1:8000
```

Start the frontend (another terminal):

```bash
pnpm install
pnpm dev
```

Open http://localhost:3000. The Next.js proxy will forward analysis requests to the Python backend. If the backend is unreachable, the user sees a clear error — results are never fabricated.

To switch back to the built-in TypeScript engine, remove or rename `.env.local`.

### Run backend tests

```powershell
cd backend
.\venv\Scripts\activate
python -m pytest tests/ -v
```

## How analysis works

- `POST /api/analyze` (`app/api/analyze/route.ts`) validates the message (10–5000 chars) and returns an `AnalysisResult`.
- By default it runs the built-in rule-based engine in `lib/analysis/engine.ts` (links, urgency, credential requests, impersonation, payment demands, scam patterns).
- To use a Python FastAPI backend instead, set `FINGUARD_API_URL` (e.g. `http://localhost:8000`). The route proxies to `POST {FINGUARD_API_URL}/v1/analyze` with `{ "message": string }` and expects a JSON body matching `AnalysisResult` in `lib/analysis/types.ts`. If the backend is unreachable, the user sees an error — results are never fabricated.

## Privacy

- Submitted text is processed in memory, never logged, stored, or cached (`Cache-Control: no-store`).
- Nothing is written to `localStorage`/`sessionStorage`.
- Screenshot text extraction uses `tesseract.js` in the browser; images are not uploaded (the OCR language data is downloaded from a CDN on first use).

## Structure

```
app/                     layout, page, /api/analyze route
components/layout/       header, footer
components/sections/     hero and educational sections
components/checker/      message input, screenshot OCR, examples
components/results/      risk indicator, signal list, results view
lib/analysis/            types and detection engine
lib/api-client.ts        typed client for /api/analyze
backend/app/             Python FastAPI backend, Pydantic schemas, detection engine
backend/tests/           pytest unit and API tests
```

FinGuard results are indicators, not proof of fraud, and never a guarantee that a message is safe.

