# Architecture

```
Frontend (React SPA)
    │  fetch /api/* · Server-Sent Events for analysis progress
    ▼
API (Express)            security headers, rate limits, Zod validation, error mapping
    ▼
Email parser             mailparser for decoding + own raw-header and MIME-boundary walkers
    ▼
Analyzers                received chain · authentication · URLs · content intents · attachments · domains
    ▼
Detection engine         27 independent detectors → findings
    ▼
ML engine                Python inference service (optional; loopback HTTP)
    ▼
Threat intelligence      optional providers, cached, never contacted unless configured
    ▼
Evidence correlation     trust context, severity adjustments
    ▼
Risk scoring             grouped, capped, saturating 0-100 score + breakdown
    ▼
Database                 SQLite through Kysely (summary columns + full result JSON)
```

## Frontend

`client/` is a React 19 single-page app. Routing is in `App.tsx`. Pages that pull in charts (dashboard, model) are lazy-loaded. Server state is managed with TanStack Query. The domain types are imported type-only from `server/src/models/analysis.ts` through the `@shared` alias, so the client and API cannot drift apart.

The analysis flow posts the email with `Accept: text/event-stream` and reads the response body as a stream. Each `stage` event is rendered as it arrives, and the `result` event navigates to the investigation.

## API

`server/src/app.ts` builds the Express app from an `AppContext` (config, logger, database, repositories, ML client, threat-intel service). Tests construct the same app with an in-memory database and a stub ML client. Controllers are thin: they validate input with Zod, call a service, and shape the response.

## Email parser

`services/parser/parseEmail.ts` combines two views of the message:

- **mailparser** for decoding: transfer encodings, charsets, RFC 2047 words, attachments.
- **Own raw readers** for forensics. `headers.ts` preserves header order and duplicates (mailparser merges them). `mime.ts` walks the boundary structure with depth and part limits and reports malformed structure as warnings.

Input without an RFC 5322 header block is rejected with `422 not_an_email`. Everything else produces a result, with parser warnings attached.

## Analyzers and detectors

Analyzers compute shared facts once: the chronological Received chain, the authentication summary, URL list with per-URL indicators, intent scores with text spans, and attachment metadata. These go into a `DetectionContext`.

Detectors (`server/src/detectors/**`) are pure functions of that context. The registry runs each in a `try/catch`, assigns ids and provenance, and records failures without aborting the analysis.

## ML engine

`ml/inference/service.py` (FastAPI) loads the latest versioned bundle at start-up and exposes `/predict`, `/health` and `/model`. The API sends the **raw message bytes**, so the service parses and featurises with the same code used in training, which removes train/serve skew by construction. On timeout or error the API records the stage as skipped and continues.

## Threat intelligence

`services/enrichment/threatIntel.ts` holds provider adapters behind one interface. Unconfigured providers short-circuit to `not_configured` with no network call. Results are cached in memory for an hour.

## Evidence correlation and scoring

`services/scoring/correlation.ts` decides whether the trusted-sender context applies and, if so, downgrades content findings with a recorded reason. `riskScore.ts` turns findings and the ML assessment into the score, level, classification, contribution list and summary. See [detection-engine.md](detection-engine.md).

## Database

Three tables:

- `analyses`: denormalised summary columns for filtering and sorting, plus the full result JSON and optional raw source.
- `findings`: one row per finding, for dashboard aggregates.
- `feedback`: analyst verdicts, with a `reviewed` flag so feedback becomes training data only after review.

Indexes cover the filter and sort columns. Schema creation uses Kysely's schema builder, so a PostgreSQL dialect can replace SQLite without rewriting queries.

## Extension points

- **New detector:** add a module under `detectors/<area>/` and register it.
- **New threat-intel source:** implement `ThreatIntelProvider`.
- **New model:** add a candidate in `ml/models/candidates.py`; the selection gate decides whether it can ship.

The `AppContext` is the seam for authentication, multi-tenancy or a job queue later.
