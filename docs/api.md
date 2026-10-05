# API

Base path `/api`. JSON responses carry `success: true` or `success: false` with `error: { code, message, details? }`.

## Analysis

### `POST /api/analyze`

`multipart/form-data` with a single file in the field `email` (`.eml`, `.txt` or `.mbox`, up to `MAX_EMAIL_BYTES`). `.msg` files are rejected with guidance.

### `POST /api/analyze/raw`

```json
{ "raw": "Return-Path: <…>\nFrom: …\n\nbody", "sourceName": "optional label" }
```

### Responses

Both endpoints return `201` with:

```json
{
  "success": true,
  "analysisId": "an_mfz1k9c2a1b2c3d4e5f6",
  "riskScore": 88,
  "riskLevel": "critical",
  "classification": "phishing",
  "findings": [
    {
      "id": "f1",
      "detector": "auth.dmarc",
      "severity": "critical",
      "confidence": 0.95,
      "title": "DMARC failed for the From domain",
      "…": "…"
    }
  ],
  "analysis": {
    "id": "…",
    "metadata": {},
    "body": {},
    "received": [],
    "authentication": {},
    "urls": [],
    "attachments": [],
    "ml": {},
    "risk": {},
    "stages": []
  }
}
```

With `Accept: text/event-stream` the response is a stream instead:

```
event: stage
data: {"type":"stage","stage":{"id":"parse","label":"Email parsed","status":"done","durationMs":6.1,"detail":"3 MIME part(s), 18 headers"}}

… one event per stage: parse, headers, authentication, urls, content, attachments, rules, ml, threat_intel, correlation, scoring, persist

event: result
data: {"type":"result","analysis":{…}}
```

Failures after the stream has started arrive as `event: error` with the same error body.

### Error codes

| Code                                     | Status | Meaning                                                     |
| ---------------------------------------- | ------ | ----------------------------------------------------------- |
| `missing_file`                           | 400    | No file in the `email` field                                |
| `unsupported_file`, `unsupported_format` | 400    | Wrong type, or Outlook `.msg`                               |
| `validation_failed`                      | 400    | Body or query failed validation; `details` lists the fields |
| `payload_too_large`                      | 413    | Over `MAX_EMAIL_BYTES`                                      |
| `not_an_email`                           | 422    | No RFC 5322 header block                                    |
| `mime_parse_failed`                      | 422    | The parser could not process the MIME structure             |
| `rate_limited`                           | 429    | More than 30 analyses per minute from one client            |
| `internal_error`                         | 500    | No details are disclosed; no data is modified               |

## Investigations

| Endpoint                       | Notes                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/analyses`            | Query: `page` (1), `pageSize` (25, max 100), `search`, `riskLevel` (comma list of critical, high, medium, low, safe), `classification` (comma list), `from`, `to` (ISO date or datetime), `sort` (created_at, risk_score, finding_count, sender_address, subject, classification), `order` (asc, desc). Returns `{ items, total, page, pageSize }`. |
| `GET /api/analyses/:id`        | Full `AnalysisResult`, including the latest analyst feedback                                                                                                                                                                                                                                                                                        |
| `GET /api/analyses/:id/raw`    | Original source as `text/plain` with `nosniff`; 404 if `STORE_RAW_SOURCE=false`                                                                                                                                                                                                                                                                     |
| `GET /api/analyses/:id/report` | Downloadable JSON report: executive summary, verdict and breakdown, metadata, authentication, header analysis, indicators, URL, attachment, ML and threat-intel sections, IOCs, recommendations                                                                                                                                                     |
| `DELETE /api/analyses/:id`     | Removes the investigation, its findings and feedback                                                                                                                                                                                                                                                                                                |

Ids must match `^an_[a-z0-9]{10,40}$`.

## Feedback

`POST /api/feedback` with `{ "analysisId", "verdict", "notes"? }`. `verdict` is one of `confirmed_phishing`, `confirmed_legitimate`, `false_positive`, `false_negative`, `uncertain`.

## System

| Endpoint                                            | Notes                                                                                                                                                                 |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/health`                                   | Status of api, database (live query), ml (live probe, cached 5 s), storage (writability and size) and each threat-intel provider. Overall `degraded` when ML is down. |
| `GET /api/stats`                                    | Totals, classification and risk distributions, finding categories, 30-day history, top indicators                                                                     |
| `GET /api/model`                                    | From the live ML service, or from saved artifacts when it is offline (`source` says which)                                                                            |
| `GET /api/threat-intel/:indicator`                  | Domain or IPv4. Returns `local` analysis (domains only) and `external` provider results; unconfigured providers report `not_configured` and are not contacted.        |
| `GET /api/samples`, `GET /api/samples/:label/:file` | Bundled fictional samples, served from an allow-list                                                                                                                  |
