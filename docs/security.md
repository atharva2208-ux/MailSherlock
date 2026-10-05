# Security

MailSherlock's input is, by definition, crafted by attackers. The design assumes every message, filename, URL and header is hostile.

## Input handling

- **Uploads:** multer memory storage only, so there are no temporary files to traverse or execute. Limits: one file, `MAX_EMAIL_BYTES` (10 MiB by default), at most 6 multipart parts and 1 KiB field values. Extension and MIME allow-list.
- **Content check:** the parser rejects anything without an RFC 5322 header block (`422 not_an_email`).
- **Parser limits:** MIME nesting depth 12, 300 parts, 500 headers, 100 attachments, HTML over 5 MB not parsed, body text truncated to 100k characters for analysis. Malformed structure becomes warnings, not crashes. Detectors run in isolation.
- **Validation:** Zod schemas for every body, query and path parameter, including strict patterns for analysis ids, indicators and sample names.
- **Filenames:** control characters, directory components and leading dots are stripped before display or storage.

## Never executing or visiting

- Attachments are hashed and read for magic bytes; ZIP central directories are listed without decompression. Nothing is executed or written to disk.
- URLs are parsed, never fetched. The UI shows them defanged (`hxxps://evil[.]com`) with a copy action, never as live links.
- URLScan is used in search mode only; MailSherlock never submits an attacker URL to be visited.
- No code path invokes a shell or a child process with user data.

## Rendering hostile content

1. **Server-side sanitisation** (sanitize-html) allows only formatting tags. It removes scripts, event handlers, iframes, SVG, forms, styles beyond a small safe set, and every image (so tracking pixels never load). Link `href`s are moved into an inert `data-href` attribute.
2. **Sandboxed display.** The sanitised HTML is rendered in an iframe with `sandbox=""` (no scripts, no same-origin access, no forms) and a `default-src 'none'` CSP inside the frame.
3. **Text by default.** Email text and raw source are rendered as React text nodes, which are escaped. The raw endpoint returns `text/plain` with `X-Content-Type-Options: nosniff`.

A test fixture with script, `onerror`, `javascript:`, iframe, SVG and CSS `url()` payloads verifies the sanitiser output.

## HTTP hardening

- Helmet sets a strict CSP (`script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `form-action 'self'`), `nosniff`, `Referrer-Policy: no-referrer` and HSTS. `x-powered-by` is disabled.
- Rate limits: 30 analyses and 600 API requests per minute per client.
- CORS is enabled only outside production, and only for `CORS_ORIGIN`.
- Errors return a code and message. 5xx responses never include stack traces or internals.

## Data protection

- Queries are parameterised through Kysely. User search terms have `%`, `_` and `\` escaped before `LIKE`.
- Logs are structured (pino) and contain event names, ids, counts and timings. Email content, subjects and addresses are not logged. A redaction list covers authorization headers, API keys and raw or body fields in case an object is logged by mistake.
- Raw source storage can be disabled with `STORE_RAW_SOURCE=false`. Investigations can be deleted, which cascades to findings and feedback.
- Secrets are read from `.env` (git-ignored). The browser only learns whether a provider is configured.
- The ML service binds to `127.0.0.1` and is reached only by the API.
- Training datasets are fetched by script into git-ignored directories. Private mail must never be used.

## Path traversal

Sample files are served only when the name matches `^(phishing|legitimate)/[a-z0-9-]+\.eml$`. The resolved path must also remain inside the samples directory, which is a second, independent check. Integration tests cover encoded traversal attempts.

## Known gaps

- There is no authentication or authorisation; deploy behind an authenticating proxy or VPN, not on the public internet.
- DKIM signatures are not verified cryptographically; results depend on the receiving server's Authentication-Results header.
