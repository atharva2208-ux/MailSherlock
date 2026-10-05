# Detection engine

## Findings

Every finding has:

- `id`, `detector`, `category` and `source` (`rule` or `threat_intel`)
- `severity`: critical, high, medium, low or info
- `confidence`: 0-1
- `title` and `description`
- `whyItMatters`
- `evidence`: label/value pairs
- `recommendation`
- `method`: how it was detected, in plain words
- optional MITRE ATT&CK technique ids
- optional `spans`: offsets into the body text, used for highlighting
- optional `relatedUrls`
- `scoreGroup`
- optional `adjustment`, recording why severity was lowered

## Detectors

| Id                                                                                                                              | What it looks for                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `auth.spf`, `auth.dkim`, `auth.dmarc`                                                                                           | Failures in the top-most Authentication-Results header; DMARC fail is critical              |
| `header.reply_to_mismatch`                                                                                                      | Reply-To in a different organisation; higher if free-mail or with a look-alike sender       |
| `header.return_path_mismatch`                                                                                                   | Envelope sender in another organisation; informational when DMARC passes (normal for ESPs)  |
| `header.received_chain`                                                                                                         | Backwards hop timestamps, missing reverse DNS, Date header far from the first relay         |
| `header.anomalies`                                                                                                              | Scripting mailers (PHPMailer and similar), duplicate From headers, missing Message-ID       |
| `impersonation.display_name`                                                                                                    | Brand name or a foreign address in the display name                                         |
| `impersonation.lookalike_sender`                                                                                                | Sender domain imitating a protected brand                                                   |
| `impersonation.homoglyph`                                                                                                       | Mixed-script IDN sender or link domains                                                     |
| `impersonation.executive`                                                                                                       | Executive persona combined with a financial ask, urgency and/or secrecy                     |
| `url.ip_host`                                                                                                                   | Raw IPs and decimal/hex/octal-encoded IPs                                                   |
| `url.obfuscation`                                                                                                               | `user@host` authority tricks, percent-encoded hosts, `javascript:` / `data:text/html` links |
| `url.redirect`                                                                                                                  | Shorteners and redirect parameters to other domains                                         |
| `url.suspicious_tld`                                                                                                            | High-abuse TLDs and deep subdomain chains                                                   |
| `url.lookalike_domain`                                                                                                          | Link hosts imitating protected brands                                                       |
| `url.anchor_mismatch`                                                                                                           | Visible link text naming a different domain than the href                                   |
| `url.credential_harvesting`                                                                                                     | Embedded forms (critical with a password field), login-style paths on non-brand domains     |
| `content.urgency`, `content.credential_request`, `content.financial_request`, `content.social_engineering`, `content.scam_lure` | Weighted intent analysis (below)                                                            |
| `content.hidden_text`                                                                                                           | Text hidden with CSS, and script tags                                                       |
| `attachment.dangerous_type`, `attachment.disguised_name`, `attachment.type_mismatch`                                            | File type, double extensions/RTLO, magic-byte mismatch, executables in ZIPs                 |

## Domain analysis

`services/analyzers/domain.ts` parses hosts with the Public Suffix List (tldts) and compares the registrable label against brand keywords using four checks:

1. **Homoglyph:** the label contains non-ASCII characters and its Unicode-confusable skeleton equals the brand (`microsоft` with Cyrillic о).
2. **Character substitution:** the skeleton after digit and letter-cluster substitution (0→o, 1→l, rn→m, vv→w) equals the brand (`paypa1`, `arnazon`, `g00gle`).
3. **Typosquat:** Levenshtein distance 1 (or 2 for brands of 8+ characters) (`gooogle`).
4. **Combosquat:** a hyphen-separated token equals or substitutes the brand (`paypal-resolution-center`), or the brand appears as a subdomain of an unrelated domain (`paypal.com.secure-login.top`).

Official brand domains are excluded. Mixed-script detection uses Unicode script properties per label.

## Content intents

Phrases are grouped into intents (urgency, account threat, credential request, MFA request, payment request, bank-detail change, gift cards, secrecy, authority, prize, delivery and job lures). Each phrase has a weight reflecting how specific it is to manipulation; repeated matches of one phrase do not add up.

Context then adjusts the scores:

- A credential request is amplified by a call to action (links or a form) and by an account threat.
- Payment, gift-card and bank-change requests are amplified by secrecy or pressure.
- Urgency with no attached request is halved, as is authority without a request or secrecy.

Severity thresholds per detector map the adjusted score to a severity. The `Pressure + request + action` finding fires only when pressure, a request and a way to act all co-occur.

## Scoring

```
points(finding) = SEVERITY_POINTS[severity] × confidence      critical 35, high 22, medium 10, low 4, info 0
group score     = Σ points sorted desc × 0.5^rank, capped     caps: auth 40, sender 25, header 12, impersonation 45,
                                                                    url 40, credential form 40, content 25,
                                                                    pressure pattern 15, hidden 12, attachment 50, TI 45
rule score      = min(100, Σ groups)
corroboration   = +8 (3 categories with high+ findings) or +12 (4+)
ML              = above threshold: 6 + 14 × (p − t)/(1 − t)   (max 20)
                    × 0.5 if model confidence is low
                    capped at 8 if rule score < 10
                    × 0.25 in trusted sender context
                  below threshold and no critical finding: up to −8
raw             = rule score + corroboration + ML
score           = 100 × (1 − e^(−raw/60)), floor 60 if a critical finding has confidence ≥ 0.9
```

The floor guarantees that a single unambiguous indicator, such as a password form or `invoice.pdf.exe`, is never scored below high just because nothing else was found.

## Trusted sender context

The trusted context applies when all of these hold:

- DMARC passes and is not misaligned.
- There is no look-alike sender, homoglyph or display-name impersonation.
- Every link stays on the sender's organisational domain, or on another official domain of the same brand.
- No link or attachment has high or critical indicators.
- There is no embedded password form.

In that context, content findings (except financial requests and hidden content) drop two severity levels with a recorded reason, and ML points are quartered. This is what keeps genuine password resets, sign-in alerts and receipts from being flagged.

## End-to-end check

```bash
npm run analyze-samples -w server                  # every sample through the full pipeline
npm run analyze-samples -w server -- --challenge   # plus the modern challenge set
```
