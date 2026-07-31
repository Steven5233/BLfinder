<div align="center">

```
██████╗ ██╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔══██╗██║     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══██╗██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

### Business Logic Flaw Detection Engine — v3.2 Phase 6

*The scanner that finds what 90% of bug bounty hunters miss.*
*Traffic import · Persistent database · Deep discovery · Live dashboard · HackerOne integration.*
*Now with SSRF/CSRF, source code exposure scanning, and OTP rate-limit testing.*

<br>

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-green?style=flat-square)](https://termux.dev)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red?style=flat-square)](https://owasp.org/API-Security)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=flat-square)](https://hackerone.com)
[![Version](https://img.shields.io/badge/Version-3.2%20Phase%206-blue?style=flat-square)](https://github.com/Steven5233/BLfinder)
[![GitHub](https://img.shields.io/badge/GitHub-Steven5233%2FBLfinder-181717?style=flat-square&logo=github)](https://github.com/Steven5233/BLfinder)

</div>

---

> **⚠️ Legal Notice:** BLFinder is designed exclusively for **authorised security testing** — bug bounty programmes, penetration testing engagements, and security research on systems you own or have explicit written permission to test. Unauthorised use against any system is illegal and unethical. The developer assumes no liability for misuse.

---

## Table of Contents

- [What is BLFinder?](#-what-is-blfinder)
- [What Sets It Apart](#-what-sets-it-apart)
- [Phase Architecture](#-phase-architecture)
- [Detection Modules — All 21](#-detection-modules--all-21)
- [Phase 5+: Deep Discovery Engine](#-phase-5-deep-discovery-engine)
- [Phase 6: Perimeter, Source Exposure & OTP Testing](#-phase-6-perimeter-source-exposure--otp-testing)
- [Phase 5: Professional Operations](#-phase-5-professional-operations)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [All CLI Flags](#-all-cli-flags)
- [Traffic Import](#-traffic-import)
- [Scan Profiles](#-scan-profiles)
- [Persistent Database](#-persistent-database)
- [HackerOne Integration](#-hackerone-integration)
- [Live Dashboard](#-live-dashboard)
- [Endpoints File Format](#-endpoints-file-format)
- [Flow Templates](#-flow-templates)
- [Evidence & Reports](#-evidence--reports)
- [Understanding Results](#-understanding-results)
- [Bug Bounty Playbook](#-bug-bounty-playbook)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [About the Author](#-about-the-author)
- [Acknowledgements](#-acknowledgements)

---

## 🔍 What is BLFinder?

BLFinder is an **async Python security scanner** built exclusively to detect business logic vulnerabilities in REST APIs and web applications. Unlike generic scanners (Burp Suite active scan, OWASP ZAP, nikto), BLFinder focuses on flaws that require **semantic understanding of the application's business rules** — vulnerabilities that no signature-based tool can detect.

It runs natively on **Termux for Android**, so you can hunt from anywhere.

**Every finding includes:**

| Component | Detail |
|---|---|
| **EvidencePackage** | Live-captured HTTP pairs — not templates, not guesses |
| **Field-level diff** | Exactly which JSON fields changed between baseline and attack |
| **Impact assessment** | Actual PII, credentials, or financial data found in the response |
| **Confidence score** | 0–100% with reasoning and false-positive analysis |
| **Proof of Concept** | Verified `curl`, Python, Burp raw HTTP, and HTTPie |
| **HackerOne markdown** | One-click copy-paste submission with real evidence |
| **Persistent database** | Findings stored across sessions, duplicates auto-filtered |
| **Direct H1 export** | Push to HackerOne as draft reports via API |

---

## 🎯 What Sets It Apart

Most automated scanners test for known patterns — SQLi, XSS, path traversal. Business logic flaws require understanding **what the application is supposed to do** and testing whether it can be forced to do something else. No CVE, no signature, no SAST rule catches these.

| Vulnerability Type | Burp Active | OWASP ZAP | BLFinder |
|---|:---:|:---:|:---:|
| Price / Quantity Manipulation | ❌ | ❌ | ✅ |
| IDOR / BOLA (cross-user confirmed) | ⚠️ | ⚠️ | ✅ |
| Blind IDOR (5-oracle detection) | ❌ | ❌ | ✅ |
| Race Conditions (double-spend) | ❌ | ❌ | ✅ |
| JWT alg:none + Claim Escalation | ⚠️ | ❌ | ✅ |
| State Machine Abuse | ❌ | ❌ | ✅ |
| Mass Assignment | ⚠️ | ❌ | ✅ |
| Multi-Step Flow Attacks | ❌ | ❌ | ✅ |
| Workflow / MFA Bypass | ❌ | ❌ | ✅ |
| GraphQL Deep Scan + IDOR | ❌ | ⚠️ | ✅ |
| WebSocket Vulnerability Scan | ❌ | ❌ | ✅ |
| API Version Abuse | ❌ | ❌ | ✅ |
| Coupon Stacking / Type Confusion | ❌ | ❌ | ✅ |
| BOPLA (hidden field exposure) | ❌ | ❌ | ✅ |
| OAuth2 Vulnerability Testing | ❌ | ❌ | ✅ |
| JS AST Endpoint Extraction | ❌ | ❌ | ✅ |
| OpenAPI / Swagger Auto-Discovery | ❌ | ⚠️ | ✅ |
| Headless SPA Crawl (Playwright) | ❌ | ❌ | ✅ |
| Burp / HAR / mitmproxy Import | manual | manual | ✅ |
| Persistent Finding Database | ❌ | ❌ | ✅ |
| HackerOne API Export | ❌ | ❌ | ✅ |
| Real Evidence Capture | manual | manual | ✅ |
| SSRF (metadata + blind + OOB, 4-tier) | ⚠️ | ⚠️ | ✅ |
| CSRF (active forged-replay confirmation) | ⚠️ | ⚠️ | ✅ |
| Source Code Exposure (.git/.env/backups) | ⚠️ | ⚠️ | ✅ |
| Source Map Reconstruction + Static Bug Scan | ❌ | ❌ | ✅ |
| OTP Rate-Limit / Lockout Bypass Testing | ❌ | ❌ | ✅ |
| Standalone Fast-Path Modes (no full pipeline) | ❌ | ❌ | ✅ |

---

## 🏗️ Phase Architecture

BLFinder is structured in five cumulative phases. Each phase builds on the last — you get everything below your phase for free.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 1 — Detection Core                                               │
│  Multi-step flow attacks · Blind IDOR oracles · Session management      │
│  OAuth2 · Timing oracle · Volatile field learning                       │
├─────────────────────────────────────────────────────────────────────────┤
│  Phase 2 — Evidence Engine                                              │
│  Live HTTP capture · Field-level JSON diff · Impact scoring             │
│  Burp-format raw HTTP · HackerOne-ready markdown generation             │
├─────────────────────────────────────────────────────────────────────────┤
│  Phase 3 — Validation & Recon                                           │
│  Soft-404 prevention · WAF detection · Subdomain mapping                │
│  JS secret extraction · Response classification · Confidence capping    │
├─────────────────────────────────────────────────────────────────────────┤
│  Phase 4 — Attack Surface Expansion                                     │
│  Mass IDOR enumeration · GraphQL deep scan · WebSocket scanner          │
│  API version abuse · Business context classifier                        │
├─────────────────────────────────────────────────────────────────────────┤
│  Phase 5 — Professional Operations                                      │
│  Traffic import (Burp/HAR/mitmproxy) · Scan profiles · SQLite database  │
│  Deduplication · HackerOne API export · Live TUI dashboard              │
├─────────────────────────────────────────────────────────────────────────┤
│  Phase 5+ — Deep Discovery Engine                                       │
│  JS AST parsing · OpenAPI/Swagger/Postman · Smart wordlist (depth 1–5)  │
│  API version permutation · Headless SPA crawl · Priority scoring        │
│  Schema enrichment · Proto/gRPC extraction · Soft-404 filter            │
├─────────────────────────────────────────────────────────────────────────┤
│  Phase 6 — Perimeter, Source Exposure & OTP Testing  ◄ NEW              │
│  SSRF: metadata / blind-timing / OOB / protocol-smuggling (4 tiers)     │
│  CSRF: forged cross-site replay with semantic-diff effect confirmation  │
│  Source code exposure (.git/.env/backups) + source-map bug scanning     │
│  OTP rate-limit, race-condition, and IP-spoof lockout-bypass testing    │
│  Standalone fast-paths: --source-only / --otp-scan skip the pipeline    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Detection Modules — All 21

### 🔴 Critical

| # | Module | What It Detects |
|---|--------|-----------------|
| 1 | **Price Manipulation** | Tampers price/amount/total/fee fields including deeply nested JSON. Confirms when orders are accepted at attacker-controlled prices via response field comparison. Tests 10 tamper values including `0`, `0.01`, `-1`, `null`, and `false`. |
| 2 | **Negative Quantity** | Submits negative quantities to trigger reverse charges, negative inventory, or credit abuse. Canary-tested to eliminate servers that accept any value indiscriminately. |
| 3 | **IDOR / BOLA** | Path ID swaps, body ID mutation, UUID permutation, header injection (`X-User-Id`, `X-Admin-User`), and no-auth access — all with optional cross-user confirmation via second token. Full evidence capture on every test. |
| 4 | **Blind IDOR** | 5-oracle detection (HTTP status, response size, error message, timing, cross-user similarity) for IDORs where the server returns HTTP 200 regardless. Designed for APIs with uniform success responses. |
| 5 | **Mass Assignment** | Injects privileged fields (`is_admin`, `role`, `kyc_verified`, `price_override`) and confirms reflection via baseline comparison. Also auto-discovers target-specific privilege fields from live 200 responses. Eliminates false positives from pre-set fields. |
| 6 | **State Machine Abuse** | Forces objects to privileged states (`paid`, `approved`, `completed`, `verified`) without satisfying transition conditions. Confirmed when the state appears in the response body. |
| 7 | **Race Conditions** | Fires 15 concurrent requests to detect double-spending, reward duplication, and single-use bypass. Extended indicator list covers gambling/fintech keywords: `bet`, `wager`, `stake`, `cashout`, `bonus`, `deposit`, `topup`. Re-verifies with a sequential request after burst to establish ground truth. |
| 8 | **JWT alg:none Bypass** | Tests signature bypass by replacing the algorithm with `none`. Canary-verified with a fully random invalid token to confirm the server does not accept everything. |
| 9 | **BFLA / Privilege Escalation** | Probes 12 admin and internal paths with low-privilege and no-auth tokens. Confirms actual content is returned (not a generic landing page) before reporting. |

### 🟠 High

| # | Module | What It Detects |
|---|--------|-----------------|
| 10 | **Workflow / MFA Bypass** | Skips numbered workflow steps (`step_2` → `step_5`), tests OTP/MFA token omission. Canary step (999) prevents false positives. |
| 11 | **Coupon Abuse** | Array injection and type confusion (`["CODE","CODE"]`). Confirmed by comparing extracted discount amounts before and after. |
| 12 | **BOPLA** | Hidden fields exposed via `?expand=all`, `?fields=*`, `?include_deleted=true`. Detects sensitive field names (`password`, `salary`, `ssn`, `secret`) in newly exposed keys. |
| 13 | **Time Logic Bypass** | Far-future (`2099-12-31`) and negative UNIX timestamps in body fields. Confirmed only when the response meaningfully differs from the baseline. |
| 14 | **Integer Overflow** | Extreme values (`2^31-1`, `2^63-1`, `-2^31`) that cause HTTP 500 or negative values in the response (e.g. negative balance after large deposit). |
| 15 | **Limit / Offset Abuse** | Pagination manipulation (`limit=99999`) to bulk-export records. Compares actual parsed record counts, not just byte length. |
| 16 | **BFLA (Cross-User)** | User 2 performing `DELETE`/`PUT`/`PATCH` on User 1's resources — requires a second token. Reports confirmed only when the mutating method succeeds. |
| 17 | **Soft Delete Bypass** | Accessing deleted/archived records via filter parameters. Semantic diff confirms a real change, not noise. |

### 🟡 Medium

| # | Module | What It Detects |
|---|--------|-----------------|
| 18 | **GraphQL** | Introspection enabled in production, unauthenticated data access (`users`, `me`). Tests multiple common GraphQL paths automatically. |
| 19 | **Account Enumeration** | Different error messages for valid vs invalid accounts, and a statistical timing oracle (>200ms delta triggers a low-confidence finding). |
| 20 | **HTTP Method Override** | `X-HTTP-Method-Override: DELETE` and `_method=DELETE` headers causing a different response than the plain `POST` baseline. |
| 21 | **Parameter Pollution** | Duplicate query parameters (e.g. `id=1&id=999999`) changing application behaviour via semantic diff. |

### 🔬 Phase 4: Expanded Attack Surface

Activate with dedicated flags. Run after the standard 21-module sweep.

| Module | Flag | What It Detects |
|--------|------|-----------------|
| **GraphQL Deep Scan** | `--graphql-deep` | Full schema traversal, field-level IDOR, batching abuse, alias DoS |
| **WebSocket Scanner** | `--websocket` | Auth bypass over WS, message injection, WS IDOR, race conditions |
| **API Version Abuse** | `--version-scan` | Retired `v1`/`v2` endpoints with weaker controls still accessible |
| **IDOR Mass Enumeration** | `--idor-range N` | Rapid ID-range enumeration; harvests IDs from baseline responses. Supports numeric, UUID, MongoDB ObjectID, Stripe-format, and base62 IDs |
| **Cross-Endpoint BOLA** | `--idor-cross-endpoint` | Uses IDs harvested from one endpoint to attack others in the same session |
| **SSRF** | `--ssrf` | Cloud metadata leakage, blind internal-network timing leads, out-of-band collaborator confirmation, protocol-smuggling context. See [Phase 6](#-phase-6-perimeter-source-exposure--otp-testing) |
| **CSRF** | `--csrf` | Forged cross-site replay with semantic-diff effect confirmation, token-validation-depth check, GET-downgrade and Content-Type bypass checks. See [Phase 6](#-phase-6-perimeter-source-exposure--otp-testing) |
| **Source Code Scan** | `--source-scan` | Exposed `.git`/`.env`/backup/credential files + source-map reconstruction and static bug-pattern scan. See [Phase 6](#-phase-6-perimeter-source-exposure--otp-testing) |

---

## 🌐 Phase 5+: Deep Discovery Engine

The Deep Discovery Engine replaces the legacy regex crawler with a multi-layer pipeline that finds endpoints invisible to traditional crawlers.

```
Layer 1  →  robots.txt · sitemap.xml                   (RobotsParser)
Layer 2a →  JS file fetching + AST endpoint extraction  (JSASTParser)
Layer 2b →  OpenAPI / Swagger / Postman spec probing    (OpenAPIParser)
             (30+ well-known paths auto-probed + custom --openapi-path)
Layer 4a →  Business-context-seeded smart wordlist      (SmartWordlist)
             depth 1 (~200 paths) … depth 5 (~10,000 paths)
Layer 4b →  API version shadow discovery                (VersionPermuter)
             v1→v2→v3→internal→legacy→beta permutations
Layer 5  →  URL normalisation + deduplication           (normaliser)
Optional →  Playwright headless SPA crawl               (--use-headless)
             Intercepts all XHR/fetch calls during navigation
             Clicks buttons/forms with --headless-interact
```

### Discovery Flags

```bash
# Enable the full pipeline
--deep-discovery

# Wordlist depth (default: 2)
--wordlist-depth 3          # ~1500 paths + full sub-resource tree

# Engine-level depth
--discovery-depth 3

# Skip individual layers
--no-robots                 # Skip robots.txt / sitemap.xml
--no-js-ast                 # Skip JS AST pass
--no-openapi                # Skip OpenAPI/Swagger probing
--no-version-permute        # Skip version shadow discovery
--no-wordlist               # Skip wordlist entirely (spec/JS/headless only)

# Extra spec paths beyond the 30+ probed automatically
--openapi-path /api/v1/openapi.json
--openapi-path /internal/swagger.yaml

# Business context tags — seeds the wordlist with domain-specific paths
--business-tags payment,order,admin,transfer

# Headless crawl (requires: pip install playwright && playwright install chromium)
--use-headless
--headless-interact         # Also click buttons and submit forms

# gRPC / Protobuf
--proto-path ./protos/user_service.proto

# Save all discovered endpoints before scanning
--save-discovery ~/discovered.json

# Discovery-only — skip all attack modules
--no-scan
```

### Example: Deep Discovery Pipeline

```bash
# Full pipeline at depth 3 with headless crawl and business tags
python blfinder.py \
  -t https://api.target.com \
  -T mytoken \
  --deep-discovery \
  --wordlist-depth 3 \
  --business-tags payment,order,subscription \
  --use-headless \
  --save-discovery discovered.json \
  --html -o ~/results

# Discovery only — review endpoints before attacking
python blfinder.py \
  -t https://api.target.com -T mytoken \
  --deep-discovery --wordlist-depth 2 \
  --save-discovery endpoints.json \
  --no-scan

# Then scan the saved endpoints
python blfinder.py \
  -t https://api.target.com -T mytoken \
  -e endpoints.json \
  --html --json -o ~/results
```

---

## 🧬 Phase 6: Perimeter, Source Exposure & OTP Testing

Four additions that round out coverage beyond the API surface itself: SSRF and CSRF join the standard endpoint sweep as opt-in modules, while source code exposure and OTP rate-limiting each get their own **standalone fast-path mode** — point them at one URL and they run *only* that check, skipping discovery and every other module entirely. Use the fast-path when you already know exactly what you want tested and don't want the noise or the wait of a full scan.

### SSRF Scanner — `--ssrf`

Four independent evidence tiers, escalating in reliability:

| Tier | What it does | Confidence |
|------|--------------|------------|
| 1 — In-band metadata | Points candidate URL parameters at AWS/GCP/Azure/Alibaba/DigitalOcean/Oracle metadata endpoints and `file:///etc/passwd`, then greps the *response the app hands back* for credential/metadata signatures | Confirmed — direct evidence |
| 2 — Blind internal-network | Loopback/RFC1918/link-local targets with allow-list bypass encodings (decimal/octal/hex IP, IPv6-mapped), confirmed only via a statistically significant `TimingOracle` delta against a guaranteed-unreachable control host | Capped, unconfirmed lead |
| 3 — Out-of-band | Fires a unique-per-request collaborator subdomain (`--ssrf-oob-domain`); a correlated DNS/HTTP hit is unambiguous proof of server-side egress | Confirmed if a pluggable checker correlates the hit |
| 4 — Protocol smuggling | Tests `file://`/`gopher://`/`dict://` acceptance — contextual only, raises the severity of a Tier 1–3 finding rather than standing alone | N/A |

Candidate parameters are found by name heuristic (`url`, `callback`, `webhook`, `avatar`, `redirect`, ...) or value shape, recursively through JSON bodies, plus a path-based fallback for webhook/screenshot/unfurl-style features.

```bash
--ssrf                              # enable within a normal scan
--ssrf-oob-domain abc123.oast.fun   # optional Tier 3 collaborator domain
```

### CSRF Scanner — `--csrf`

Never reports "no token found" as a finding on its own. Four layers, and only a live-confirmed exploit chain gets reported:

1. **Token & defense discovery** (passive) — CSRF-token-shaped fields in body/headers/cookies, plus the session cookie's `SameSite` attribute.
2. **Forged cross-site replay** (the core proof, opt-in via `--csrf`) — resends the exact state-changing request with any token blanked and `Origin`/`Referer` swapped to an attacker domain, then uses the project's own `SemanticDiff` engine to confirm the forged request achieved the *same effect* as the legitimate one — not just "got a response."
3. **Token validation depth** — if a token exists, resubmits it tampered (with a legitimate Origin) to check whether it's validated for correctness or merely checked for presence.
4. **GET-downgrade / Content-Type bypass** — is the same mutation reachable via plain GET? Does swapping `Content-Type: text/plain` bypass an implicit JSON-only "defense"?

Without `--csrf`, only a conservative passive hardening-gap check runs (no extra requests, no active replay). Requires cookie-based auth (`-c`) — CSRF doesn't apply to pure Bearer/JWT header auth, and the module correctly stays silent in that case rather than producing a false report.

```bash
--csrf   # enables ACTIVE replay — resends real state-changing requests
```

### Source Code Exposure & Static Bug Scanner — `--source-scan` / `--source-only`

**Phase A — Exposure sweep** (once per host): probes ~18 known-sensitive paths (`.git/HEAD`, `.git/config`, `.env` + variants, `.aws/credentials`, `id_rsa`, `.vscode/sftp.json`, `.npmrc`, PHP/WordPress/docker-compose backups, Django `settings.py`, `.htpasswd`). Every path has its own content validator (never just "got a 200") and is checked against a soft-404/SPA-catch-all canary first.

**Phase B — Source map reconstruction**: when a response looks like JS, looks for a `sourceMappingURL` comment, fetches the `.map` file (capped 2MB), and if `sourcesContent` is embedded, statically scans the *original unminified source* for: disabled TLS verification, `eval`/`Function` sinks, DOM XSS sinks, unsafe `postMessage` handlers, hardcoded internal hosts/IPs, `Math.random()` used for tokens, commented-out auth checks, debug/bypass flags. With no map, a reduced minification-safe subset still runs against the raw JS.

Exposure findings are `confirmed=True` (content-validated). Static code-pattern findings are always `confirmed=False`, labeled "Requires Manual Triage" — a regex match is a lead, not proof. Capped at 20 JS files and ~500KB of reconstructed source per host.

```bash
# Integrated into a normal scan
--source-scan
--js-url https://cdn.target.com/main.js     # explicit JS file, repeatable

# Standalone fast path — skips discovery and every other module entirely
python blfinder.py --source-only -t https://api.target.com -o ~/results -v
```

### OTP Rate-Limit & Lockout Bypass Scanner — `--otp-scan`

Standalone-only (there's no non-standalone form of this one — it needs its own URL and digit count, not a generic endpoint). Measures rate-limiting robustness; it does **not** attempt to brute-force the real OTP value, and it never touches an OTP send/resend endpoint on its own.

| Test | What it does |
|------|--------------|
| 1 — Sequential lockout detection | Random wrong-guess codes one at a time, watching for a 429/403/423, `Retry-After`, or a "too many attempts"-style phrase. No block within the sample budget → flags **missing rate limiting**, with a brute-force time estimate built from *this endpoint's own measured request rate* |
| 2 — Concurrency burst | A true parallel burst; more processed than the sequential threshold predicts → flags a likely TOCTOU counter race condition |
| 3 — Header-spoof bypass | Only if a real lockout was found — retries with a fresh random IP in `X-Forwarded-For`/`X-Real-IP`/`X-Client-IP` per request; if the block disappears, the limiter is keyed off a spoofable client header |

```bash
python blfinder.py --otp-scan \
  --otp-url https://api.target.com/auth/verify-otp \
  --otp-digits 6 \
  --otp-field code \
  --otp-extra-body '{"user_id":"123","challenge_id":"abc"}' \
  --otp-samples 30 --otp-concurrency 15 \
  --otp-success-marker '"verified":true' \
  -o ~/results
```

Attempt counts are hard-capped internally (500 sequential / 50 concurrent) regardless of what's requested. If `--otp-success-marker` ever matches a random guess (a real valid code was accidentally hit), the scan stops immediately instead of continuing.

### Skipping Re-Verification — `--no-verify`

Every finding normally passes through `FindingVerifier`, which re-runs the attack request to confirm the anomaly still reproduces before it's reported. This can occasionally false-negative on a flaky or stateful target (session state that only reproduces once, a re-test that gets rate-limited, timing that shifts under load) and drop a genuine finding.

```bash
--no-verify   # skip re-verification entirely — report every finding as first detected
```

Even without `--no-verify`, anything the verifier drops is no longer silently discarded — it's written to `<output>/dropped_findings.json` for manual review.

---

## ⚙️ Phase 5: Professional Operations

### Traffic Import

Stop writing `endpoints.json` by hand. Import real traffic directly from your proxy — this is the **most important workflow improvement** for getting real results. When you import from Burp, blfinder uses your actual session cookies, real request bodies, and real field values.

```bash
# Burp Suite XML/JSON export
python blfinder.py -t https://target.com -T token \
  --import-burp burp_session.xml

# Browser HAR (Chrome DevTools → Network → Save all as HAR)
python blfinder.py -t https://target.com -T token \
  --import-har session.har

# mitmproxy flows
python blfinder.py -t https://target.com -T token \
  --import-mitmproxy flows.bin

# Filter to API paths and save generated endpoints file
python blfinder.py -t https://target.com -T token \
  --import-burp burp_session.xml \
  --import-filter "/api/" \
  --import-save ~/endpoints.json

# Combine all three sources — deduplication is automatic
python blfinder.py -t https://target.com -T token \
  -e known.json \
  --import-burp burp.xml \
  --import-har session.har \
  --import-filter "/api/v"
```

> **Tip:** Always prefer `--import-burp` over the enricher's auto-generated bodies. Burp-imported traffic contains your real email, real IDs, real currency values, and real session context — which makes IDOR detection far more reliable.

### Scan Profiles

Eight built-in profiles tune every scanner parameter for a specific target type. **CLI flags always override profile settings.**

| Profile | Best For | Key Settings |
|---------|----------|--------------|
| `ecommerce` | Shopping carts, checkout flows | Price/coupon modules first, checkout flow, IDOR on order IDs |
| `fintech` | Banking, payment APIs | High confidence (70%), slow rate (1.5s), deep IDOR, strict validation |
| `saas` | SaaS dashboards, admin panels | Mass assignment, BFLA, GraphQL deep, tenant IDOR |
| `stealth` | WAF-protected or rate-limited targets | Very slow rate (3s), random UA rotation, minimal footprint |
| `fast` | CTFs, test environments | Zero delay, low confidence threshold, all modules enabled |
| `graphql` | GraphQL-first APIs | GraphQL deep scan, introspection, batching abuse |
| `api_only` | Pure REST APIs, no frontend | JS extraction off, subdomain recon off, API modules only |
| `thorough` | High-value targets, maximum coverage | All modules, multiple confirmation attempts, full recon |

```bash
python blfinder.py -t https://shop.target.com -T token --profile ecommerce
python blfinder.py -t https://api.bank.com    -T token --profile fintech
python blfinder.py -t https://app.saas.com    -T token --profile saas
```

**Custom profile** — create `profiles/myprofile.json`:

```json
{
  "name": "myprofile",
  "settings": {
    "rate_limit": 0.8,
    "min_confidence": 60,
    "confirm_attempts": 3,
    "fuzz_depth": 3,
    "run_graphql_deep": true,
    "idor_range": 50,
    "idor_harvest": true,
    "js_secrets": true,
    "deep_discovery": true,
    "discovery_depth": 3
  },
  "flows": ["ecommerce_checkout", "funds_transfer"],
  "auto_flows": true,
  "priority_modules": ["price_manipulation", "idor_bola", "race_condition"],
  "skip_modules": ["account_enumeration", "parameter_pollution"],
  "discovery": {
    "business_tags": ["payment", "order", "refund"],
    "no_wordlist": false,
    "max_js_files": 50
  }
}
```

### Persistent Database

Every scan writes to a local SQLite database. Duplicates are automatically filtered across sessions.

```bash
# Tag findings with a program handle
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --program target_h1

# Skip endpoints already confirmed vulnerable
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --no-repeat

# View history across all scans
python blfinder.py --show-history --db ~/.blfinder.db

# Search past findings by keyword
python blfinder.py --search "IDOR payment" --db ~/.blfinder.db
python blfinder.py --search "race condition" --db ~/.blfinder.db --program target_h1
```

**Database schema:**

```
scans     ← scan_id, target, program, config, timestamps, finding_count
findings  ← id, scan_id, title, severity, confirmed, confidence, status,
            endpoint, evidence, poc, program, created_at
programs  ← handle, scope, notes, created_at
```

**Finding lifecycle:** `new` → `exported` (after H1 submission) → `closed / duplicate / informative`

### HackerOne Integration

Push findings directly to HackerOne as draft reports. Drafts are created but **not** submitted — you review and submit manually.

```bash
# Auto-export new findings immediately after scan
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --program target_h1 \
  --export-h1 target_h1 \
  --h1-token yourusername:your_api_token

# Export from database only (no new scan)
python blfinder.py \
  --export-h1 target_h1 \
  --h1-token yourusername:your_api_token \
  --db ~/.blfinder.db \
  --program target_h1
```

Each exported report contains: title, CVSS, CWE, OWASP reference, step-by-step reproduction, real request/response pairs, and impact statement — all sourced from the live scan evidence.

Get your API token at: [hackerone.com/settings/api_token/edit](https://hackerone.com/settings/api_token/edit). Format: `username:api_token`.

### Live Dashboard

```bash
python blfinder.py -t https://target.com -T token --dashboard
python blfinder.py -t https://target.com -T token --dashboard --force-ansi
```

```
┌─ BLFinder v3.1 ──────────────────────────────────────────────────────┐
│ Target: https://api.target.com                        Scan #47        │
│ Endpoints: 22/126 scanned  Requests: 847  429s: 3  Elapsed: 00:06:11 │
│ Current: /api/v1/orders/455                                           │
├─ Live Findings ───────────────────────────────────────────────────────┤
│ [CRITICAL ✓] IDOR — Path ID 456→455 returned different resource       │
│ [CRITICAL ✓] Race Condition — 8/15 concurrent requests succeeded      │
│ [HIGH]       BOPLA — expand=all exposes 7 hidden fields               │
│ [MEDIUM]     GraphQL Introspection enabled in production               │
├─ Rate — api.target.com ───────────────────────────────────────────────┤
│ delay=0.38s   ok=843   429s=3   (auto-backing off)                    │
└──────────────────────── [p] Pause   [q] Quit ─────────────────────────┘
```

Press **`p`** to pause mid-scan (inspect a finding before continuing), **`q`** to stop cleanly.

---

## 📱 Installation

### Termux (Android) — Recommended

```bash
# Step 1: Install Termux from F-Droid (NOT the Play Store — it's outdated there)
# https://f-droid.org/en/packages/com.termux/

# Step 2: Install dependencies
pkg update && pkg upgrade -y
pkg install python git -y
pip install aiohttp --break-system-packages

# Step 3: Clone the repository
git clone https://github.com/Steven5233/BLfinder.git ~/BLfinder
cd ~/BLfinder

# Step 4: Verify
python blfinder.py --help

# Optional: headless crawl support (~300MB Chromium)
pip install playwright --break-system-packages
playwright install chromium
```

### Linux / macOS

```bash
git clone https://github.com/Steven5233/BLfinder.git
cd BLfinder
pip install aiohttp
python blfinder.py --help

# Optional: headless crawl
pip install playwright && playwright install chromium
```

### Requirements

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| aiohttp | Latest |
| Playwright | Optional (headless crawl only) |
| RAM | ~100 MB |
| Storage | ~5 MB (+ ~300 MB for Chromium if headless) |

No other mandatory dependencies. Runs on stock Python + aiohttp.

---

## ⚡ Quick Start

```bash
# 1 — Basic scan, smart discovery finds endpoints automatically
python blfinder.py -t https://api.target.com

# 2 — With auth token (Bearer injected automatically)
python blfinder.py -t https://api.target.com \
  -T eyJhbGciOiJIUzI1NiJ9...

# 3 — Cookie-authenticated target (e.g. 1win.com)
python blfinder.py \
  -t https://target.com \
  --cookie "session_token=your-token-value" \
  --cookie "cf_clearance=cloudflare-value" \
  --skip-unauth \
  --max-endpoints 3 \
  --html -o ~/results

# 4 — Full IDOR confirmation (two accounts — highest-value flag)
python blfinder.py \
  -t https://api.target.com \
  -T user1_token -T2 user2_token \
  -e endpoints.json \
  --html --json --md -o ~/results -v

# 5 — Import from Burp, use profile, save to DB
python blfinder.py \
  -t https://shop.target.com \
  -T user1_token -T2 user2_token \
  --import-burp traffic.xml \
  --profile ecommerce \
  --db ~/.blfinder.db --program target_h1 \
  --html --md -o ~/results

# 6 — Full Phase 5+ professional scan
python blfinder.py \
  -t https://api.target.com \
  -T user1_token -T2 user2_token \
  --import-burp traffic.xml \
  --profile thorough \
  --deep-discovery --wordlist-depth 3 \
  --business-tags payment,order,subscription \
  --db ~/.blfinder.db --program target_h1 \
  --dashboard \
  --html --json --md -o ~/results

# 7 — Discovery only — review before attacking
python blfinder.py \
  -t https://api.target.com -T mytoken \
  --deep-discovery --wordlist-depth 2 \
  --save-discovery endpoints.json \
  --no-scan

# 8 — Full scan with SSRF, CSRF, and source-code exposure enabled
python blfinder.py \
  -t https://api.target.com \
  -T user1_token -c "session=abc123" \
  -e endpoints.json \
  --ssrf --ssrf-oob-domain abc123.oast.fun \
  --csrf --source-scan \
  --html --json -o ~/results

# 9 — Source code exposure only — fastest, lowest-noise, no auth needed
python blfinder.py --source-only -t https://api.target.com -o ~/results -v

# 10 — OTP rate-limit test only — standalone, needs just the verify URL + digit count
python blfinder.py --otp-scan \
  --otp-url https://api.target.com/auth/verify-otp \
  --otp-digits 6 -o ~/results

# 11 — Re-run without the verifier if it's dropping genuine findings
python blfinder.py -t https://api.target.com -e endpoints.json --no-verify
```

Open `~/results/report.html` for a full interactive report: 7 tabs per finding including side-by-side request comparison, field-level diff, impact assessment, and a HackerOne-ready submission.

---

## 📖 All CLI Flags

### Core

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--target` | required | Target base URL |
| `-T`, `--token` | — | Auth token — User 1 (primary account). Pass raw token value only, no `Bearer` prefix |
| `-T2`, `--token2` | — | Auth token — User 2 (enables cross-user IDOR confirmation) |
| `-T3`, `--token3` | — | Auth token — User 3 (privilege chain testing) |
| `-e`, `--endpoints` | — | Endpoints JSON file |
| `-H`, `--header` | — | Extra request header, repeatable: `-H "X-Api-Key: abc"` |
| `-c`, `--cookie` | — | Extra cookie, repeatable: `-c "1w_token=abc"` |
| `--proxy` | — | HTTP proxy URL: `http://127.0.0.1:8080` |
| `-r`, `--rate` | `0.3` | Base delay between requests (seconds) |
| `--timeout` | `20` | Per-request timeout (seconds) |
| `--no-discover` | off | Disable smart endpoint discovery |
| `--no-ssl-verify` | off | Disable TLS certificate verification |
| `--fuzz-depth` | `2` | Nested JSON mutation depth |
| `--min-confidence` | `40` | Drop findings below this confidence % |
| `--confirm-attempts` | `2` | Re-verification attempts per finding |
| `--no-verify` | off | Skip re-verification entirely — report every finding as first detected. Dropped findings are still written to `dropped_findings.json` when verification runs |
| `--no-scan` | off | Run discovery only, skip all attack modules |
| `--skip-unauth` | off | Skip unauthenticated access probes (recommended on Cloudflare-protected targets) |
| `--max-endpoints` | `5` | Max endpoints processed concurrently (lower to 2–3 on Cloudflare targets) |

### Traffic Import

| Flag | Description |
|------|-------------|
| `--import-burp FILE` | Import Burp Suite XML or JSON export |
| `--import-har FILE` | Import browser HAR file |
| `--import-mitmproxy FILE` | Import mitmproxy flows file |
| `--import-filter REGEX` | Filter imported URLs by regex, e.g. `/api/` |
| `--import-save FILE` | Save generated endpoints JSON to this path |

### Profiles & Database

| Flag | Default | Description |
|------|---------|-------------|
| `--profile NAME` | — | Load settings profile (`ecommerce`, `fintech`, `saas`, `stealth`, `fast`, `graphql`, `api_only`, `thorough`) |
| `--db PATH` | `~/.blfinder.db` | SQLite database path |
| `--no-repeat` | off | Skip endpoints already confirmed vulnerable in DB |
| `--program HANDLE` | — | Tag findings with this HackerOne programme handle |
| `--export-h1 HANDLE` | — | Export new findings to HackerOne as drafts |
| `--h1-token TOKEN` | — | HackerOne API token (`username:api_token`) |
| `--show-history` | — | Print finding history from DB and exit |
| `--search QUERY` | — | Search past findings by keyword and exit |

### Dashboard

| Flag | Description |
|------|-------------|
| `--dashboard` | Enable live TUI dashboard during scan |
| `--force-ansi` | Force ANSI output (disable curses) |

### Deep Discovery Engine

| Flag | Default | Description |
|------|---------|-------------|
| `--deep-discovery` | off | Enable full multi-layer discovery pipeline |
| `--wordlist-depth N` | `2` | Wordlist depth: `1`=~200 paths … `5`=~10,000 paths |
| `--discovery-depth N` | `2` | Inner engine depth (mirrors `--wordlist-depth`) |
| `--no-robots` | off | Skip robots.txt / sitemap.xml |
| `--no-js-ast` | off | Skip JS AST extraction |
| `--no-openapi` | off | Skip OpenAPI/Swagger/Postman probing |
| `--no-version-permute` | off | Skip API version permutation |
| `--no-wordlist` | off | Skip wordlist layer entirely |
| `--openapi-path PATH` | — | Extra spec path to probe (repeatable) |
| `--proto-path FILE` | — | Local `.proto` file for gRPC extraction (repeatable) |
| `--business-tags TAGS` | — | Comma-separated tags: `payment,order,admin` |
| `--discovery-tags TAGS` | — | Alias for `--business-tags` (engine-level) |
| `--save-discovery FILE` | — | Save discovered endpoints JSON before scanning |
| `--use-headless` | off | Enable Playwright headless browser crawl |
| `--headless-interact` | off | Click buttons/forms during headless crawl |
| `--no-deep-discovery` | off | Disable engine; fall back to legacy regex crawl |

### Recon

| Flag | Default | Description |
|------|---------|-------------|
| `--recon` | off | Enable subdomain mapping + JS extraction before scan |
| `--recon-only` | off | Run recon only, save `targets.json`, and exit |
| `--js-secrets` | off | Enable JS file secret extraction |
| `--subdomain-size N` | `50` | Subdomain wordlist size |
| `--strict-validation` | off | Reject endpoints that don't return a real API response |

### Flows & Auth

| Flag | Default | Description |
|------|---------|-------------|
| `--flow TEMPLATE` | — | Run named flow template (repeatable) |
| `--flow-file FILE` | — | Load flow definitions from JSON file |
| `--auto-flows` | off | Auto-detect app type and run relevant flows |
| `--product-id N` | `1` | Product ID for e-commerce flow templates |
| `--product-price N` | `99.99` | Product price for e-commerce flow templates |
| `--oauth-url URL` | — | OAuth2 token endpoint |
| `--oauth-id ID` | — | OAuth2 client_id |
| `--oauth-secret SECRET` | — | OAuth2 client_secret |
| `--oauth-grant TYPE` | `client_credentials` | OAuth2 grant type |
| `--oauth-user USER` | — | Username for password grant |
| `--oauth-pass PASS` | — | Password for password grant |
| `--refresh-url URL` | — | Token refresh endpoint |
| `--refresh-token TOKEN` | — | Initial refresh token value |
| `--login-url URL` | — | Re-login URL (fallback for refresh) |
| `--login-body JSON` | — | Re-login body as JSON string |
| `--blind-idor` | off | Enable 5-oracle blind IDOR scanning |
| `--samples N` | `4` | Oracle sample count per test |

### Phase 4: Attack Surface

| Flag | Default | Description |
|------|---------|-------------|
| `--idor-range N` | `0` | Enable mass IDOR enumeration up to N IDs |
| `--idor-harvest` | off | Harvest IDs from baseline responses |
| `--idor-cross-endpoint` | off | Test harvested IDs against all endpoints |
| `--idor-batch-size N` | `20` | Concurrent requests per IDOR batch |
| `--websocket` | off | Enable WebSocket scanner |
| `--ws-url URL` | — | Override WebSocket URL |
| `--ws-race-count N` | `15` | Concurrent messages for WS race tests |
| `--graphql-deep` | off | Enable full GraphQL deep scan |
| `--version-scan` | off | Enable API version abuse scan |
| `--classify` | off | Print business context attack plan and exit |

### SSRF

| Flag | Default | Description |
|------|---------|--------------|
| `--ssrf` | off | Enable SSRF scanning module |
| `--ssrf-oob-domain DOMAIN` | — | Collaborator/interactsh domain for Tier 3 out-of-band confirmation |

### CSRF

| Flag | Default | Description |
|------|---------|--------------|
| `--csrf` | off | Enable ACTIVE cross-site replay confirmation (resends real state-changing requests with forged Origin/Referer). Without this, only passive hardening-gap detection runs |

### Source Code Scanner

| Flag | Default | Description |
|------|---------|--------------|
| `--source-scan` | off | Enable source exposure sweep + static bug-pattern scan within a normal scan |
| `--source-only` | off | Run ONLY the source code scanner against `-t/--target`, skip everything else, then exit |
| `--js-url URL` | — | Explicit JS file URL to feed into Phase B, repeatable — used automatically by `--source-only` in addition to auto-discovered `<script src>` tags |

### OTP Rate-Limit Scanner

| Flag | Default | Description |
|------|---------|--------------|
| `--otp-scan` | off | Run ONLY the OTP rate-limit/lockout-bypass scanner, skip everything else, then exit |
| `--otp-url URL` | — | OTP verification endpoint to test (required with `--otp-scan`) |
| `--otp-digits N` | — | OTP code length, e.g. `4` or `6` (required with `--otp-scan`) |
| `--otp-field NAME` | `otp` | Body/query field name holding the OTP guess |
| `--otp-method METHOD` | `POST` | HTTP method for the verification request |
| `--otp-in-query` | off | Send the OTP field as a query parameter instead of a JSON body |
| `--otp-extra-body JSON` | `{}` | Extra JSON object merged alongside the OTP field, e.g. `'{"user_id":"123"}'` |
| `--otp-samples N` | `20` | Sequential wrong-guess attempts for Test 1 (hard cap 500) |
| `--otp-concurrency N` | `10` | Simultaneous requests for Test 2 (hard cap 50) |
| `--otp-success-marker TEXT` | — | Response substring indicating a CORRECT OTP — scan stops immediately if matched |
| `--otp-delay SECS` | `0.1` | Delay between sequential attempts in Test 1 |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | `.` | Output directory |
| `--html` | off | Generate HTML report |
| `--json` | off | Generate JSON report |
| `--md` | off | Generate Markdown report |
| `-v`, `--verbose` | off | Print every request in real time |
| `--no-color` | off | Disable ANSI colours (for log files / CI) |

---

## 📋 Endpoints File Format

Build this with `--import-burp` / `--import-har` + `--import-save`. Manual format:

```json
[
  {
    "url": "/api/v1/checkout",
    "method": "POST",
    "body": {
      "product_id": 123,
      "quantity": 1,
      "price": 99.99,
      "coupon_code": "SAVE10"
    },
    "params": {}
  },
  {
    "url": "/api/v1/orders/456",
    "method": "GET",
    "body": {},
    "params": {}
  },
  {
    "url": "/api/v1/payments",
    "method": "POST",
    "body": {
      "amount": 100,
      "currency": "USD",
      "payment_method": "card",
      "order_id": 456
    },
    "params": {}
  },
  {
    "url": "/api/v1/profile",
    "method": "PUT",
    "body": {
      "user_id": 100,
      "name": "Test User",
      "email": "test@example.com"
    },
    "params": {}
  }
]
```

> **Important:** The placeholder values (`test@example.com`, `amount: 100`) are starting points that the attack modules immediately mutate — they are changed to negative values, zero, overflow integers, etc. The field **names** are what matter. Use `--import-burp` to get your real values automatically from actual intercepted traffic.

All keys are passed directly to the attack modules. Include every field the real application sends — BLFinder uses the body structure to understand which fields to mutate.

---

## 🔄 Flow Templates

11 pre-built multi-step flow templates. Run with `--flow <name>`.

| Template | What It Tests |
|----------|---------------|
| `ecommerce_checkout` | Add to cart → coupon → checkout → payment |
| `ecommerce_refund` | Return initiation → refund confirmation |
| `subscription_upgrade` | Plan selection → upgrade confirmation |
| `funds_transfer` | Transfer initiation → confirmation |
| `withdrawal` | Request → OTP verify → execute |
| `password_reset` | Request → token verify → set new password |
| `user_registration` | Register → email verify → profile complete |
| `redeem_reward` | Check reward → redeem |
| `referral_bonus` | Apply referral → claim bonus |
| `kyc_verification` | Submit → upload doc → verify status |
| `api_key_creation` | Request key → activate |

Each template attacks every marked step for: price manipulation, negative quantity, coupon abuse, state machine abuse, mass assignment, workflow bypass, and race condition on the final step.

**Custom flow file:**

```json
{
  "name": "my_flow",
  "steps": [
    {
      "id": "add_item",
      "method": "POST",
      "url": "/api/cart/items",
      "body": {"product_id": 123, "quantity": 1, "price": 99.99},
      "extract": {"cart_id": "$.cart.id"},
      "attack_here": true,
      "required": true
    },
    {
      "id": "checkout",
      "method": "POST",
      "url": "/api/checkout",
      "body": {"cart_id": "{{cart_id}}", "total": "{{cart_total}}"},
      "attack_here": true,
      "required": true
    }
  ]
}
```

Use `{{variable}}` to inject values extracted from earlier steps.

---

## 📊 Evidence & Reports

### Terminal Output

```
[*] BLFinder v3.1 Phase 5+ — Target: https://api.target.com
[*] 8 endpoints queued

[*] Deep Discovery — running multi-layer pipeline...
  [L1:robots]   15 endpoints found
  [L2:js_ast]   3 endpoints found
  [L2:js_regex] 106 endpoints found
  [L4:wordlist] 2 endpoints found
  [L5:dedup]    removed 0 duplicates

[*] Total after deep discovery: 126 endpoints (+125 new)
[*] Database: ~/.blfinder.db (scan #47)
[*] Verifying 3 findings...

──────────────────────────────────────────────────────
 BLFinder v3.1 Phase 5+ — Scan Complete
 Target  : https://api.target.com
 Date    : 2026-05-14 14:32:11
──────────────────────────────────────────────────────
 CRITICAL  2
 HIGH      1
 TOTAL     3
──────────────────────────────────────────────────────
[*] Database: 3 new, 0 duplicates

[CRITICAL] IDOR — Path ID 456→455 returned different resource ✓ CONFIRMED
  Endpoint   : https://api.target.com/api/v1/orders/455
  Confidence : 91% — cross-user confirmed; 403→200; +1,240B; email + phone exposed
```

### HTML Report — 7 Tabs per Finding

| Tab | Content |
|-----|---------|
| **Overview** | Description, endpoint, confidence reasoning, FP analysis, recommendation |
| **Evidence** | Side-by-side baseline vs attack request and response (live captured) |
| **Diff** | Field-level JSON diff with colour-coded change table |
| **Impact** | Sensitive data detected, privacy/financial/credential flags, record count |
| **Reproduce** | Verified `curl` command, step-by-step manual guide |
| **Raw HTTP** | Burp Suite importable format for all captured pairs |
| **HackerOne** | Complete copy-paste ready submission with real endpoints and evidence |

---

## 🔎 Understanding Results

### Confidence Score

| Score | Meaning | Recommended Action |
|-------|---------|-------------------|
| 80–100% | Very likely real | Report immediately |
| 60–79% | Probably real | Manual verify first |
| 40–59% | Possible | Test manually, then report |
| < 40% | Low confidence | Dropped automatically |

### Confirmed vs Unconfirmed

| Badge | Meaning |
|-------|---------|
| `✓ CONFIRMED` | Cross-user verified **or** consistently reproduced across N re-tests |
| *(none)* | Detected heuristically — manual verification recommended before reporting |

### False Positive Notes

| Note | Action |
|------|--------|
| `WAF/security block detected` | Disable VPN and re-test |
| `Responses nearly identical` | Difference is noise — skip |
| `Intermittent reproduction` | Re-run with `--confirm-attempts 3` |
| `Server accepts everything (canary)` | No validation at all — low value |

---

## 🏆 Bug Bounty Playbook

### Step 1 — Import real traffic (most important step)

```bash
# Browse the app in Burp, export, import
# This gives you real session cookies, real bodies, real field values
python blfinder.py -t https://target.com -T token \
  --import-burp session.xml \
  --import-filter "/api/" \
  --import-save endpoints.json
```

### Step 2 — Use two accounts (enables confirmed findings)

```bash
# CONFIRMED findings pay significantly more
python blfinder.py -T "account1_token" -T2 "account2_token" ...
```

### Step 3 — Pick the right profile

```bash
--profile ecommerce   # Shopping / marketplace
--profile fintech     # Banking / payments
--profile saas        # B2B SaaS / admin portals
--profile thorough    # Maximum coverage, high-value targets
```

### Step 4 — Enable deep discovery on API-heavy targets

```bash
--deep-discovery --wordlist-depth 3 --business-tags payment,order,subscription
```

### Step 5 — Manage multi-day engagements with the database

```bash
# Day 1 — scan scope A
python blfinder.py ... --db ~/.blfinder.db --program target_h1

# Day 2 — scan scope B, skip already-found vulns
python blfinder.py ... --db ~/.blfinder.db --program target_h1 --no-repeat

# Any time — review findings
python blfinder.py --show-history --db ~/.blfinder.db
```

### Step 6 — Use the HackerOne tab, not a blank report

The HTML report's **HackerOne tab** generates a complete submission — real endpoint URLs, real request/response pairs, real impact. Don't write the report from scratch.

### Step 7 — Disable VPN if findings show WAF notes

WAF blocks from VPN exit nodes inflate false positives. Disable VPN, re-run, compare.

### Typical Payout Ranges

| Finding Type | Typical Range |
|---|---|
| IDOR / BOLA (confirmed, PII exposed) | $500 – $10,000+ |
| Price / Quantity Manipulation | $500 – $5,000 |
| Race Condition (double-spend) | $500 – $5,000 |
| JWT alg:none bypass | $1,000 – $8,000 |
| Mass Assignment (privilege escalation) | $500 – $3,000 |
| State Machine Abuse | $300 – $3,000 |
| Workflow / MFA Bypass | $200 – $2,000 |
| OAuth2 Vulnerability | $500 – $5,000 |

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named aiohttp` | `pip install aiohttp --break-system-packages` |
| `Connection refused` | Check URL; try `--no-ssl-verify` |
| `All timeouts` | `--timeout 30` |
| `Too many 429s` | `-r 2.0` or `--profile stealth` |
| `0 findings, 0 endpoints tested` | Add `-e endpoints.json` or `--import-burp`, and `-T token` |
| `120/128 endpoints skipped (soft-404)` | Apply `core/discovery/scanner_patch.py` — raises soft-404 threshold |
| `RuntimeWarning: coroutine never awaited` | Apply `core/discovery/scanner_patch.py` — fixes lambda bug |
| `WAF FP notes on all findings` | Disable VPN and re-run |
| `Profile not found` | Check `profiles/NAME.json` exists; use `~/.blfinder/profiles/` as alternative |
| `Dashboard blank` | Try `--force-ansi` to switch from curses to ANSI mode |
| `H1 export fails` | Token format must be `username:api_token`, not just the token |
| `Database locked` | Only run one instance per `--db` path at a time |
| `Playwright not found` | `pip install playwright --break-system-packages && playwright install chromium` |
| `Cloudflare blocking mid-scan` | Refresh `cf_clearance` from browser → restart with new cookie value |
| `Enricher returns fake values (email: testexample@gmail.com)` | Use `--import-burp` instead — enricher placeholders are correct by design; real values come from imported traffic |
| `Permission denied` | `chmod +x blfinder.py` |
| `Termux storage issues` | `termux-setup-storage`, use `~/storage/downloads/` for output |
| `Verifier drops findings I believe are genuine` | Re-run with `--no-verify`, or check `<output>/dropped_findings.json` — every dropped finding is written there, not lost |
| `--otp-scan does nothing / 0 findings` | Confirm `--otp-field` matches the actual body field name, and pass `--otp-extra-body` for any other required fields (user_id, challenge_id, session, ...) |
| `--source-only finds no JS bug patterns` | The target's JS may have no exposed `sourceMappingURL`/`.map` file — Phase B falls back to a smaller minification-safe pattern set in that case, which is expected, not a bug |
| `SSRF Tier 3 (OOB) never confirms` | Requires `--ssrf-oob-domain` pointed at a real collaborator/interactsh server; without it, only Tiers 1/2/4 run |

---

## 📁 Project Structure

```
BLfinder/
│
├── blfinder.py                      ← CLI entry point — all phase flags
├── endpoints.example.json           ← Endpoint definition template
├── flows.example.json               ← Custom flow definition template
├── README.md
│
├── profiles/                        ← Phase 5: Scan profile JSON files
│   ├── ecommerce.json
│   ├── fintech.json
│   ├── saas.json
│   ├── stealth.json
│   ├── fast.json
│   ├── graphql.json
│   ├── api_only.json
│   └── thorough.json
│
└── core/
    ├── models.py                    ← Shared dataclasses (Finding, ScanConfig, PoC)
    ├── scanner.py                   ← All 21 detection modules + evidence wiring
    ├── confidence.py                ← Confidence scoring + FP reduction engine
    ├── poc.py                       ← Proof of Concept generator
    ├── verifier.py                  ← Finding re-verification loop
    ├── reporter.py                  ← Report dispatcher (HTML / JSON / Markdown)
    │
    ├── discovery/                   ← Phase 5+: Deep Discovery Engine
    │   ├── engine.py                ← DeepDiscoveryEngine orchestrator
    │   ├── models.py                ← DiscoveryConfig, DiscoveredEndpoint
    │   ├── cli_args.py              ← add_discovery_args() / apply_discovery_args()
    │   ├── endpoint_enricher.py     ← Body parameter inference + method promotion
    │   ├── scanner_patch.py         ← Monkey-patch for coroutine + soft-404 bugs
    │   ├── layer1_surface/
    │   │   └── robots_parser.py     ← robots.txt + sitemap.xml parser
    │   ├── layer2_static/
    │   │   ├── js_ast_parser.py     ← JS AST + regex endpoint extractor
    │   │   └── openapi_parser.py    ← OpenAPI / Swagger / Postman parser
    │   ├── layer4_wordlist/
    │   │   ├── smart_wordlist.py    ← Context-seeded wordlist prober
    │   │   └── version_permuter.py  ← API version shadow discovery
    │   └── layer5_dedup/
    │       └── normaliser.py        ← URL normalisation + deduplication
    │
    ├── evidence/                    ← Phase 2: Evidence capture
    │   ├── capture.py               ← EvidencePackage + EvidenceCapture class
    │   ├── http_recorder.py         ← Burp / curl / Python / HTTPie converter
    │   ├── diff_engine.py           ← Field-level JSON diff engine
    │   └── impact_assessor.py       ← PII / credential / financial impact scoring
    │
    ├── reporting/                   ← Phase 2: Report generators
    │   ├── evidence_report.py       ← HTML report with 7-tab evidence layout
    │   └── hackerone_formatter.py   ← HackerOne-ready markdown generator
    │
    ├── analysis/                    ← Phase 1: Semantic analysis
    │   ├── semantic_diff.py         ← JSON-aware response comparison
    │   └── field_extractor.py       ← Volatile field learning + detection
    │
    ├── oracles/                     ← Phase 1: Oracle-based detection
    │   ├── timing_oracle.py         ← Statistical timing oracle
    │   └── blind_idor.py            ← 5-oracle blind IDOR scanner
    │
    ├── auth/                        ← Phase 1: Session management
    │   ├── session_manager.py       ← Token refresh + CSRF extraction
    │   └── oauth_handler.py         ← OAuth2 flow + vulnerability testing
    │
    ├── flows/                       ← Phase 1: Multi-step flows
    │   ├── flow_replayer.py         ← Multi-step executor + attack engine
    │   └── flow_templates.py        ← 11 pre-built business flow templates
    │
    ├── validation/                  ← Phase 3: Endpoint validation
    │   ├── endpoint_validator.py    ← Soft-404, WAF, not-GraphQL detection
    │   └── response_classifier.py  ← Response class + confidence capping
    │
    ├── recon/                       ← Phase 3: Reconnaissance
    │   ├── subdomain_mapper.py      ← Subdomain discovery + API surface scoring
    │   └── js_secret_extractor.py  ← JS file secret pattern extraction
    │
    ├── modules/                     ← Phase 4/6: Expanded attack surface
    │   ├── idor_mass_enum.py        ← Mass IDOR enumeration + ID harvesting
    │   ├── graphql_deep.py          ← GraphQL schema traversal + field IDOR
    │   ├── websocket_scanner.py     ← WebSocket vulnerability scanner
    │   ├── api_version_abuse.py     ← Version endpoint discovery + downgrade
    │   ├── ssrf_scanner.py          ← 4-tier SSRF: metadata/blind/OOB/protocol
    │   ├── csrf_scanner.py          ← Forged-replay CSRF w/ semantic-diff proof
    │   ├── source_code_scanner.py   ← .git/.env exposure + source-map bug scan
    │   └── otp_scanner.py           ← OTP rate-limit + lockout-bypass scanner
    │
    ├── intelligence/                ← Phase 4: Business context
    │   └── business_classifier.py  ← Endpoint classification + attack prioritisation
    │
    ├── integrations/                ← Phase 5: Traffic import
    │   └── burp_importer.py         ← Burp XML/JSON, HAR, mitmproxy parser
    │
    ├── storage/                     ← Phase 5: Persistence
    │   └── scan_database.py         ← SQLite DB, dedup, H1 export, history
    │
    └── tui/                         ← Phase 5: Live dashboard
        └── live_dashboard.py        ← Curses / ANSI TUI + pause support
```

> `<output>/dropped_findings.json` is written automatically whenever `FindingVerifier` drops a finding that passed the confidence filter but failed re-test — nothing is silently discarded. Use `--no-verify` to skip re-verification entirely instead.

---

## 🤝 Contributing

Contributions are welcome. To add a new detection module:

1. Add your check as `async def _check_yourmodule(...) -> list[Finding]` in `core/scanner.py`
2. Use `self._new_evidence()` and `self._req_ev()` to capture live HTTP evidence
3. Call `self._build_pkg()` and `self._attach(f, pkg)` before `_finalize_finding()`
4. Add the module to the `all_checks` list in `_run_endpoint_checks()`
5. Add a PoC builder in `core/poc.py` matching your category string
6. Open a pull request describing what the module detects, with at least one real-world example

**Every finding must include:**
- A canary / FP check where applicable
- A `cwe`, `cvss`, and `owasp` reference
- Evidence capture via `_req_ev()` for both baseline and attack requests
- A clear `recommendation` field

To add a scan profile, create `profiles/NAME.json` following the schema in the [Scan Profiles](#scan-profiles) section.

---

## 👤 About the Author

BLFinder is built by **Adoyi Steven (séç gúy)**, a cybersecurity researcher and penetration tester focused on practical tools for ethical hacking, bug bounty hunting, and enterprise security.

- **GitHub:** [Steven5233](https://github.com/Steven5233)
- **Repository:** [BLFinder](https://github.com/Steven5233/BLfinder)

BLFinder started as a personal tool to automate the business logic checks that manual testers run on every engagement — the checks that generic scanners walk straight past. It evolved into a full platform after consistently finding high-severity bugs that Burp Suite's active scanner missed. Phase 5 adds the professional operational layer for sustained, multi-day bug bounty engagements. Phase 5+ adds a discovery engine that finds the endpoints other tools never even know exist.

---

## 🙏 Acknowledgements

- **[séç gúy Bug Bounty Course](https://wa.me/2349015552392)** — The structured bug bounty methodology, business logic attack mindset, and real-world hunting techniques taught in this course directly shaped BLFinder's detection approach. Many of the attack patterns in the 21 modules trace back to lessons from this programme. If you want to understand the theory behind what this tool does automatically, this course is the place to start. WhatsApp: **09015552392**

- [OWASP API Security Project](https://owasp.org/API-Security) — vulnerability classification framework

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — research references and attack technique documentation

- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — real-world bug patterns and disclosure reports that informed the module design

- [Intigriti Blog](https://blog.intigriti.com) — business logic research and case studies

- The bug bounty community — for documenting what automated tools miss and sharing techniques that made this tool possible

---

## 📄 License

```
MIT License — Copyright (c) 2026 Adoyi Steven

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, subject to the following conditions:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
The author is not responsible for any misuse or damage caused by this tool.
Use only on systems you own or have explicit authorisation to test.
```

---

<div align="center">

**Built for hunters. Runs on a phone. Reports with proof. Remembers everything.**

*If BLFinder found you a bounty, a ⭐ on the repo is always appreciated.*

**[⭐ Star on GitHub](https://github.com/Steven5233/BLfinder) · [🐛 Issues](https://github.com/Steven5233/BLfinder/issues) · [🍴 Fork](https://github.com/Steven5233/BLfinder/fork)**

</div>
