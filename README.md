<div align="center">

```
██████╗ ██╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔══██╗██║     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══██╗██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**Business Logic Flaw Detection Engine — v3.1 Phase 5**

*The scanner that finds what 90% of bug bounty hunters miss — now with traffic import, persistent database, live dashboard, and HackerOne integration*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-green?style=flat-square)](https://termux.dev)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red?style=flat-square)](https://owasp.org/API-Security)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=flat-square)](https://hackerone.com)
[![Version](https://img.shields.io/badge/Version-3.1%20Phase%205-blue?style=flat-square)](https://github.com/Steven5233/BLfinder)
[![GitHub](https://img.shields.io/badge/GitHub-Steven5233%2FBLfinder-181717?style=flat-square&logo=github)](https://github.com/Steven5233/BLfinder)

</div>

---

> **⚠️ Legal Disclaimer:** BLFinder is designed exclusively for **authorized security testing** — bug bounty programs, penetration testing engagements, and security research on systems you own or have explicit written permission to test. Unauthorized use against systems you do not have permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Table of Contents

- [What is BLFinder?](#-what-is-blfinder)
- [What's New in v3.1 Phase 5](#-whats-new-in-v31-phase-5)
- [Why Business Logic?](#-why-business-logic)
- [Detection Modules](#-detection-modules)
- [Phase Architecture](#-phase-architecture)
- [Key Features](#-key-features)
- [Installation](#-installation-termux--linux)
- [Quick Start](#-quick-start)
- [Usage & All Flags](#-usage--all-flags)
- [Phase 5: Traffic Import](#-phase-5-traffic-import)
- [Phase 5: Scan Profiles](#-phase-5-scan-profiles)
- [Phase 5: Persistent Database](#-phase-5-persistent-database)
- [Phase 5: HackerOne Integration](#-phase-5-hackerone-integration)
- [Phase 5: Live Dashboard](#-phase-5-live-dashboard)
- [Endpoints File Format](#-endpoints-file-format)
- [Flow Templates](#-flow-templates)
- [Evidence & Reports](#-evidence--reports)
- [Understanding Results](#-understanding-results)
- [Bug Bounty Tips](#-bug-bounty-tips)
- [Project Structure](#-project-structure)
- [About the Author](#-about-the-author)
- [Contributing](#-contributing)

---

## 🔍 What is BLFinder?

BLFinder is an **async Python security scanner** purpose-built to detect business logic vulnerabilities in REST APIs and web applications. Unlike generic scanners (Burp Suite active scan, OWASP ZAP, nikto), BLFinder focuses exclusively on flaws that require **semantic understanding of the application's business rules** — vulnerabilities that signature-based tools cannot detect.

It was built to run natively on **Termux for Android**, so you can hunt bugs from anywhere with your phone.

**Every finding in v3.1 includes:**
- **EvidencePackage** — real captured HTTP request/response pairs (not templates)
- **Field-level diff** — exactly which JSON fields changed between baseline and attack
- **Impact assessment** — actual PII, credentials, or sensitive data found in the response
- **Confidence score** (0–100%) with reasoning and false-positive analysis
- **Proof of Concept** — verified `curl`, Python script, Burp Suite raw HTTP, and HTTPie
- **HackerOne-ready markdown** — one tab click generates a copy-paste submission
- **Persistent database** — findings stored across sessions, duplicates automatically filtered
- **Direct H1 export** — push findings to HackerOne as draft reports via API

---

## 🚀 What's New in v3.1 Phase 5

Phase 5 is a professional-grade operational layer built on top of the existing Phase 1–4 detection engine. It adds the infrastructure serious hunters need to work at scale across multiple programs and sessions.

### Traffic Import Pipeline

Stop writing `endpoints.json` by hand. Import real traffic directly from your proxy:

```bash
# Import from Burp Suite session
python blfinder.py -t https://target.com -T token \
  --import-burp burp_export.xml

# Import from browser HAR file (Chrome DevTools / Firefox)
python blfinder.py -t https://target.com -T token \
  --import-har session.har

# Import from mitmproxy flows
python blfinder.py -t https://target.com -T token \
  --import-mitmproxy flows.bin

# Filter to API endpoints only, save generated endpoints.json
python blfinder.py -t https://target.com -T token \
  --import-burp burp_export.xml \
  --import-filter "/api/" \
  --import-save ~/endpoints.json
```

### Scan Profiles

Eight built-in profiles tune every scanner setting for a specific target type:

```bash
# E-commerce: price fields, coupon abuse, checkout flows
python blfinder.py -t https://shop.target.com -T token --profile ecommerce

# Financial APIs: high confidence threshold, slower rate, deep IDOR
python blfinder.py -t https://api.bank.com -T token --profile fintech

# Internal SaaS: mass assignment, BFLA, GraphQL deep
python blfinder.py -t https://app.saas.com -T token --profile saas

# Available: ecommerce | fintech | saas | stealth | fast | graphql | api_only | thorough
```

CLI flags always override profile settings. Profiles only fill in what you haven't explicitly set.

### Persistent Finding Database

Every scan writes to a local SQLite database. Duplicates are automatically skipped on subsequent runs:

```bash
# Tag findings with a program handle
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --program target_h1

# Skip endpoints already confirmed vulnerable (no duplicate reports)
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --no-repeat

# View finding history across all scans
python blfinder.py --show-history --db ~/.blfinder.db

# Search past findings by keyword
python blfinder.py --search "IDOR payment" --db ~/.blfinder.db
```

### HackerOne API Integration

Push findings directly to HackerOne as draft reports:

```bash
python blfinder.py --export-h1 target_program \
  --h1-token username:api_token \
  --db ~/.blfinder.db
```

Or auto-export new findings immediately after each scan:

```bash
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --program target_h1 \
  --export-h1 target_h1 --h1-token username:api_token
```

### Live TUI Dashboard

Real-time terminal dashboard during scanning. Supports pause/resume, live finding feed, and per-domain request stats:

```bash
python blfinder.py -t https://target.com -T token --dashboard
```

---

## 🎯 Why Business Logic?

Most automated scanners test for known vulnerability patterns — SQLi, XSS, path traversal. Business logic flaws require understanding **what the application is supposed to do** and testing whether it can be made to do something else.

| Vulnerability Type | Burp Suite Active | OWASP ZAP | BLFinder |
|---|:---:|:---:|:---:|
| Price / Quantity Manipulation | ❌ | ❌ | ✅ |
| IDOR / BOLA (cross-user confirmed) | ⚠️ | ⚠️ | ✅ |
| Blind IDOR (5-oracle detection) | ❌ | ❌ | ✅ |
| Race Conditions | ❌ | ❌ | ✅ |
| JWT alg:none + Claim Escalation | ⚠️ | ❌ | ✅ |
| State Machine Abuse | ❌ | ❌ | ✅ |
| Mass Assignment | ⚠️ | ❌ | ✅ |
| Multi-Step Flow Attacks | ❌ | ❌ | ✅ |
| Workflow / MFA Bypass | ❌ | ❌ | ✅ |
| GraphQL IDOR + Deep Scan | ❌ | ⚠️ | ✅ |
| WebSocket Vulnerability Scan | ❌ | ❌ | ✅ |
| API Version Abuse | ❌ | ❌ | ✅ |
| Coupon Stacking / Type Confusion | ❌ | ❌ | ✅ |
| BOPLA (hidden field exposure) | ❌ | ❌ | ✅ |
| OAuth2 Vulnerability Testing | ❌ | ❌ | ✅ |
| Soft Delete Bypass | ❌ | ❌ | ✅ |
| Burp/HAR/mitmproxy Import | manual | manual | ✅ |
| Persistent Finding Database | ❌ | ❌ | ✅ |
| HackerOne API Export | ❌ | ❌ | ✅ |
| Real Evidence Capture (Burp format) | manual | manual | ✅ |

---

## 🧩 Detection Modules

BLFinder v3.1 ships **21 detection modules** across three severity tiers, plus Phase 4 expanded attack surface modules.

### 🔴 Critical Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 1 | **Price Manipulation** | Tampers price/amount/total fields including deeply nested JSON. Confirms when orders are created at attacker-controlled prices via response field comparison |
| 2 | **Negative Quantity** | Submits negative quantities to trigger reverse charges, negative inventory, or credit abuse. Canary-tested to eliminate false positives |
| 3 | **IDOR / BOLA** | Path IDs, body IDs, UUID swaps, header injection (`X-User-Id`, `X-Admin-User`), no-auth access — all with cross-user confirmation and full evidence capture |
| 4 | **Blind IDOR** | 5-oracle detection (status, size, error message, timing, cross-user) for IDORs where the server returns HTTP 200 for everything |
| 5 | **Mass Assignment** | Injects privileged fields (`is_admin`, `role`, `kyc_verified`) and confirms reflection with baseline comparison — eliminates false positives from pre-set fields |
| 6 | **State Machine Abuse** | Forces objects to privileged states (`paid`, `approved`, `verified`) without satisfying transition conditions. Confirms via response reflection |
| 7 | **Race Conditions** | Fires 15 concurrent requests to detect double-spending and single-use bypass. Re-verifies with single request after burst |
| 8 | **JWT alg:none + Claims** | Tests signature bypass and arbitrary claim injection. Canary-verified with a random invalid token to eliminate false positives |
| 9 | **BFLA / Privilege Escalation** | Probes admin endpoints with low-privilege and no-auth tokens. Verifies actual content is returned (not a generic landing page) |

### 🟠 High Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 10 | **Workflow / MFA Bypass** | Skips multi-step workflows, tests OTP/MFA token omission. Canary step tests prevent false positives |
| 11 | **Coupon Abuse** | Array injection, type confusion, stacking. Confirms via discount amount comparison |
| 12 | **BOPLA** | Hidden fields exposed via `?expand=all`, `?fields=*`, `?include_deleted=true`. Detects sensitive field names in new data |
| 13 | **Time Logic Bypass** | Far-future/past timestamps in body and headers. Confirmed only when response differs from baseline |
| 14 | **Integer Overflow** | Extreme values causing negative balances or 500 errors |
| 15 | **Limit/Offset Abuse** | Pagination manipulation to dump all records. Compares actual record counts |
| 16 | **Function Level Access (BFLA)** | User 2 performing DELETE/PUT on User 1's resources — requires second token |
| 17 | **Soft Delete Bypass** | Accessing deleted/archived records via filter parameters. Semantic diff confirms real change |

### 🟡 Medium Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 18 | **GraphQL** | Introspection enabled, unauthenticated data access. Tests multiple common GQL endpoints |
| 19 | **Account Enumeration** | Different error messages and statistical timing oracle revealing valid accounts |
| 20 | **HTTP Method Override** | `X-HTTP-Method-Override` acceptance causing different responses |
| 21 | **Parameter Pollution** | Duplicate query parameters changing application behavior |

### 🔬 Phase 4: Expanded Attack Surface

These modules activate with dedicated flags and run after the standard 21-module sweep:

| Module | Flag | What It Finds |
|--------|------|---------------|
| **GraphQL Deep Scan** | `--graphql-deep` | Full schema traversal, field-level IDOR, batching abuse, alias DoS |
| **WebSocket Scanner** | `--websocket` | Auth bypass over WS, message injection, WS IDOR, race conditions |
| **API Version Abuse** | `--version-scan` | Retired v1/v2 endpoints with weaker controls still accessible |
| **IDOR Mass Enumeration** | `--idor-range N` | Rapid enumeration of ID ranges, harvests IDs from baseline responses |
| **Cross-Endpoint BOLA** | `--idor-cross-endpoint` | Uses IDs harvested from one endpoint to attack others |

---

## 🏗️ Phase Architecture

BLFinder is structured in five cumulative phases. Each phase builds on the last.

```
Phase 1 — Detection Core
  Multi-step flow attacks, blind IDOR oracles, session management, OAuth2

Phase 2 — Evidence Engine
  Real HTTP capture, field-level diff, impact scoring, Burp-format raw HTTP

Phase 3 — Validation & Recon
  Endpoint validator, soft-404 prevention, WAF detection, subdomain mapping,
  JS secret extraction, response classification

Phase 4 — Attack Surface Expansion
  Mass IDOR enumeration, GraphQL deep scan, WebSocket scanner,
  API version abuse, business context classifier

Phase 5 — Professional Operations ← NEW
  Traffic import (Burp/HAR/mitmproxy), scan profiles, SQLite database,
  deduplication, HackerOne API export, live TUI dashboard
```

---

## ✨ Key Features

### 🔬 Real Evidence Capture

Every finding carries an `EvidencePackage` with live-captured HTTP — not generated templates.

```
EvidencePackage per finding:
├── baseline_request    ← Exact Burp Suite format raw HTTP (normal request)
├── baseline_response   ← Full response with headers + body
├── attack_request      ← Exact raw HTTP of the exploit
├── attack_response     ← Full response proving the vulnerability
├── diff_analysis       ← Field-level JSON diff (which fields changed)
├── impact_report       ← Sensitive data found (PII, credentials, financial)
├── verified_curl       ← curl command that was actually executed
└── cross_user_pair     ← Cross-user confirmation HTTP pair
```

**HTML report tabs per finding:**

```
Overview | Evidence | Diff | Impact | Reproduce | Raw HTTP | HackerOne
```

The **HackerOne tab** generates a complete copy-paste ready submission with real endpoints, real request/response pairs, and real impact data — directly from the scan.

### 📊 Confidence Scoring & FP Reduction

Each finding is scored 0–100% before reporting:
- HTTP status comparison (403→200 = strong signal)
- Semantic body analysis (success/failure token detection)
- Response similarity scoring using `difflib` (ignores noise)
- JSON structure diff (new keys, sensitive field detection)
- Canary request testing (confirms server doesn't accept everything)
- WAF detection (flags blocked responses automatically)
- Re-verification loop — every finding re-tested N times before reporting

### ⚡ Adaptive Rate Limiter

```
429 received → exponential backoff (2^n × base_delay, max 30s)
10 clean responses → auto speed-up (×0.85 per cycle)
Per-domain tracking → multiple targets handled independently
```

### 🔄 Multi-Step Flow Attacks

```
Flow definition → execute baseline → attack each marked step
                                   ↓
                    Price manipulation at any step
                    Coupon stacking across full flow
                    Workflow bypass (skip steps)
                    Race condition on final step
                    State machine abuse mid-flow
                    Mass assignment at registration
```

### 🔒 Session Management

- Auto-detect `401` responses and trigger token refresh
- CSRF token extraction from HTML meta tags and response headers
- Live cookie jar maintained across all requests
- OAuth2 `client_credentials` and `password` grant support

### 🗄️ Persistent Finding Database (Phase 5)

The SQLite database tracks every finding across sessions. Key capabilities:
- **Deduplication** — `--no-repeat` skips endpoints confirmed vulnerable in previous scans
- **Program tagging** — `--program handle` associates all findings with a bug bounty program
- **Cross-session history** — `--show-history` prints an aggregated stats view
- **Search** — `--search "IDOR payment"` finds past findings by keyword
- **Status tracking** — findings move from `new` → `exported` after H1 submission

---

## 📱 Installation (Termux + Linux)

### Termux (Android) — Recommended

```bash
# Step 1: Install from F-Droid (NOT Play Store — outdated there)
# https://f-droid.org/en/packages/com.termux/

# Step 2: Install dependencies
pkg update && pkg upgrade -y
pkg install python git -y
pip install aiohttp --break-system-packages

# Step 3: Clone
git clone https://github.com/Steven5233/BLfinder.git ~/BLfinder
cd ~/BLfinder

# Step 4: Verify
python blfinder.py --help
```

### Linux / macOS

```bash
git clone https://github.com/Steven5233/BLfinder.git
cd BLfinder
pip install aiohttp
python blfinder.py --help
```

### Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ |
| aiohttp | Latest |
| Android (Termux) | 7.0+ |
| RAM | ~100MB |
| Storage | ~5MB |

No other dependencies. Runs entirely on stock Python + aiohttp.

---

## ⚡ Quick Start

```bash
# 1. Basic scan — smart discovery finds endpoints automatically
python blfinder.py -t https://api.target.com

# 2. With your auth token
python blfinder.py -t https://api.target.com \
  -T "eyJhbGciOiJIUzI1NiJ9..."

# 3. Full bug bounty scan — two accounts for IDOR confirmation
python blfinder.py \
  -t https://api.target.com \
  -T "user1_token_here" \
  -T2 "user2_token_here" \
  -e endpoints.json \
  --html --json --md \
  -o ~/results \
  -v

# 4. Phase 5 professional scan — full pipeline
python blfinder.py \
  -t https://api.target.com \
  -T user1_token -T2 user2_token \
  --import-burp traffic.xml \
  --profile thorough \
  --db ~/.blfinder.db --program target_h1 \
  --dashboard \
  --html --json --md -o ~/results
```

After running, open `~/results/report.html` for a full interactive report with 7 tabs per finding — including side-by-side request comparison, field-level diff, impact assessment, and a HackerOne-ready submission.

---

## 📖 Usage & All Flags

### Core Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--target` | required | Target base URL |
| `-T`, `--token` | — | Auth token for User 1 (primary account) |
| `-T2`, `--token2` | — | Auth token for User 2 (enables IDOR cross-user confirmation) |
| `-T3`, `--token3` | — | Auth token for User 3 (privilege chain testing) |
| `-e`, `--endpoints` | — | Path to endpoints JSON file |
| `-H`, `--header` | — | Extra headers, repeatable: `-H "X-Api-Key: abc"` |
| `-c`, `--cookie` | — | Cookies, repeatable: `-c "session=abc123"` |
| `--proxy` | — | HTTP proxy: `http://127.0.0.1:8080` |
| `-r`, `--rate` | `0.3` | Base delay between requests (seconds) |
| `--timeout` | `20` | Request timeout (seconds) |
| `--no-discover` | off | Disable smart endpoint discovery |
| `--no-ssl-verify` | off | Disable SSL certificate verification |
| `--fuzz-depth` | `2` | Nested JSON mutation depth |
| `--min-confidence` | `40` | Drop findings below this confidence % |
| `--confirm-attempts` | `2` | Re-verification attempts per finding |

### Phase 5: Traffic Import

| Flag | Description |
|------|-------------|
| `--import-burp FILE` | Import Burp Suite XML or JSON traffic export |
| `--import-har FILE` | Import browser HAR file (Chrome DevTools, Firefox, Insomnia) |
| `--import-mitmproxy FILE` | Import mitmproxy flows file |
| `--import-filter REGEX` | Filter imported URLs by regex, e.g. `/api/` |
| `--import-save FILE` | Save generated endpoints.json to this path for reuse |

### Phase 5: Scan Profiles

| Flag | Description |
|------|-------------|
| `--profile NAME` | Load settings from `profiles/NAME.json`. CLI flags override profile settings. Available: `ecommerce`, `fintech`, `saas`, `stealth`, `fast`, `graphql`, `api_only`, `thorough` |

### Phase 5: Database & Program Management

| Flag | Default | Description |
|------|---------|-------------|
| `--db PATH` | `~/.blfinder.db` | SQLite database path |
| `--no-repeat` | off | Skip endpoints already confirmed vulnerable in DB |
| `--program HANDLE` | — | Tag all findings with this HackerOne program handle |
| `--export-h1 HANDLE` | — | Export new findings to HackerOne as drafts |
| `--h1-token TOKEN` | — | HackerOne API token (`username:api_token`) |
| `--show-history` | — | Print finding history from DB and exit |
| `--search QUERY` | — | Search past findings by keyword and exit |

### Phase 5: Dashboard

| Flag | Description |
|------|-------------|
| `--dashboard` | Enable live TUI dashboard during scan |
| `--force-ansi` | Force ANSI output even if curses is available |

### Phase 3: Recon

| Flag | Default | Description |
|------|---------|-------------|
| `--recon` | off | Enable subdomain mapping + JS extraction before scan |
| `--recon-only` | off | Run recon only, save `targets.json`, then exit |
| `--js-secrets` | off | Enable JS file secret extraction |
| `--subdomain-size` | `50` | Subdomain wordlist size |
| `--strict-validation` | off | Drop endpoints that don't return a real API response |

### Phase 1: Flows & Auth

| Flag | Default | Description |
|------|---------|-------------|
| `--flow TEMPLATE` | — | Run a named flow template (repeatable) |
| `--flow-file FILE` | — | Load flow definitions from a JSON file |
| `--auto-flows` | off | Auto-detect app type and run relevant flows |
| `--product-id N` | `1` | Product ID for ecommerce flow templates |
| `--product-price N` | `99.99` | Product price for ecommerce flow templates |
| `--oauth-url URL` | — | OAuth2 token endpoint URL |
| `--oauth-id ID` | — | OAuth2 client_id |
| `--oauth-secret SECRET` | — | OAuth2 client_secret |
| `--oauth-grant TYPE` | `client_credentials` | OAuth2 grant type |
| `--oauth-user USER` | — | Username for password grant |
| `--oauth-pass PASS` | — | Password for password grant |
| `--refresh-url URL` | — | Token refresh endpoint URL |
| `--refresh-token TOKEN` | — | Refresh token value |
| `--login-url URL` | — | Re-login URL (fallback for refresh) |
| `--login-body JSON` | — | Re-login body as JSON string |
| `--blind-idor` | off | Enable blind IDOR oracle scanning (slower) |
| `--samples N` | `4` | Oracle sample count per test |

### Phase 4: Attack Surface

| Flag | Default | Description |
|------|---------|-------------|
| `--idor-range N` | `0` | Enable mass IDOR enumeration up to N IDs per endpoint |
| `--idor-harvest` | off | Harvest IDs from baseline responses for cross-endpoint testing |
| `--idor-cross-endpoint` | off | Test harvested IDs against all other endpoints |
| `--idor-batch-size N` | `20` | Concurrent requests per IDOR batch |
| `--websocket` | off | Enable WebSocket scanner |
| `--ws-url URL` | — | WebSocket endpoint URL (overrides discovery) |
| `--ws-race-count N` | `15` | Concurrent messages for WS race tests |
| `--graphql-deep` | off | Enable full GraphQL deep scan |
| `--version-scan` | off | Enable API version abuse scan |
| `--classify` | off | Print business context attack plan and exit |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | `.` | Output directory for reports |
| `--html` | off | Generate HTML report (default if no format specified) |
| `--json` | off | Generate JSON report |
| `--md` | off | Generate Markdown report |
| `-v`, `--verbose` | off | Print every request in real time |
| `--no-color` | off | Disable ANSI colors (for log files) |

---

## 📥 Phase 5: Traffic Import

Instead of building an `endpoints.json` by hand, import real application traffic captured during manual browsing.

### Burp Suite Export

1. In Burp Suite, go to **Target → Site map → right-click → Save selected items** (XML format)
2. Or export from **Proxy → HTTP history → select all → Save items**

```bash
python blfinder.py -t https://target.com -T token \
  --import-burp ~/burp_session.xml \
  --import-filter "/api/v" \
  --import-save ~/endpoints.json
```

### Browser HAR File

1. Open Chrome DevTools → **Network tab**
2. Browse the application normally
3. Right-click any request → **Save all as HAR with content**

```bash
python blfinder.py -t https://target.com -T token \
  --import-har ~/session.har \
  --import-filter "/api/"
```

### mitmproxy Flows

```bash
# Capture traffic with mitmproxy first
mitmproxy -w flows.bin

# Then import
python blfinder.py -t https://target.com -T token \
  --import-mitmproxy ~/flows.bin
```

### Combining Sources

All three import flags can be used together. Imported endpoints merge with `-e endpoints.json` and discovered endpoints. Deduplication is automatic:

```bash
python blfinder.py -t https://target.com -T token \
  -e known_endpoints.json \
  --import-burp burp_export.xml \
  --import-har session.har \
  --import-filter "/api/"
```

---

## ⚙️ Phase 5: Scan Profiles

Profiles are JSON files that pre-configure the scanner for a specific class of target. They live in `profiles/NAME.json` and can also be loaded from `~/.blfinder/profiles/` or `./profiles/`.

**CLI flags always win.** If you pass `--rate 0.5` alongside `--profile fintech`, the CLI rate is used. Profiles only supply settings you haven't explicitly set.

### Built-in Profiles

| Profile | Best For | Key Settings |
|---------|----------|--------------|
| `ecommerce` | Shopping carts, checkout flows | Price/coupon modules first, checkout flow template, IDOR on order IDs |
| `fintech` | Banking, payment APIs | High confidence (70%), slow rate (1.5s), deep IDOR, strict validation |
| `saas` | SaaS dashboards, admin panels | Mass assignment, BFLA, GraphQL deep, workspace/tenant IDOR |
| `stealth` | Rate-limited or WAF-protected targets | Very slow rate (3s), random UA, minimal footprint |
| `fast` | CTFs, test environments | Zero delay, low confidence threshold, all modules |
| `graphql` | GraphQL-first APIs | GraphQL deep scan, introspection, batching abuse |
| `api_only` | Pure REST APIs, no frontend | Skip JS extraction, subdomain recon off, API modules only |
| `thorough` | Maximum coverage, high-value targets | All modules, multiple confirmation attempts, full recon |

### Custom Profile

Create `profiles/myprofile.json`:

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
    "js_secrets": true
  },
  "flows": ["ecommerce_checkout", "funds_transfer"],
  "auto_flows": true,
  "priority_modules": ["price_manipulation", "idor_bola", "race_condition"],
  "skip_modules": ["account_enumeration", "parameter_pollution"]
}
```

```bash
python blfinder.py -t https://target.com -T token --profile myprofile
```

---

## 🗄️ Phase 5: Persistent Database

BLFinder uses a local SQLite database to track findings across sessions. This makes it practical to work on the same program over days or weeks without re-reporting duplicates or losing context.

### Database Operations

```bash
# Run a scan and persist all findings
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --program target_h1

# Skip endpoints already confirmed vulnerable in previous scans
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --no-repeat

# Print finding history summary
python blfinder.py --show-history --db ~/.blfinder.db

# Search past findings
python blfinder.py --search "price manipulation" --db ~/.blfinder.db
python blfinder.py --search "IDOR" --db ~/.blfinder.db --program target_h1
```

### Database Schema

```
scans         ← scan_id, target, program, config, timestamps, finding_count
findings      ← id, scan_id, title, severity, confirmed, confidence, status
              ← endpoint, evidence, poc, program, created_at
programs      ← handle, scope, notes, created_at
```

### Finding Lifecycle

```
new → exported (after H1 submission) → closed / duplicate / informative
```

---

## 🏴 Phase 5: HackerOne Integration

BLFinder can push findings directly to HackerOne as draft reports via the H1 API. Drafts are created but not submitted — you review and submit manually.

### Setup

Get your API token from [HackerOne Account Settings](https://hackerone.com/settings/api_token/edit). The format is `username:api_token`.

### Export After Scan

```bash
# Auto-export new findings immediately after scanning
python blfinder.py -t https://target.com -T token \
  --db ~/.blfinder.db --program target_h1 \
  --export-h1 target_h1 \
  --h1-token yourusername:your_api_token
```

### Export from Database (No New Scan)

```bash
# Export all findings with status "new" for a program
python blfinder.py \
  --export-h1 target_h1 \
  --h1-token yourusername:your_api_token \
  --db ~/.blfinder.db \
  --program target_h1
```

Each finding generates a HackerOne report with:
- Title from the finding
- CVSS score, CWE, OWASP reference
- Step-by-step reproduction (from the PoC)
- Real request/response evidence (from the EvidencePackage)
- Impact statement (from the impact assessor)

---

## 📊 Phase 5: Live Dashboard

The `--dashboard` flag launches a terminal UI that shows scan progress in real time.

```bash
python blfinder.py -t https://target.com -T token --dashboard
```

**Dashboard panels:**

```
┌─ BLFinder v3.1 ─────────────────────────────────────────────────────────────┐
│ Target: https://api.target.com                      Scan #42                │
│ Endpoints: 18/64 scanned    Requests: 312    429s: 2    Elapsed: 00:04:12   │
│ Current: /api/v1/orders/456                                                  │
├─ Findings ──────────────────────────────────────────────────────────────────┤
│ [CRITICAL ✓] IDOR — Path ID 456→455 returned different resource             │
│ [HIGH]       BOPLA — expand=all exposes hidden fields                       │
│ [CRITICAL ✓] Race Condition — 8/15 concurrent requests succeeded            │
├─ Per-domain Rate ────────────────────────────────────────────────────────────│
│ api.target.com   delay=0.42s   ok=310   429s=2                              │
└─────────────────────── [p] Pause  [q] Quit ─────────────────────────────────┘
```

Use `p` to pause scanning mid-scan (useful when you want to inspect a finding before continuing), `q` to stop.

---

## 📋 Endpoints File Format

Create `endpoints.json` from Burp Suite history, browser DevTools, or the `--import-save` flag:

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
    "url": "/api/v1/orders",
    "method": "GET",
    "body": {},
    "params": {"limit": 10, "offset": 0}
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
  }
]
```

**Pro tip:** The easiest way to build this file is now `--import-burp` or `--import-har` with `--import-save`. Browse the app in Burp, export, and import — no manual JSON editing.

---

## 🔄 Flow Templates

BLFinder v3.1 includes 11 pre-built multi-step flow templates. Run them with `--flow <name>`.

| Template Name | What It Tests |
|---------------|---------------|
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

Each template attacks every marked step for price manipulation, negative quantity, coupon abuse, state machine abuse, mass assignment, workflow bypass, and race conditions on the final step.

### Custom Flow File

```json
{
  "name": "my_custom_flow",
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
[*] BLFinder v3.1 Phase 5 — Target: https://api.target.com
[*] 8 endpoints queued

[*] Smart Discovery — crawling for endpoints...
  [+] Discovered: https://api.target.com/api/v1
  [+] Discovered: https://api.target.com/swagger.json
  [*] Discovered 14 endpoints

[*] Total after discovery: 22 endpoints
[*] Database: ~/.blfinder.db (scan #47)
[*] Verifying 3 findings...

──────────────────────────────────────────────────────────────
 BLFinder v3.1 Phase 5 — Scan Complete
 Target     : https://api.target.com
 Date       : 2026-05-09 14:32:11
──────────────────────────────────────────────────────────────
  CRITICAL   2
  HIGH       1
  TOTAL      3
──────────────────────────────────────────────────────────────
[*] Database: 3 new, 0 duplicates

[CRITICAL] 1. IDOR — Path ID 456→455 returned different resource ✓ CONFIRMED
  Endpoint   : https://api.target.com/api/v1/orders/455
  Category   : Business Logic — IDOR/BOLA
  CWE/OWASP  : CWE-639 / API1:2023
  Confidence : 91% — cross-user confirmed; status 403→200; size +1,240B
  Evidence   : email, phone, address newly exposed  [CROSS-USER CONFIRMED]
```

### HTML Report — 7 Tabs per Finding

| Tab | Content |
|-----|---------|
| **Overview** | Description, endpoint, confidence reasoning, FP analysis, recommendation |
| **Evidence** | Side-by-side baseline vs attack request and response (live captured) |
| **Diff** | Field-level JSON diff with color-coded change table |
| **Impact** | Sensitive data detected, privacy/financial/credential flags, record count |
| **Reproduce** | Verified curl command, step-by-step manual guide |
| **Raw HTTP** | Burp Suite importable format for all captured pairs |
| **HackerOne** | Complete copy-paste ready submission with real endpoints and evidence |

### JSON Report Structure

```json
{
  "meta": {"tool": "BLFinder", "version": "3.1", "target": "...", "scan_date": "..."},
  "summary": {"total": 3, "CRITICAL": 2, "HIGH": 1},
  "findings": [
    {
      "title": "IDOR — Path ID 456→455 returned different resource",
      "severity": "CRITICAL",
      "confidence": 91,
      "confirmed": true,
      "endpoint": "https://api.target.com/api/v1/orders/455",
      "evidence_package": {
        "endpoint": "https://api.target.com/api/v1/orders/455",
        "confirmed": true,
        "has_sensitive": true,
        "sensitive_data": "`email`, `phone`, `address`",
        "verified_curl": "curl -sk -X GET ...",
        "diff_summary": "Size +1240B | email (ADDED) | phone (ADDED)",
        "impact_score": 75,
        "impact_statement": "Email addresses, phone numbers, and physical addresses exposed..."
      }
    }
  ]
}
```

---

## 🔎 Understanding Results

### Confidence Score

| Score | Meaning | Action |
|-------|---------|--------|
| 80–100% | Very likely real | Report immediately |
| 60–79% | Probably real | Manual verify first |
| 40–59% | Possible — needs confirmation | Test manually, then report |
| < 40% | Low confidence | Dropped automatically |

### Confirmed vs Unconfirmed

| Badge | Meaning |
|-------|---------|
| `✓ CONFIRMED` | Cross-user verified OR re-tested N times and reproduced consistently |
| *(no badge)* | Detected heuristically — manual verification recommended before reporting |

### False Positive Notes

The `FP Notes` field explains why a finding might be wrong:

| Note | Action |
|------|--------|
| `WAF/security block detected` | Disable VPN and re-test |
| `Responses nearly identical` | Difference is likely noise — skip |
| `Intermittent reproduction` | Re-run with `--confirm-attempts 3` |
| `Server accepts everything (canary)` | Server has no validation at all — low value |

---

## 🏆 Bug Bounty Tips

### Getting the Best Results

**1. Import your traffic — don't write endpoints.json by hand**
```bash
# Browse the app in Burp, export, import — takes 2 minutes
python blfinder.py -t https://target.com -T token \
  --import-burp session.xml --import-save endpoints.json
```

**2. Always use two accounts — the most important flag**
```bash
# Creates CONFIRMED findings — much higher payouts than heuristic ones
python blfinder.py -T "account1_token" -T2 "account2_token"
```

**3. Use a profile matched to the target**
```bash
--profile ecommerce   # Shopping / marketplace
--profile fintech     # Banking / payments
--profile saas        # B2B SaaS / admin portals
```

**4. Use the database to manage multi-day engagements**
```bash
# Day 1 — scan scope A
python blfinder.py ... --db ~/.blfinder.db --program target_h1

# Day 2 — scan scope B, skip already-found vulns
python blfinder.py ... --db ~/.blfinder.db --program target_h1 --no-repeat

# Review findings any time
python blfinder.py --show-history --db ~/.blfinder.db
```

**5. Use the HackerOne tab in the HTML report**
The report's HackerOne tab generates a complete submission — real endpoint URLs, real request/response pairs, real impact. Do not write the report manually.

**6. Re-run without VPN if findings show WAF notes**
WAF blocks from VPN IPs cause false positives. Disable VPN, re-run, compare results.

**7. Run flow templates on e-commerce targets**
```bash
--flow ecommerce_checkout --flow ecommerce_refund --auto-flows
```

### Typical Payout Ranges

| Finding Type | Typical Payout |
|---|---|
| IDOR/BOLA (confirmed, PII exposed) | $500 – $10,000+ |
| Price/Quantity Manipulation | $500 – $5,000 |
| Race Condition (double-spend) | $500 – $5,000 |
| JWT alg:none bypass | $1,000 – $8,000 |
| Mass Assignment (privilege escalation) | $500 – $3,000 |
| Workflow/MFA bypass | $200 – $2,000 |
| State Machine Abuse | $300 – $3,000 |
| OAuth2 Vulnerability | $500 – $5,000 |

---

## 📁 Project Structure

```
BLfinder/
│
├── blfinder.py                        ← CLI entry point (all phase flags)
├── endpoints.example.json             ← Template for endpoint definitions
├── flows.example.json                 ← Template for custom flow definitions
├── README.md
│
├── profiles/                          ← Phase 5: Scan profile JSON files
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
    ├── __init__.py
    ├── models.py                      ← Shared dataclasses (Finding, ScanConfig, PoC)
    ├── scanner.py                     ← All 21 detection modules + evidence wiring
    ├── confidence.py                  ← Confidence scoring & FP reduction engine
    ├── poc.py                         ← Proof of concept generator
    ├── verifier.py                    ← Finding re-verification loop
    ├── reporter.py                    ← Report dispatcher (HTML/JSON/Markdown)
    │
    ├── evidence/                      ← Phase 2: Evidence capture system
    │   ├── capture.py                 ← EvidencePackage + EvidenceCapture class
    │   ├── http_recorder.py           ← Burp/curl/Python/HTTPie format converter
    │   ├── diff_engine.py             ← Field-level JSON diff engine
    │   └── impact_assessor.py        ← PII/credential/financial impact scoring
    │
    ├── reporting/                     ← Phase 2: Report generators
    │   ├── hackerone_formatter.py     ← HackerOne-ready markdown generator
    │   └── evidence_report.py        ← HTML report with 7-tab evidence layout
    │
    ├── analysis/                      ← Phase 1: Semantic analysis
    │   ├── semantic_diff.py           ← JSON-aware response comparison
    │   └── field_extractor.py         ← Volatile field learning + detection
    │
    ├── oracles/                       ← Phase 1: Oracle-based detection
    │   ├── timing_oracle.py           ← Statistical timing oracle
    │   └── blind_idor.py              ← 5-oracle blind IDOR scanner
    │
    ├── auth/                          ← Phase 1: Session management
    │   ├── session_manager.py         ← Token refresh + CSRF extraction
    │   └── oauth_handler.py           ← OAuth2 flow + vulnerability testing
    │
    ├── flows/                         ← Phase 1: Multi-step flows
    │   ├── flow_replayer.py           ← Multi-step flow executor + attack engine
    │   └── flow_templates.py          ← 11 pre-built business flow templates
    │
    ├── validation/                    ← Phase 3: Endpoint validation
    │   ├── endpoint_validator.py      ← Soft-404, WAF, not-GraphQL detection
    │   └── response_classifier.py    ← Response class + confidence cap
    │
    ├── recon/                         ← Phase 3: Reconnaissance
    │   ├── subdomain_mapper.py        ← Subdomain discovery + API surface scoring
    │   └── js_secret_extractor.py    ← JS file secret pattern extraction
    │
    ├── modules/                       ← Phase 4: Expanded attack surface
    │   ├── idor_mass_enum.py          ← Mass IDOR enumeration + ID harvesting
    │   ├── graphql_deep.py            ← GraphQL schema traversal + field IDOR
    │   ├── websocket_scanner.py       ← WebSocket vulnerability scanner
    │   └── api_version_abuse.py       ← Version endpoint discovery + downgrade
    │
    ├── intelligence/                  ← Phase 4: Business context
    │   └── business_classifier.py    ← Endpoint classification + attack prioritization
    │
    ├── integrations/                  ← Phase 5: Traffic import
    │   └── burp_importer.py           ← Burp XML/JSON, HAR, mitmproxy parser
    │
    ├── storage/                       ← Phase 5: Persistence
    │   └── scan_database.py           ← SQLite DB, dedup, H1 export, history
    │
    └── tui/                           ← Phase 5: Live dashboard
        └── live_dashboard.py          ← Curses/ANSI TUI dashboard + pause support
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named aiohttp` | `pip install aiohttp --break-system-packages` |
| `Connection refused` | Check URL, try `--no-ssl-verify` |
| `All timeouts` | Increase: `--timeout 30` |
| `Too many 429s` | Increase rate: `-r 2.0` or use `--profile stealth` |
| `0 findings` | Add endpoints with `-e` or `--import-burp`, add auth token with `-T` |
| `WAF FP notes on all findings` | Disable VPN and re-run |
| `Permission denied` | `chmod +x blfinder.py` |
| `Termux storage` | `termux-setup-storage` then use `~/storage/downloads/` |
| `Database locked` | Only run one instance per `--db` path at a time |
| `H1 export fails` | Check token format is `username:api_token`, not just the token |
| `Dashboard blank` | Try `--force-ansi` to switch from curses to ANSI mode |
| `Profile not found` | Check `profiles/NAME.json` exists; run without profile flag to proceed |
| `Evidence package missing` | Ensure `core/evidence/` directory is present |
| `HackerOne tab empty` | Requires `core/reporting/` directory |

---

## 👤 About the Author

BLFinder is built by **Adoyi Steven (séç gúy)**, a cybersecurity researcher and penetration tester focused on practical tools for ethical hacking, bug bounty hunting, and enterprise GRC.

- **GitHub:** [Steven5233](https://github.com/Steven5233)
- **Repository:** [BLFinder](https://github.com/Steven5233/BLfinder)

BLFinder started as a personal tool to automate the business logic checks that manual testers run on every engagement — the checks that generic scanners consistently miss. It evolved into a full platform after consistently finding high-severity bugs that Burp Suite's active scanner walked past. Phase 5 adds the operational layer that makes it practical for sustained, multi-day bug bounty engagements.

---

## 🤝 Contributing

Contributions are welcome. To add a new detection module:

1. Add your check method to `core/scanner.py` as `async def _check_yourmodule(...) -> list[Finding]`
2. Use `self._new_evidence()` and `self._req_ev()` to capture HTTP evidence
3. Call `self._build_pkg()` and `self._attach(f, pkg)` before `_finalize_finding()`
4. Add the check to `_run_endpoint_checks()` in `scanner.py`
5. Add a PoC builder in `core/poc.py` matching your category string
6. Open a pull request with a description of what the module detects and at least one real-world example

**Every finding must include:**
- A canary/FP check where applicable
- A `cwe`, `cvss`, and `owasp` reference
- Evidence capture via `_req_ev()` for baseline and attack requests
- A clear `recommendation` field

To add a new scan profile, create `profiles/NAME.json` following the schema in the [Custom Profile](#custom-profile) section.

---

## 📄 License

```
MIT License — Copyright (c) 2026 Adoyi Steven

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, subject to the following conditions:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
The author is not responsible for any misuse or damage caused by this tool.
Use only on systems you own or have explicit authorization to test.
```

---

## 🙏 Acknowledgements

- [OWASP API Security Project](https://owasp.org/API-Security) — vulnerability classification
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — research references
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — real-world bug patterns
- [Intigriti Blog](https://blog.intigriti.com) — business logic research
- The bug bounty community for documenting what automated tools miss

---

<div align="center">

**Built for hunters. Runs on a phone. Reports with proof. Remembers everything.**

*If this tool helped you get a bounty, consider starring the repo ⭐*

**[⭐ Star on GitHub](https://github.com/Steven5233/BLfinder) · [🐛 Report Issues](https://github.com/Steven5233/BLfinder/issues) · [🍴 Fork](https://github.com/Steven5233/BLfinder/fork)**

</div>
