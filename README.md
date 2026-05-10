<div align="center">

```
██████╗ ██╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔══██╗██║     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══██╗██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**Business Logic Flaw Detection Engine — v3.1**

*The scanner that finds what 90% of bug bounty hunters miss*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-green?style=flat-square)](https://termux.dev)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red?style=flat-square)](https://owasp.org/API-Security)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=flat-square)](https://hackerone.com)
[![GitHub](https://img.shields.io/badge/GitHub-Steven5233%2FBLfinder-181717?style=flat-square&logo=github)](https://github.com/Steven5233/BLfinder)

</div>

---

> **⚠️ Legal Disclaimer:** BLFinder is designed exclusively for **authorized security testing** — bug bounty programs, penetration testing engagements, and security research on systems you own or have explicit written permission to test. Unauthorized use against systems you do not have permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Table of Contents

- [What is BLFinder?](#-what-is-blfinder)
- [Why Business Logic?](#-why-business-logic)
- [Detection Modules](#-detection-modules)
- [Key Features](#-key-features)
- [Installation](#-installation-termux--linux)
- [Quick Start](#-quick-start)
- [Usage & Examples](#-usage--examples)
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
| GraphQL IDOR + Introspection | ❌ | ⚠️ | ✅ |
| Coupon Stacking / Type Confusion | ❌ | ❌ | ✅ |
| BOPLA (hidden field exposure) | ❌ | ❌ | ✅ |
| OAuth2 Vulnerability Testing | ❌ | ❌ | ✅ |
| Soft Delete Bypass | ❌ | ❌ | ✅ |
| Real Evidence Capture (Burp format) | manual | manual | ✅ |

---

## 🧩 Detection Modules

BLFinder v3.1 ships **21 detection modules** across three severity tiers.

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
| 16 | **Function Level Access** | User 2 performing DELETE/PUT on User 1's resources — requires second token |
| 17 | **Soft Delete Bypass** | Accessing deleted/archived records via filter parameters. Semantic diff confirms real change |

### 🟡 Medium Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 18 | **GraphQL** | Introspection enabled, unauthenticated data access. Tests multiple common GQL endpoints |
| 19 | **Account Enumeration** | Different error messages and statistical timing oracle revealing valid accounts |
| 20 | **HTTP Method Override** | `X-HTTP-Method-Override` acceptance causing different responses |
| 21 | **Parameter Pollution** | Duplicate query parameters changing application behavior |

### 🤖 Smart Discovery Engine

- **JS file crawler** — extracts API paths from JavaScript bundles
- **OpenAPI/Swagger parser** — auto-generates endpoint list from `/swagger.json`, `/openapi.json`
- **Common path probing** — tests 15+ common API base paths
- **Method inference** — infers HTTP method from path keywords

---

## ✨ Key Features

### 🔬 Real Evidence Capture (v3.1)

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
```

After running, open `~/results/report.html` for a full interactive report with 7 tabs per finding — including side-by-side request comparison, field-level diff, impact assessment, and a HackerOne-ready submission.

---

## 📖 Usage & Examples

```
usage: blfinder.py [-h] -t TARGET [-T TOKEN] [-T2 TOKEN2] [-T3 TOKEN3]
                   [-e ENDPOINTS] [-H Key:Value] [-c name=value]
                   [--proxy PROXY] [-r RATE] [--timeout TIMEOUT]
                   [--no-discover] [--no-ssl-verify] [--fuzz-depth N]
                   [--min-confidence N] [--confirm-attempts N]
                   [--flow TEMPLATE] [--flow-file FILE] [--auto-flows]
                   [--oauth-url URL] [--oauth-id ID] [--oauth-secret SECRET]
                   [--oauth-grant TYPE] [--oauth-user USER] [--oauth-pass PASS]
                   [--refresh-url URL] [--refresh-token TOKEN]
                   [--login-url URL] [--login-body JSON]
                   [--blind-idor] [--samples N]
                   [-o OUTPUT] [--html] [--json] [--md] [-v] [--no-color]
```

### All Options

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
| `--flow` | — | Run a named built-in flow template (repeatable) |
| `--flow-file` | — | Load flow definitions from a JSON file |
| `--auto-flows` | off | Auto-detect app type and run relevant flows |
| `--oauth-url` | — | OAuth2 token endpoint URL |
| `--oauth-id` | — | OAuth2 client_id |
| `--oauth-secret` | — | OAuth2 client_secret |
| `--oauth-grant` | `client_credentials` | OAuth2 grant type |
| `--oauth-user` | — | Username for password grant |
| `--oauth-pass` | — | Password for password grant |
| `--refresh-url` | — | Token refresh endpoint URL |
| `--refresh-token` | — | Refresh token value |
| `--login-url` | — | Re-login URL (fallback for refresh) |
| `--login-body` | — | Re-login body as JSON string |
| `--blind-idor` | off | Enable blind IDOR oracle scanning (slower) |
| `--samples` | `4` | Oracle sample count per test |
| `-o`, `--output` | `.` | Output directory for reports |
| `--html` | off | Generate HTML report (default if no format specified) |
| `--json` | off | Generate JSON report |
| `--md` | off | Generate Markdown report |
| `-v`, `--verbose` | off | Print every request in real time |
| `--no-color` | off | Disable ANSI colors (for log files) |

### Common Scenarios

```bash
# ── Scenario 1: API with JWT auth ─────────────────────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -e endpoints.json \
  --html -o ~/results

# ── Scenario 2: Cookie-based auth ─────────────────────────────────────────────
python blfinder.py \
  -t https://app.target.com \
  -c "session=abc123def456" \
  -c "csrf_token=xyz789" \
  -e endpoints.json

# ── Scenario 3: Two accounts for confirmed IDOR ───────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "victim_user_token" \
  -T2 "attacker_user_token" \
  -e endpoints.json \
  --min-confidence 60

# ── Scenario 4: Through Burp Suite proxy ──────────────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "your_token" \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify \
  -v

# ── Scenario 5: E-commerce flow template ──────────────────────────────────────
python blfinder.py \
  -t https://shop.target.com \
  -T "your_token" \
  --flow ecommerce_checkout \
  --auto-flows \
  --html -o ~/results

# ── Scenario 6: OAuth2 client_credentials ────────────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  --oauth-url https://auth.target.com/oauth/token \
  --oauth-id my_client_id \
  --oauth-secret my_secret \
  -e endpoints.json

# ── Scenario 7: With token auto-refresh ──────────────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "access_token" \
  --refresh-url https://auth.target.com/token/refresh \
  --refresh-token "refresh_token_here" \
  -e endpoints.json

# ── Scenario 8: Slow, careful scan for sensitive targets ──────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "your_token" \
  -r 2.0 \
  --timeout 30 \
  --confirm-attempts 3 \
  --min-confidence 60 \
  --html --json --md -o ~/results

# ── Scenario 9: Full professional bug bounty scan ─────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T user1_token \
  -T2 user2_token \
  -e endpoints.json \
  --flow ecommerce_checkout \
  --flow funds_transfer \
  --auto-flows \
  --blind-idor \
  --html --json --md \
  -o ~/results \
  -v
```

---

## 📋 Endpoints File Format

Create `endpoints.json` from your Burp Suite history or browser DevTools:

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

**Pro tip:** Export requests from Burp Suite → right-click → Copy as curl → convert to this JSON format. The more endpoints you provide, the more thorough the scan.

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

Each template attacks every marked step for:
- Price manipulation
- Negative quantity
- Coupon abuse
- State machine abuse
- Mass assignment
- Workflow bypass (direct step access)
- Race conditions on the final step

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

### Terminal Output (Termux-optimized)

```
[*] BLFinder v3.1 — Target: https://api.target.com
[*] 8 endpoints queued

[*] Smart Discovery — crawling for endpoints...
  [+] Discovered: https://api.target.com/api/v1
  [+] Discovered: https://api.target.com/swagger.json
  [*] Discovered 14 endpoints

[*] Total after discovery: 22 endpoints
[*] Verifying 3 findings...

──────────────────────────────────────────────────────────────
 BLFinder v3.1 — Scan Complete
 Target     : https://api.target.com
 Date       : 2026-05-09 14:32:11
──────────────────────────────────────────────────────────────
  CRITICAL   2
  HIGH       1
  TOTAL      3
──────────────────────────────────────────────────────────────

[CRITICAL] 1. IDOR — Path ID 456→455 returned different resource ✓ CONFIRMED
  Endpoint   : https://api.target.com/api/v1/orders/455
  Category   : Business Logic — IDOR/BOLA
  CWE/OWASP  : CWE-639 / API1:2023
  Confidence : 91% — Baseline 403→200: access gained; cross-user confirmed
  Evidence   : Status 200→200 | Size +1,240B | email,phone newly exposed | [CROSS-USER CONFIRMED]
  Sensitive  : `email`, `phone`, `address`
  PoC        : User can access another user's resource by changing the ID
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

**1. Always use two accounts — the most important flag**
```bash
# Creates CONFIRMED findings — much higher payouts than heuristic ones
python blfinder.py -T "account1_token" -T2 "account2_token"
```

**2. Build a good endpoints.json**
- Use Burp Suite to browse the app normally and export requests
- Include endpoints with IDs in the URL: `/api/orders/123`, `/api/users/456`
- Include full payment/checkout request bodies
- Include anything with coupons, referrals, or credits

**3. Match rate limit to target sensitivity**
```bash
-r 0.1    # CTF / test environments
-r 0.5    # Normal bug bounty targets
-r 2.0    # Sensitive financial applications
```

**4. Use the HackerOne tab directly**
The report's HackerOne tab generates a complete submission — real endpoint URLs, real request/response pairs, real impact. Do not write the report manually.

**5. Re-run without VPN if findings show WAF notes**
WAF blocks from VPN IPs cause false positives. Disable VPN, re-run, compare results.

**6. Run flow templates on e-commerce targets**
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
├── blfinder.py                        ← CLI entry point (Phase 1 + Phase 2 flags)
├── endpoints.example.json             ← Template for endpoint definitions
├── flows.example.json                 ← Template for custom flow definitions
├── README.md
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
    ├── evidence/                      ← v3.1 Evidence capture system
    │   ├── __init__.py
    │   ├── capture.py                 ← EvidencePackage + EvidenceCapture class
    │   ├── http_recorder.py           ← Burp/curl/Python/HTTPie format converter
    │   ├── diff_engine.py             ← Field-level JSON diff engine
    │   └── impact_assessor.py        ← PII/credential/financial impact scoring
    │
    ├── reporting/                     ← v3.1 Report generators
    │   ├── __init__.py
    │   ├── hackerone_formatter.py     ← HackerOne-ready markdown generator
    │   └── evidence_report.py        ← HTML report with 7-tab evidence layout
    │
    ├── analysis/                      ← Phase 1 semantic analysis
    │   ├── __init__.py
    │   ├── semantic_diff.py           ← JSON-aware response comparison
    │   └── field_extractor.py         ← Volatile field learning + detection
    │
    ├── oracles/                       ← Phase 1 oracle-based detection
    │   ├── __init__.py
    │   ├── timing_oracle.py           ← Statistical timing oracle
    │   └── blind_idor.py              ← 5-oracle blind IDOR scanner
    │
    ├── auth/                          ← Phase 1 session management
    │   ├── __init__.py
    │   ├── session_manager.py         ← Token refresh + CSRF extraction
    │   └── oauth_handler.py           ← OAuth2 flow + vulnerability testing
    │
    └── flows/                         ← Phase 1 multi-step flows
        ├── __init__.py
        ├── flow_replayer.py           ← Multi-step flow executor + attack engine
        └── flow_templates.py          ← 11 pre-built business flow templates
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named aiohttp` | `pip install aiohttp --break-system-packages` |
| `Connection refused` | Check URL, try `--no-ssl-verify` |
| `All timeouts` | Increase: `--timeout 30` |
| `Too many 429s` | Increase rate: `-r 2.0` |
| `0 findings` | Add endpoints with `-e`, add auth token with `-T` |
| `WAF FP notes on all findings` | Disable VPN and re-run |
| `Permission denied` | `chmod +x blfinder.py` |
| `Termux storage` | `termux-setup-storage` then use `~/storage/downloads/` |
| `Evidence package missing` | Install complete — check `core/evidence/` directory exists |
| `HackerOne tab empty` | Evidence capture requires `core/reporting/` directory |

---

## 👤 About the Author

BLFinder is built by **Adoyi Steven (séç gúy)**, a cybersecurity researcher and penetration tester focused on practical tools for ethical hacking, bug bounty hunting, and enterprise GRC.

- **GitHub:** [Steven5233](https://github.com/Steven5233)
- **Repository:** [BLFinder](https://github.com/Steven5233/BLfinder)

BLFinder started as a personal tool to automate the business logic checks that manual testers run on every engagement — the checks that generic scanners consistently miss. It evolved into a full platform after consistently finding high-severity bugs that Burp Suite's active scanner walked past.

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

**Built for hunters. Runs on a phone. Reports with proof.**

*If this tool helped you get a bounty, consider starring the repo ⭐*

**[⭐ Star on GitHub](https://github.com/Steven5233/BLfinder) · [🐛 Report Issues](https://github.com/Steven5233/BLfinder/issues) · [🍴 Fork](https://github.com/Steven5233/BLfinder/fork)**

</div>
