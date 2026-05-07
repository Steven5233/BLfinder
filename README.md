

```
██████╗ ██╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔══██╗██║     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══██╗██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
```

**Business Logic Flaw Detection Engine — v2.1**

*The scanner that finds what 90% of bug bounty hunters miss*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20macOS-green?style=flat-square)](https://termux.dev)
[![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-red?style=flat-square)](https://owasp.org/API-Security)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange?style=flat-square)](https://hackerone.com)

</div>

---

> **⚠️ Legal Disclaimer:** BLFinder is designed exclusively for **authorized security testing** — bug bounty programs, penetration testing engagements, and security research on systems you own or have explicit written permission to test. Unauthorized use against systems you do not have permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## About the Author

BLFINDER is built by **Adoyi Steven(séç gúy)**, a cybersecurity researcher and penetration tester focused on practical tools for ethical hacking, bug bounty hunting, and enterprise GRC.

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
- [Output & Reports](#-output--reports)
- [Understanding Results](#-understanding-results)
- [Bug Bounty Tips](#-bug-bounty-tips)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)

---

## 🔍 What is BLFinder?

BLFinder is an **async Python security scanner** purpose-built to detect business logic vulnerabilities in REST APIs and web applications. Unlike generic scanners (Burp Suite active scan, OWASP ZAP, nikto), BLFinder focuses exclusively on flaws that require **semantic understanding of the application's business rules** — vulnerabilities that signature-based tools cannot detect.

It was built to run natively on **Termux for Android**, so you can hunt bugs from anywhere with your phone.

Every finding includes:
- **Confidence score** (0–100%) with reasoning
- **False positive analysis** with automatic re-verification
- **Proof of Concept** in three formats: `curl`, `Python script`, and `Burp Suite raw request`
- **Step-by-step reproduction guide** ready to paste into HackerOne/Bugcrowd

---

## 🎯 Why Business Logic?

Most automated scanners test for known vulnerability patterns — SQLi, XSS, path traversal. Business logic flaws require understanding **what the application is supposed to do** and testing whether it can be made to do something else.

| Vulnerability Type | Burp Suite Active | OWASP ZAP | BLFinder |
|---|:---:|:---:|:---:|
| Price/Quantity Manipulation | ❌ | ❌ | ✅ |
| IDOR / BOLA (cross-user confirmed) | ⚠️ | ⚠️ | ✅ |
| Race Conditions | ❌ | ❌ | ✅ |
| JWT alg:none + Claim Escalation | ⚠️ | ❌ | ✅ |
| State Machine Abuse | ❌ | ❌ | ✅ |
| Mass Assignment | ⚠️ | ❌ | ✅ |
| Workflow / MFA Bypass | ❌ | ❌ | ✅ |
| GraphQL IDOR + Introspection | ❌ | ⚠️ | ✅ |
| Coupon Stacking / Type Confusion | ❌ | ❌ | ✅ |
| BOPLA (hidden field exposure) | ❌ | ❌ | ✅ |
| Soft Delete Bypass | ❌ | ❌ | ✅ |
| Account Enumeration (timing oracle) | ⚠️ | ⚠️ | ✅ |

---

## 🧩 Detection Modules

BLFinder v2.1 ships **20 detection modules**:

### 🔴 Critical Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 1 | **Price Manipulation** | Tampers price/amount/total fields including deeply nested JSON. Detects when orders are created at attacker-controlled prices |
| 2 | **Negative Quantity** | Submits negative quantities to trigger reverse charges, negative inventory, or credit abuse |
| 3 | **IDOR / BOLA** | Path IDs, body IDs, UUID swaps, header injection (`X-User-Id`, `X-Admin-User`), no-auth access — all with cross-user confirmation |
| 4 | **Mass Assignment** | Injects privileged fields (`is_admin`, `role`, `kyc_verified`, etc.) and confirms when they're reflected with elevated values |
| 5 | **State Machine Abuse** | Forces objects to privileged states (`paid`, `approved`, `verified`) without satisfying transition conditions |
| 6 | **Race Conditions** | Fires 15 concurrent requests to detect double-spending, duplicate coupon redemption, and single-use bypass |
| 7 | **JWT alg:none + Claim Escalation** | Tests signature bypass and arbitrary claim injection with false-positive verification |
| 8 | **BFLA / Privilege Escalation** | Probes admin endpoints with low-privilege and no-auth tokens, verifies actual content is returned |

### 🟠 High Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 9 | **Workflow / MFA Bypass** | Skips multi-step workflows, tests OTP/MFA token omission |
| 10 | **Coupon Abuse** | Array injection, type confusion, stacking, replay attacks |
| 11 | **BOPLA** | Hidden fields exposed via `?expand=all`, `?fields=*`, `?include_deleted=true` |
| 12 | **Time Logic Bypass** | Far-future/past timestamps in body and headers to bypass expiry |
| 13 | **Integer Overflow** | Extreme values causing negative balances or server errors |
| 14 | **Limit/Offset Abuse** | Pagination manipulation to dump all records |
| 15 | **Function Level Access (BFLA)** | User 2 performing DELETE/PUT on User 1's resources |
| 16 | **Soft Delete Bypass** | Accessing deleted/archived records via filter parameters |

### 🟡 Medium Severity Modules

| # | Module | What It Finds |
|---|--------|---------------|
| 17 | **GraphQL** | Introspection enabled, unauthenticated data access |
| 18 | **Account Enumeration** | Different error messages and timing oracles revealing valid accounts |
| 19 | **HTTP Method Override** | `X-HTTP-Method-Override` header acceptance |
| 20 | **Parameter Pollution** | Duplicate query parameters changing application behavior |

### 🤖 Smart Discovery Engine

- **JS file crawler** — extracts API paths from JavaScript bundles
- **OpenAPI/Swagger parser** — auto-generates endpoint list from `/swagger.json`, `/openapi.json`
- **Common path probing** — tests 20+ common API base paths
- **Method inference** — guesses HTTP method from path keywords

---

## ✨ Key Features

### 🎯 Proof of Concept Generation
Every finding automatically generates:
```
┌─ cURL command      → Copy-paste ready, runs immediately
├─ Python script     → Standalone, no setup needed
├─ Burp Suite format → Raw HTTP for Repeater
└─ Manual steps      → For your HackerOne writeup
```

### 📊 Confidence Scoring & FP Reduction
Each finding is scored 0–100% before reporting:
- **HTTP status comparison** (403→200 = strong signal)
- **Semantic body analysis** (success/failure token detection)
- **Response similarity scoring** using `difflib` (ignores noise)
- **JSON structure diff** (new keys, sensitive field detection)
- **Canary request testing** (confirms server doesn't accept everything)
- **WAF detection** (flags blocked responses automatically)
- **Re-verification loop** — every finding is re-tested N times before reporting

### ⚡ Adaptive Rate Limiter
```
429 received → exponential backoff (2^n × base_delay, max 30s)
10 clean responses → auto speed-up (×0.85 per cycle)
Per-domain tracking → multiple targets handled independently
```

### 🔄 Cross-User IDOR Confirmation
With two tokens (`-T` + `-T2`), BLFinder automatically:
1. Finds a potential IDOR with User 1's token
2. Confirms User 2 can access User 1's resource
3. Marks the finding as `✓ CONFIRMED` with `CRITICAL` severity

---

## 📱 Installation (Termux + Linux)

### Termux (Android) — Recommended

```bash
# Step 1: Install from F-Droid (NOT Play Store)
# https://f-droid.org/en/packages/com.termux/

# Step 2: Install dependencies
pkg update && pkg upgrade -y
pkg install python git -y
pip install aiohttp --break-system-packages

# Step 3: Clone the tool
git clone  https://github.com/Steven5233/BLFScanner.git ~/blfinder
cd ~/blfinder

# Step 4: Verify
python blfinder.py --help
```

### Linux / macOS

```bash
# Clone
git clone https://github.com/Steven5233/BLFScanner.git
cd blfinder

# Install dependencies
pip install aiohttp

# Run
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

After running, open `~/results/report.html` in your browser for a full interactive report with tabbed PoC for every finding.

---

## 📖 Usage & Examples

```
usage: blfinder.py [-h] -t TARGET [-T TOKEN] [-T2 TOKEN2] [-T3 TOKEN3]
                   [-e ENDPOINTS] [-H Key:Value] [-c name=value]
                   [--proxy PROXY] [-r RATE] [--timeout TIMEOUT]
                   [--no-discover] [--no-ssl-verify] [--fuzz-depth N]
                   [--min-confidence N] [--confirm-attempts N]
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
| `-o`, `--output` | `.` | Output directory for reports |
| `--html` | off | Generate HTML report |
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

# ── Scenario 5: Fast recon, no verification ───────────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "your_token" \
  --no-discover \
  -r 0.1 \
  --confirm-attempts 1 \
  --min-confidence 30

# ── Scenario 6: Slow, careful scan for sensitive targets ──────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "your_token" \
  -r 2.0 \
  --timeout 30 \
  --confirm-attempts 3 \
  --min-confidence 60 \
  --html --json --md -o ~/results

# ── Scenario 7: Extra headers (API key + origin) ──────────────────────────────
python blfinder.py \
  -t https://api.target.com \
  -T "bearer_token" \
  -H "X-Api-Key: your_api_key" \
  -H "Origin: https://app.target.com" \
  -H "Referer: https://app.target.com/dashboard" \
  -e endpoints.json
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
    "params": {
      "limit": 10,
      "offset": 0
    }
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
    "url": "/api/v1/coupons/redeem",
    "method": "POST",
    "body": {
      "coupon_code": "FREESHIP",
      "order_id": 456
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
  },
  {
    "url": "/api/v1/auth/login",
    "method": "POST",
    "body": {
      "email": "user@example.com",
      "password": "password123"
    },
    "params": {}
  }
]
```

**Pro tip:** Export requests from Burp Suite → right-click → Copy as curl → convert to this format. The more endpoints you provide, the more thorough the scan.

---

## 📊 Output & Reports

### Terminal Output (Termux-optimized)

```
[*] BLFinder v2.1 — Target: https://api.target.com
[*] 8 endpoints queued

[*] Smart Discovery — crawling for endpoints...
  [+] Discovered: https://api.target.com/api/v1
  [+] Discovered: https://api.target.com/swagger.json
  [*] Discovered 14 endpoints

[*] Total after discovery: 22 endpoints

[*] Verifying 3 findings...
─────────────────────────────────────────────────────────────────
 BLFinder v2.1 — Scan Complete
 Target     : https://api.target.com
 Date       : 2026-05-07 18:34:58
─────────────────────────────────────────────────────────────────
  CRITICAL   2
  HIGH       1
  TOTAL      3
─────────────────────────────────────────────────────────────────

[CRITICAL] 1. IDOR/BOLA — Path ID 456 → 455 leaked different resource ✓ CONFIRMED
  Category   : Business Logic — IDOR/BOLA
  CWE/OWASP  : CWE-639 / API1:2023 Broken Object Level Authorization
  Confidence : 85% — Baseline 403 → tampered 200: access gained; Cross-user confirmed
  Evidence   : ID 456 → 455: responses differ [CROSS-USER CONFIRMED]
  PoC        : User can access another user's resource by changing the ID
```

### HTML Report

An interactive dark-themed report with:
- Severity summary dashboard
- Collapsible findings (Critical/High auto-expanded)
- **Tabbed PoC section** per finding (cURL / Python / Burp / Steps)
- Confidence bar with reasoning
- False positive analysis notes
- OWASP/CWE references

### JSON Report

Machine-readable output for integration with CI/CD pipelines, Jira, or custom dashboards:

```json
{
  "meta": {
    "tool": "BLFinder",
    "version": "2.1",
    "target": "https://api.target.com",
    "scan_date": "2026-05-07T18:34:58"
  },
  "summary": {
    "total": 3,
    "CRITICAL": 2,
    "HIGH": 1
  },
  "findings": [
    {
      "title": "IDOR/BOLA — Path ID 456 → 455 leaked different resource",
      "severity": "CRITICAL",
      "confidence": 85,
      "confirmed": true,
      "cwe": "CWE-639",
      "cvss": 9.1,
      "owasp": "API1:2023 Broken Object Level Authorization",
      "poc": {
        "summary": "...",
        "curl_command": "curl -sk ...",
        "python_script": "#!/usr/bin/env python3 ...",
        "burp_request": "GET /api/v1/orders/455 HTTP/1.1 ...",
        "steps": ["1. ...", "2. ..."],
        "expected_result": "..."
      }
    }
  ]
}
```

### Markdown Report

Structured write-up ready to paste into HackerOne, Bugcrowd, or Notion. Each finding includes full PoC, evidence, and reproduction steps in markdown format.

---

## 🔎 Understanding Results

### Confidence Score

| Score | Meaning | Action |
|-------|---------|--------|
| 80–100% | Very likely real | Report immediately |
| 60–79% | Probably real | Manual verify first |
| 40–59% | Possible, needs confirmation | Test manually, then report |
| < 40% | Low confidence | Dropped automatically |

### Confirmed vs Unconfirmed

| Badge | Meaning |
|-------|---------|
| `✓ CONFIRMED` | Cross-user verified OR re-tested N times and reproduced |
| *(no badge)* | Detected heuristically — manual verification recommended |

### False Positive Notes

The `FP Notes` field tells you **why the finding might be wrong**:

| Note | Meaning |
|------|---------|
| `WAF/security block detected` | Response may be a WAF block page, not real data |
| `Responses nearly identical` | Difference may be noise (timestamp, session ID) |
| `Intermittent reproduction` | Only reproduced on some retries — timing-dependent |
| `Generic success response` | Server returns `{"success":true}` for everything |

---

## 🏆 Bug Bounty Tips

### Getting the Best Results

**1. Always use two accounts**
```bash
# Create two accounts on the target, get both tokens
python blfinder.py -T "account1_token" -T2 "account2_token"
# This enables CONFIRMED IDOR findings — much higher payouts
```

**2. Build a good endpoints.json**
- Use Burp Suite to browse the app normally and export requests
- Include endpoints with IDs in the URL: `/api/orders/123`, `/api/users/456`
- Include payment/checkout flows with full request bodies
- Include anything with coupons, referrals, or credits

**3. Match rate limit to target sensitivity**
```bash
-r 0.1    # CTF / test environments
-r 0.5    # Normal bug bounty targets
-r 2.0    # Sensitive financial applications
```

**4. Increase confidence threshold for high-value programs**
```bash
--min-confidence 70  # Only report high-confidence findings
--confirm-attempts 3 # Re-test 3 times before accepting
```

**5. Run without VPN if findings show WAF notes**
```bash
# WAF blocks from VPN IPs can cause false positives
# Disable VPN, re-run, compare results
```

### What to Include in Your Report

- ✅ Screenshot of normal request + response
- ✅ Screenshot of exploited request + response
- ✅ The curl command from the PoC section
- ✅ The Python script from the PoC section
- ✅ Clear description of the business impact
- ✅ Markdown report as an attachment

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

---

## 📁 Project Structure

```
blfinder/
│
├── blfinder.py                  ← CLI entry point
├── endpoints.example.json       ← Template for endpoint definitions
├── TERMUX_SETUP.md              ← Android/Termux setup guide
├── README.md                    ← This file
│
└── core/
    ├── __init__.py
    ├── models.py                ← Shared dataclasses (Finding, ScanConfig, PoC)
    ├── scanner.py               ← All 20 detection modules
    ├── confidence.py            ← Confidence scoring & FP reduction engine
    ├── poc.py                   ← Proof of concept generator
    ├── verifier.py              ← Finding re-verification loop
    └── reporter.py              ← HTML / JSON / Markdown report generator
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `No module named aiohttp` | `pip install aiohttp --break-system-packages` |
| `Connection refused` | Check URL, try `--no-ssl-verify` |
| `All timeouts` | Increase: `--timeout 30` |
| `Too many 429s` | Increase rate: `-r 2.0` |
| `0 findings` | Add more endpoints with `-e`, add auth token with `-T` |
| `WAF FP notes on all findings` | Disable VPN and re-run |
| `Permission denied` | `chmod +x blfinder.py` |
| `Termux storage` | `termux-setup-storage` then use `~/storage/downloads/` |

---

## 🤝 Contributing

Contributions are welcome. To add a new detection module:

1. Add your check method to `core/scanner.py` as `async def _check_yourmodule(...) -> list[Finding]`
2. Call `self._finalize_finding(...)` on every finding before appending (this applies confidence scoring + PoC)
3. Add a PoC builder in `core/poc.py` matching your category string
4. Add the check to `_run_endpoint_checks()` in `scanner.py`
5. Open a pull request with a description of what the module detects and at least one real-world example

Please ensure all findings include:
- A canary/FP check where possible
- A `cwe`, `cvss`, and `owasp` reference
- A clear `recommendation` field

---

## 📄 License

```
MIT License — Copyright (c) 2026

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

**Built for hunters. Runs on a phone. Finds what others miss.**

*If this tool helped you get a bounty, consider starring the repo ⭐*

</div>
