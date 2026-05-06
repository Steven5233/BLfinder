**BLFinder v2.0 — Business Logic Flaw Scanner** (formerly BLFScanner)

A specialized tool that detects business logic vulnerabilities missed by traditional automated scanners (Burp, ZAP, Nuclei, etc.).

### Key Detections
- **Price/quantity manipulation** (including negative values, zero, decimals)
- **Workflow/step bypass** (skipping checkout stages)
- **Privilege escalation** (parameter tampering, vertical/horizontal, JWT claims)
- **IDOR / BOLA** (including cross-user confirmation with multiple tokens)
- **Mass assignment** & object property enumeration
- **Race conditions** (concurrent request testing)
- **Coupon/discount stacking & replay**
- **Time-based logic flaws** (date manipulation)
- **State machine abuse**
- **Integer overflow, type confusion, hidden parameters**
- **GraphQL-specific issues**, HTTP method override, and more

Optimized for **bug bounty hunters** and **Termux/Android** use.

## Features
- Async + adaptive rate limiting (handles 429s intelligently)
- Multi-token support (User1 + User2 for IDOR confirmation)
- Smart endpoint discovery (optional)
- Deep nested JSON fuzzing/mutation
- Rich reporting: **HTML** (beautiful interactive), **JSON**, **Markdown**, terminal summary
- User-Agent rotation + proxy support (Burp/HTTP)
- Extensive evasion and confirmation logic

## Installation (Termux Recommended)

See `blfinder/TERMUX_SETUP.md` for full details.

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install aiohttp --break-system-packages

# Clone repo
git clone https://github.com/Steven5233/BLFScanner.git
cd BLFScanner/blfinder
```

## Quick Usage

```bash
# Basic scan
python blfinder.py -t https://api.target.com

# With authentication (recommended)
python blfinder.py -t https://api.target.com -T "eyJhbGciOi..."

# Cross-user IDOR testing (highly recommended)
python blfinder.py \
  -t https://api.target.com \
  -T "user1_token" \
  -T2 "user2_token" \
  -e endpoints.json \
  --html --json --md \
  -o results \
  -v
```

**Other useful flags:**
- `--proxy http://127.0.0.1:8080` — route through Burp
- `--no-ssl-verify`
- `-r 0.5` — adjust rate limit
- `--no-discover` — disable auto-discovery
- `-v` — verbose output

## Endpoints File (`endpoints.json`)

Provide a list of interesting business-logic endpoints for deeper testing. Example included: `endpoints.example.json`.

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
    }
  }
]
```

## Project Structure
```
blfinder/
├── blfinder.py              # CLI entry point
├── core/
│   ├── scanner.py           # Core scanning engine + all detection modules
│   └── reporter.py          # HTML/JSON/MD report generators
├── TERMUX_SETUP.md
├── endpoints.example.json
└── ...
```

**Main scanner** (`core/scanner.py`) implements dozens of targeted business logic checks with baseline responses, mutation logic, success/failure heuristics, and deduplication.

**Reporter** generates professional, color-coded, interactive reports.

## Important Notes / Responsible Use
- This tool performs active testing and parameter tampering. Use **only on targets you are authorized** to test.
- Respect rate limits and terms of service.
- Start with low aggression (`-r 1.0` or higher) on production-like targets.
- Many findings require manual verification.

## Roadmap / Future
- More GraphQL modules
- Login / auth bypass checks
- Better JS endpoint extraction
- Integration with other tools

## Contributing
Pull requests welcome — especially new detection modules or improvements to evasion/adaptive behavior.

---

**Author:** Séç gúy 
