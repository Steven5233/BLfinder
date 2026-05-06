# BLFinder v2.0 — Termux Setup & Usage Guide

## STEP 1: Install Termux

Install from F-Droid (NOT Play Store — outdated there):
  https://f-droid.org/en/packages/com.termux/

## STEP 2: Setup Python

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install aiohttp --break-system-packages
python --version
python -c "import aiohttp; print('aiohttp OK')"
```

## STEP 3: Get BLFinder

```bash
cd ~
ls blfinder/   # should show blfinder.py, core/, etc.
```

## STEP 4: Run It

```bash
cd ~/blfinder

# Basic scan
python blfinder.py -t https://api.target.com

# With auth token
python blfinder.py -t https://api.target.com -T "eyJhbGciOiJIUzI1NiJ9..."

# With TWO tokens (enables cross-user IDOR confirmation)
python blfinder.py \
  -t https://api.target.com \
  -T "user1_jwt_token_here" \
  -T2 "user2_jwt_token_here"

# With endpoint list
python blfinder.py \
  -t https://api.target.com \
  -T "your_token_here" \
  -e endpoints.json

# Full bug bounty scan
python blfinder.py \
  -t https://api.target.com \
  -T "user1_token" \
  -T2 "user2_token" \
  -e endpoints.json \
  --html --json --md \
  -o ~/results \
  -v
```

## STEP 5: Burp Proxy

```bash
python blfinder.py \
  -t https://api.target.com \
  -T "your_token" \
  --proxy http://192.168.1.100:8080 \
  --no-ssl-verify
```

## STEP 6: View Results

```bash
pkg install termux-tools -y
termux-open ~/results/report.html
# or
cat ~/results/report.md | less -R
```

## Troubleshooting

"No module named aiohttp":
  pip install aiohttp --break-system-packages

"Connection refused":
  Try --no-ssl-verify

"Too many 429 errors":
  Use -r 1.5 or higher

"Permission denied":
  chmod +x blfinder.py
