#!/usr/bin/env python3
"""
BLFinder v2.0 — CLI Entry Point
Usage: python blfinder.py -t https://target.com [options]
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="BLFinder v2.0 — Business Logic Flaw Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES (Termux):
  python blfinder.py -t https://api.target.com -T eyJhbGciOi...
  python blfinder.py -t https://api.target.com -T user1_token -T2 user2_token -e endpoints.json
  python blfinder.py -t https://api.target.com --no-discover -r 0.1
  python blfinder.py -t https://api.target.com --proxy http://127.0.0.1:8080
  python blfinder.py -t https://api.target.com -v -o results/ --html --json --md
""")
    p.add_argument("-t", "--target",   required=True, help="Target base URL")
    p.add_argument("-T",  "--token",   default="",    help="Auth token for User 1 (primary)")
    p.add_argument("-T2", "--token2",  default="",    help="Auth token for User 2 (IDOR cross-user)")
    p.add_argument("-T3", "--token3",  default="",    help="Auth token for User 3 (privilege chain)")
    p.add_argument("-e",  "--endpoints", default="",  help="Path to endpoints JSON file")
    p.add_argument("-H",  "--header",  action="append", default=[], metavar="Key:Value", help="Extra headers")
    p.add_argument("-c",  "--cookie",  action="append", default=[], metavar="name=value", help="Cookies")
    p.add_argument("--proxy",          default="",    help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("-r",  "--rate",    type=float, default=0.3, help="Base delay between requests (default: 0.3)")
    p.add_argument("--timeout",        type=int,   default=20,  help="Request timeout in seconds (default: 20)")
    p.add_argument("--no-discover",    action="store_true", help="Disable smart endpoint discovery")
    p.add_argument("--no-ssl-verify",  action="store_true", help="Disable SSL verification")
    p.add_argument("--fuzz-depth",     type=int,   default=2,   help="Nested JSON mutation depth (default: 2)")
    p.add_argument("-o",  "--output",  default=".",  help="Output directory for reports")
    p.add_argument("--html",           action="store_true", help="Generate HTML report")
    p.add_argument("--json",           action="store_true", help="Generate JSON report")
    p.add_argument("--md",             action="store_true", help="Generate Markdown report")
    p.add_argument("-v",  "--verbose", action="store_true", help="Verbose request logging")
    p.add_argument("--no-color",       action="store_true", help="Disable ANSI colors")
    return p.parse_args()


def load_endpoints(path: str) -> list[dict]:
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "endpoints" in data:
            return data["endpoints"]
    except FileNotFoundError:
        print(f"[!] Endpoints file not found: {path}")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in endpoints file: {e}")
    return []


def parse_headers(header_list: list[str]) -> dict:
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def parse_cookies(cookie_list: list[str]) -> dict:
    cookies = {}
    for c in cookie_list:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


async def main():
    args = parse_args()

    try:
        from core.scanner import BLFScanner, ScanConfig
        from core.reporter import (
            print_terminal_summary, generate_html_report,
            generate_json_report, generate_markdown_report
        )
    except ImportError as e:
        print(f"[!] Import error: {e}")
        print("[!] Run: pip install aiohttp --break-system-packages")
        sys.exit(1)

    config = ScanConfig(
        target_url=args.target.rstrip("/"),
        auth_token=args.token,
        second_user_token=args.token2,
        third_user_token=args.token3,
        headers=parse_headers(args.header),
        cookies=parse_cookies(args.cookie),
        proxy=args.proxy,
        rate_limit=args.rate,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        smart_discovery=not args.no_discover,
        fuzz_depth=args.fuzz_depth,
        output_dir=args.output,
        verbose=args.verbose,
        no_auth_check=True,
    )

    endpoints = load_endpoints(args.endpoints)
    if not endpoints:
        endpoints = [{"url": "/", "method": "GET", "body": {}, "params": {}}]
        print("[*] No endpoints file — using smart discovery only")

    async with BLFScanner(config) as scanner:
        findings = await scanner.run_all_modules(endpoints)

    os.makedirs(args.output, exist_ok=True)
    cfg_dict = {"target_url": config.target_url}

    if not args.no_color:
        print_terminal_summary(findings, cfg_dict)
    else:
        print(f"\n[+] Scan complete. {len(findings)} findings.")

    if args.html or not (args.json or args.md):
        generate_html_report(findings, cfg_dict, f"{args.output}/report.html")
    if args.json:
        generate_json_report(findings, cfg_dict, f"{args.output}/report.json")
    if args.md:
        generate_markdown_report(findings, cfg_dict, f"{args.output}/report.md")

    critical_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
