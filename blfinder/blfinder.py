#!/usr/bin/env python3
"""
BLFinder v3.0 — CLI Entry Point
Phase 1: Multi-step flows, blind IDOR, session management, OAuth2

New flags in v3.0:
  --flow            Run a named built-in flow template
  --flow-file       Load flow definitions from a JSON file
  --auto-flows      Auto-detect and run relevant flow templates
  --oauth-url       OAuth2 token endpoint URL
  --oauth-id        OAuth2 client_id
  --oauth-secret    OAuth2 client_secret
  --oauth-grant     OAuth2 grant type (client_credentials|password)
  --oauth-user      Username for password grant
  --oauth-pass      Password for password grant
  --refresh-url     Token refresh endpoint
  --refresh-token   Refresh token value
  --login-url       Re-login URL (fallback for token refresh)
  --login-body      Re-login body as JSON string
  --blind-idor      Enable blind IDOR oracle scanning
  --samples         Oracle sample count (default: 4)
  --product-id      Product ID for e-commerce flow templates
  --product-price   Product price for e-commerce flow templates
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="BLFinder v3.0 — Business Logic Flaw Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic scan
  python blfinder.py -t https://api.target.com -T "token"

  # With two accounts for IDOR confirmation
  python blfinder.py -t https://api.target.com -T user1_token -T2 user2_token -e endpoints.json

  # Run built-in e-commerce flow template
  python blfinder.py -t https://shop.target.com -T "token" --flow ecommerce_checkout

  # Run custom flow from file
  python blfinder.py -t https://api.target.com -T "token" --flow-file flows.json

  # OAuth2 client_credentials
  python blfinder.py -t https://api.target.com \\
    --oauth-url https://auth.target.com/oauth/token \\
    --oauth-id my_client_id --oauth-secret my_secret

  # OAuth2 password grant
  python blfinder.py -t https://api.target.com \\
    --oauth-url https://auth.target.com/token \\
    --oauth-id client_id --oauth-secret secret \\
    --oauth-grant password --oauth-user user@test.com --oauth-pass pass123

  # With token auto-refresh
  python blfinder.py -t https://api.target.com -T "access_token" \\
    --refresh-url https://auth.target.com/token/refresh \\
    --refresh-token "refresh_token_here"

  # Full professional scan with all Phase 1 features
  python blfinder.py \\
    -t https://api.target.com \\
    -T user1_token -T2 user2_token \\
    -e endpoints.json \\
    --flow ecommerce_checkout \\
    --auto-flows \\
    --blind-idor \\
    --html --json --md \\
    -o ~/results -v
""",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    p.add_argument("-t",  "--target",    required=True,           help="Target base URL")
    p.add_argument("-T",  "--token",     default="",              help="Auth token for User 1")
    p.add_argument("-T2", "--token2",    default="",              help="Auth token for User 2 (IDOR confirmation)")
    p.add_argument("-T3", "--token3",    default="",              help="Auth token for User 3")
    p.add_argument("-e",  "--endpoints", default="",              help="Endpoints JSON file")
    p.add_argument("-H",  "--header",    action="append", default=[], metavar="Key:Value")
    p.add_argument("-c",  "--cookie",    action="append", default=[], metavar="name=value")
    p.add_argument("--proxy",            default="",              help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("-r",  "--rate",      type=float, default=0.3, help="Base request delay in seconds (default: 0.3)")
    p.add_argument("--timeout",          type=int,   default=20,  help="Request timeout in seconds (default: 20)")
    p.add_argument("--no-discover",      action="store_true",     help="Disable smart endpoint discovery")
    p.add_argument("--no-ssl-verify",    action="store_true",     help="Disable SSL verification")
    p.add_argument("--fuzz-depth",       type=int,   default=2,   help="Nested JSON mutation depth (default: 2)")
    p.add_argument("--min-confidence",   type=int,   default=40,  help="Min confidence %% to report (default: 40)")
    p.add_argument("--confirm-attempts", type=int,   default=2,   help="Re-verification attempts (default: 2)")

    # ── Phase 1: Flows ────────────────────────────────────────────────────────
    p.add_argument(
        "--flow",
        action="append", default=[],
        metavar="TEMPLATE_NAME",
        help=(
            "Run a named built-in flow template. Can repeat. "
            "Options: " + ", ".join([
                "ecommerce_checkout", "ecommerce_refund", "subscription_upgrade",
                "funds_transfer", "withdrawal", "password_reset",
                "user_registration", "redeem_reward", "referral_bonus",
                "kyc_verification", "api_key_creation",
            ])
        ),
    )
    p.add_argument(
        "--flow-file", default="",
        help="Path to a JSON file containing custom flow definitions (flows.json format)",
    )
    p.add_argument(
        "--auto-flows", action="store_true",
        help="Auto-detect application type and run relevant flow templates",
    )
    p.add_argument("--product-id",    type=int,   default=1,     help="Product ID for e-commerce flow templates")
    p.add_argument("--product-price", type=float, default=99.99, help="Product price for e-commerce flow templates")

    # ── Phase 1: OAuth2 ───────────────────────────────────────────────────────
    p.add_argument("--oauth-url",    default="", help="OAuth2 token endpoint URL")
    p.add_argument("--oauth-id",     default="", help="OAuth2 client_id")
    p.add_argument("--oauth-secret", default="", help="OAuth2 client_secret")
    p.add_argument(
        "--oauth-grant", default="client_credentials",
        choices=["client_credentials", "password", "refresh_token"],
        help="OAuth2 grant type (default: client_credentials)",
    )
    p.add_argument("--oauth-user",  default="", help="Username for OAuth2 password grant")
    p.add_argument("--oauth-pass",  default="", help="Password for OAuth2 password grant")
    p.add_argument("--oauth-scope", default="", help="OAuth2 scope")

    # ── Phase 1: Session / Token Refresh ──────────────────────────────────────
    p.add_argument("--refresh-url",   default="", help="Token refresh endpoint URL")
    p.add_argument("--refresh-token", default="", help="Refresh token value")
    p.add_argument("--login-url",     default="", help="Re-login URL for token refresh fallback")
    p.add_argument(
        "--login-body", default="",
        help='Re-login request body as JSON string e.g. \'{"email":"x","password":"y"}\'',
    )

    # ── Phase 1: Blind IDOR ───────────────────────────────────────────────────
    p.add_argument("--blind-idor", action="store_true", help="Enable blind IDOR oracle scanning (slower)")
    p.add_argument("--samples",    type=int, default=4,  help="Oracle sample count per test (default: 4)")

    # ── Output ────────────────────────────────────────────────────────────────
    p.add_argument("-o",  "--output",  default=".", help="Output directory for reports")
    p.add_argument("--html",           action="store_true", help="Generate HTML report")
    p.add_argument("--json",           action="store_true", help="Generate JSON report")
    p.add_argument("--md",             action="store_true", help="Generate Markdown report")
    p.add_argument("-v",  "--verbose", action="store_true", help="Verbose request logging")
    p.add_argument("--no-color",       action="store_true", help="Disable ANSI colors (for log files)")

    return p.parse_args()


def load_endpoints(path: str) -> list[dict]:
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("endpoints", [])
    except FileNotFoundError:
        print(f"[!] Endpoints file not found: {path}")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in endpoints file: {e}")
    return []


def load_flow_file(path: str) -> list[dict]:
    """Load one or more flow definitions from a JSON file."""
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "steps" in data:
            return [data]   # Single flow
        return []
    except FileNotFoundError:
        print(f"[!] Flow file not found: {path}")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in flow file: {e}")
    return []


def parse_headers(header_list: list[str]) -> dict:
    h = {}
    for item in header_list:
        if ":" in item:
            k, v = item.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def parse_cookies(cookie_list: list[str]) -> dict:
    c = {}
    for item in cookie_list:
        if "=" in item:
            k, v = item.split("=", 1)
            c[k.strip()] = v.strip()
    return c


def build_flow_configs(args) -> list:
    """Build flow configuration list from CLI args."""
    configs = []

    # Built-in named templates
    for template_name in args.flow:
        configs.append({"__template__": template_name})

    # Custom flow file
    for flow_def in load_flow_file(args.flow_file):
        configs.append(flow_def)

    return configs


def build_oauth_config(args):
    """Build OAuthConfig from CLI args if OAuth flags are provided."""
    if not args.oauth_url:
        return None
    try:
        from core.auth.oauth_handler import OAuthConfig
        login_body = {}
        if args.login_body:
            try:
                login_body = json.loads(args.login_body)
            except json.JSONDecodeError:
                print(f"[!] Invalid --login-body JSON: {args.login_body}")

        return OAuthConfig(
            token_url=args.oauth_url,
            client_id=args.oauth_id,
            client_secret=args.oauth_secret,
            grant_type=args.oauth_grant,
            username=args.oauth_user,
            password=args.oauth_pass,
            scope=args.oauth_scope,
        )
    except ImportError:
        print("[!] OAuth handler not available — skipping OAuth config")
        return None


def build_refresh_config(args):
    """Build RefreshConfig from CLI args if refresh flags are provided."""
    if not args.refresh_url and not args.login_url:
        return None
    try:
        from core.auth.session_manager import RefreshConfig
        login_body = {}
        if args.login_body:
            try:
                login_body = json.loads(args.login_body)
            except json.JSONDecodeError:
                pass

        return RefreshConfig(
            refresh_url=args.refresh_url,
            refresh_token_value=args.refresh_token,
            login_url=args.login_url,
            login_body=login_body,
        )
    except ImportError:
        return None


async def main():
    args = parse_args()

    try:
        from core.models import ScanConfig
        from core.scanner import BLFScanner
        from core.reporter import (
            print_terminal_summary,
            generate_html_report,
            generate_json_report,
            generate_markdown_report,
        )
    except ImportError as e:
        print(f"[!] Import error: {e}")
        print("[!] Run: pip install aiohttp --break-system-packages")
        sys.exit(1)

    # ── Build ScanConfig ──────────────────────────────────────────────────────
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
        min_confidence=args.min_confidence,
        confirmation_attempts=args.confirm_attempts,
    )

    # ── Phase 1: Attach new config fields ────────────────────────────────────
    # Flow configs
    flow_configs = build_flow_configs(args)
    config.run_flows = bool(flow_configs) or args.auto_flows
    config.flow_configs = flow_configs
    config.auto_detect_flows = args.auto_flows
    config.product_id    = args.product_id
    config.product_price = args.product_price

    # OAuth config
    oauth_cfg = build_oauth_config(args)
    config.oauth_config = oauth_cfg

    # Refresh config
    refresh_cfg = build_refresh_config(args)
    config.refresh_config = refresh_cfg

    # Blind IDOR oracle samples
    config.oracle_samples = args.samples

    # ── Resolve flow templates ────────────────────────────────────────────────
    if flow_configs:
        try:
            from core.flows.flow_templates import FlowTemplates
            resolved_flows = []
            for fc in flow_configs:
                if isinstance(fc, dict) and "__template__" in fc:
                    template_name = fc["__template__"]
                    template_fn = getattr(FlowTemplates, template_name, None)
                    if template_fn:
                        resolved_flows.append(template_fn(
                            product_id=args.product_id,
                            price=args.product_price,
                        ) if template_name == "ecommerce_checkout" else template_fn())
                        print(f"[*] Flow template loaded: {template_name}")
                    else:
                        print(f"[!] Unknown flow template: {template_name}")
                        print(f"[!] Available: {', '.join(FlowTemplates.list_all())}")
                else:
                    resolved_flows.append(fc)
            config.flow_configs = resolved_flows
        except ImportError as e:
            print(f"[!] Flow templates not available: {e}")

    # ── Load endpoints ────────────────────────────────────────────────────────
    endpoints = load_endpoints(args.endpoints)
    if not endpoints:
        endpoints = [{"url": "/", "method": "GET", "body": {}, "params": {}}]
        print("[*] No endpoints file — using smart discovery only")

    # ── Run scanner ───────────────────────────────────────────────────────────
    async with BLFScanner(config) as scanner:
        findings = await scanner.run_all_modules(endpoints)

    # ── Generate reports ──────────────────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)
    cfg_dict = {"target_url": config.target_url}

    if not args.no_color:
        print_terminal_summary(findings, cfg_dict)
    else:
        print(f"\n[+] Scan complete. {len(findings)} findings.")

    # Default to HTML if no format specified
    if args.html or not (args.json or args.md):
        generate_html_report(findings, cfg_dict, f"{args.output}/report.html")
    if args.json:
        generate_json_report(findings, cfg_dict, f"{args.output}/report.json")
    if args.md:
        generate_markdown_report(findings, cfg_dict, f"{args.output}/report.md")

    return 1 if any(f.severity.value == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
