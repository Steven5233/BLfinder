#!/usr/bin/env python3
"""
BLFinder v3.1 Phase 3 — CLI Entry Point

New Phase 3 flags:
  --recon             Enable subdomain mapping + JS secret extraction
  --recon-only        Recon only, print targets, don't scan
  --js-secrets        Extract secrets from JS files (requires --recon or standalone)
  --subdomain-size N  Wordlist size for subdomain brute force (default: 50)
  --strict-validation Enable strict endpoint validation (recommended for real targets)
  --flow TEMPLATE     Run a named built-in flow template (repeatable)
  --flow-file FILE    Load flow definitions from a JSON file
  --auto-flows        Auto-detect application type and run relevant templates
  --oauth-url URL     OAuth2 token endpoint
  --oauth-id ID       OAuth2 client_id
  --oauth-secret SEC  OAuth2 client_secret
  --oauth-grant TYPE  client_credentials | password | refresh_token
  --oauth-user USER   Username for password grant
  --oauth-pass PASS   Password for password grant
  --refresh-url URL   Token refresh endpoint
  --refresh-token TOK Refresh token value
  --login-url URL     Re-login URL (fallback refresh)
  --login-body JSON   Re-login body as JSON string
  --blind-idor        Enable blind IDOR oracle scanning
  --samples N         Oracle sample count (default: 4)
  --product-id N      Product ID for e-commerce flow templates
  --product-price F   Product price for e-commerce flow templates
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="BLFinder v3.1 Phase 3 — Business Logic Flaw Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic scan with smart discovery
  python blfinder.py -t https://api.target.com -T "token"

  # Two accounts — enables confirmed IDOR
  python blfinder.py -t https://api.target.com -T user1 -T2 user2 -e endpoints.json

  # Full Phase 3 scan with recon
  python blfinder.py -t https://api.target.com -T "token" --recon --js-secrets \\
    --html --json --md -o ~/results -v

  # Recon only — discover subdomains without scanning
  python blfinder.py -t https://target.com --recon-only

  # E-commerce flow attack
  python blfinder.py -t https://shop.target.com -T "token" --flow ecommerce_checkout

  # OAuth2 auto-authenticate then scan
  python blfinder.py -t https://api.target.com \\
    --oauth-url https://auth.target.com/token \\
    --oauth-id client_id --oauth-secret secret

  # Full professional bug bounty scan
  python blfinder.py \\
    -t https://api.target.com \\
    -T user1_token -T2 user2_token \\
    -e endpoints.json \\
    --recon --js-secrets \\
    --flow ecommerce_checkout --auto-flows \\
    --blind-idor --strict-validation \\
    --html --json --md -o ~/results -v
""",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    p.add_argument("-t",  "--target",      required=True,            help="Target base URL")
    p.add_argument("-T",  "--token",       default="",               help="Auth token for User 1")
    p.add_argument("-T2", "--token2",      default="",               help="Auth token for User 2 (IDOR confirmation)")
    p.add_argument("-T3", "--token3",      default="",               help="Auth token for User 3")
    p.add_argument("-e",  "--endpoints",   default="",               help="Endpoints JSON file")
    p.add_argument("-H",  "--header",      action="append", default=[], metavar="Key:Value",
                   help="Extra headers (repeatable)")
    p.add_argument("-c",  "--cookie",      action="append", default=[], metavar="name=value",
                   help="Cookies (repeatable)")
    p.add_argument("--proxy",              default="",               help="HTTP proxy e.g. http://127.0.0.1:8080")
    p.add_argument("-r",  "--rate",        type=float, default=0.3,  help="Base request delay in seconds (default: 0.3)")
    p.add_argument("--timeout",            type=int,   default=20,   help="Request timeout in seconds (default: 20)")
    p.add_argument("--no-discover",        action="store_true",      help="Disable smart endpoint discovery")
    p.add_argument("--no-ssl-verify",      action="store_true",      help="Disable SSL verification")
    p.add_argument("--fuzz-depth",         type=int,   default=2,    help="Nested JSON mutation depth (default: 2)")
    p.add_argument("--min-confidence",     type=int,   default=40,   help="Min confidence %% to report (default: 40)")
    p.add_argument("--confirm-attempts",   type=int,   default=2,    help="Re-verification attempts (default: 2)")

    # ── Phase 3: Recon ────────────────────────────────────────────────────────
    p.add_argument("--recon",              action="store_true",
                   help="Enable subdomain mapping + JS secret extraction before scan")
    p.add_argument("--recon-only",         action="store_true",
                   help="Recon only — print discovered targets, do not scan")
    p.add_argument("--js-secrets",         action="store_true",
                   help="Extract API keys and tokens from JavaScript files")
    p.add_argument("--subdomain-size",     type=int,   default=50,
                   help="Subdomain wordlist size for brute force (default: 50)")
    p.add_argument("--strict-validation",  action="store_true",
                   help="Strict endpoint validation — skip soft-404 and HTML responses")

    # ── Phase 1: Flows ────────────────────────────────────────────────────────
    p.add_argument(
        "--flow",
        action="append", default=[],
        metavar="TEMPLATE_NAME",
        help=(
            "Run a named built-in flow template (repeatable). "
            "Options: ecommerce_checkout, ecommerce_refund, subscription_upgrade, "
            "funds_transfer, withdrawal, password_reset, user_registration, "
            "redeem_reward, referral_bonus, kyc_verification, api_key_creation"
        ),
    )
    p.add_argument("--flow-file",          default="",
                   help="Path to a JSON file containing custom flow definitions")
    p.add_argument("--auto-flows",         action="store_true",
                   help="Auto-detect app type and run relevant flow templates")
    p.add_argument("--product-id",         type=int,   default=1,
                   help="Product ID for e-commerce flow templates (default: 1)")
    p.add_argument("--product-price",      type=float, default=99.99,
                   help="Product price for e-commerce flow templates (default: 99.99)")

    # ── Phase 1: OAuth2 ───────────────────────────────────────────────────────
    p.add_argument("--oauth-url",          default="", help="OAuth2 token endpoint URL")
    p.add_argument("--oauth-id",           default="", help="OAuth2 client_id")
    p.add_argument("--oauth-secret",       default="", help="OAuth2 client_secret")
    p.add_argument(
        "--oauth-grant",
        default="client_credentials",
        choices=["client_credentials", "password", "refresh_token"],
        help="OAuth2 grant type (default: client_credentials)",
    )
    p.add_argument("--oauth-user",         default="", help="Username for OAuth2 password grant")
    p.add_argument("--oauth-pass",         default="", help="Password for OAuth2 password grant")
    p.add_argument("--oauth-scope",        default="", help="OAuth2 scope")

    # ── Phase 1: Token refresh ────────────────────────────────────────────────
    p.add_argument("--refresh-url",        default="", help="Token refresh endpoint URL")
    p.add_argument("--refresh-token",      default="", help="Refresh token value")
    p.add_argument("--login-url",          default="", help="Re-login URL for fallback refresh")
    p.add_argument("--login-body",         default="",
                   help='Re-login body as JSON string e.g. \'{"email":"x","password":"y"}\'')

    # ── Phase 1: Blind IDOR ───────────────────────────────────────────────────
    p.add_argument("--blind-idor",         action="store_true",
                   help="Enable blind IDOR oracle scanning (slower, more thorough)")
    p.add_argument("--samples",            type=int,   default=4,
                   help="Oracle sample count per test (default: 4)")

    # ── Output ────────────────────────────────────────────────────────────────
    p.add_argument("-o",  "--output",      default=".",  help="Output directory for reports")
    p.add_argument("--html",               action="store_true", help="Generate HTML evidence report")
    p.add_argument("--json",               action="store_true", help="Generate JSON report")
    p.add_argument("--md",                 action="store_true", help="Generate Markdown / HackerOne report")
    p.add_argument("-v",  "--verbose",     action="store_true", help="Verbose request logging")
    p.add_argument("--no-color",           action="store_true", help="Disable ANSI colors (for log files)")

    return p.parse_args()


# ── Loaders ───────────────────────────────────────────────────────────────────

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
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "steps" in data:
            return [data]
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


# ── Config builders ───────────────────────────────────────────────────────────

def build_oauth_config(args):
    if not args.oauth_url:
        return None
    try:
        from core.auth.oauth_handler import OAuthConfig
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
        print("[!] OAuth handler not available")
        return None


def build_refresh_config(args):
    if not args.refresh_url and not args.login_url:
        return None
    try:
        from core.auth.session_manager import RefreshConfig
        login_body = {}
        if args.login_body:
            try:
                login_body = json.loads(args.login_body)
            except json.JSONDecodeError:
                print(f"[!] Invalid --login-body JSON")
        return RefreshConfig(
            refresh_url=args.refresh_url,
            refresh_token_value=args.refresh_token,
            login_url=args.login_url,
            login_body=login_body,
        )
    except ImportError:
        return None


def build_flow_configs(args) -> list:
    """Resolve flow template names and custom flow files into config list."""
    configs = []
    for template_name in args.flow:
        configs.append({"__template__": template_name})
    for flow_def in load_flow_file(args.flow_file):
        configs.append(flow_def)
    return configs


def resolve_flow_templates(flow_configs: list, args) -> list:
    """Convert template name references into actual FlowStep lists."""
    try:
        from core.flows.flow_templates import FlowTemplates
    except ImportError:
        print("[!] Flow templates not available")
        return flow_configs

    resolved = []
    for fc in flow_configs:
        if isinstance(fc, dict) and "__template__" in fc:
            name = fc["__template__"]
            fn   = getattr(FlowTemplates, name, None)
            if fn is None:
                print(f"[!] Unknown flow template: {name}")
                print(f"[!] Available: {', '.join(FlowTemplates.list_all())}")
                continue
            try:
                if name == "ecommerce_checkout":
                    steps = fn(
                        product_id=args.product_id,
                        price=args.product_price,
                    )
                else:
                    steps = fn()
                resolved.append(steps)
                print(f"[*] Flow template loaded: {name}")
            except Exception as e:
                print(f"[!] Flow template error ({name}): {e}")
        else:
            resolved.append(fc)
    return resolved


# ── Recon-only runner ─────────────────────────────────────────────────────────

async def run_recon_only(args):
    """Run subdomain mapping and JS extraction without scanning."""
    from urllib.parse import urlparse

    target_domain = urlparse(args.target).netloc or args.target

    print(f"[*] BLFinder v3.1 Phase 3 — Recon only: {target_domain}\n")

    try:
        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        session   = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=15),
        )
    except ImportError:
        print("[!] aiohttp not available. Run: pip install aiohttp --break-system-packages")
        return

    try:
        # Subdomain mapping
        try:
            from core.recon.subdomain_mapper import SubdomainMapper
            mapper = SubdomainMapper(verbose=args.verbose)
            result = await mapper.map(
                target_domain,
                max_wordlist=args.subdomain_size,
                session=session,
            )
            print(f"\n[*] Subdomain results for {target_domain}:")
            print(f"    Total found : {result.total_found}")
            print(f"    Live        : {result.live_count}")
            print(f"    API surface : {result.api_count}")
            print()
            for sub in result.subdomains:
                if sub.is_live:
                    marker = f"[{sub.priority}]"
                    notes  = ", ".join(sub.notes[:2]) if sub.notes else ""
                    print(f"  {marker:<12} {sub.hostname:<40} score={sub.score:<3} {notes}")

            # Save targets
            os.makedirs(args.output, exist_ok=True)
            targets_path = f"{args.output}/targets.json"
            with open(targets_path, "w") as fh:
                json.dump(
                    [
                        {
                            "hostname": s.hostname,
                            "priority": s.priority,
                            "score":    s.score,
                            "api_paths": s.api_paths,
                        }
                        for s in result.subdomains if s.is_live
                    ],
                    fh,
                    indent=2,
                )
            print(f"\n[+] Targets saved → {targets_path}")

        except ImportError:
            print("[!] Subdomain mapper not available")

        # JS secret extraction
        if args.js_secrets:
            try:
                from core.recon.js_secret_extractor import JSSecretExtractor
                extractor = JSSecretExtractor(verbose=args.verbose)
                js_result = await extractor.extract(args.target, session=session)
                print(f"\n[*] JS Secrets for {args.target}:")
                print(f"    Files scanned : {js_result.js_files_scanned}")
                print(f"    Secrets found : {len(js_result.confirmed_secrets)}")
                print()
                for secret in js_result.confirmed_secrets:
                    sev = secret.severity
                    print(
                        f"  [{sev}] {secret.pattern_name}: "
                        f"{secret.redacted} "
                        f"(line {secret.line_number} in {secret.source_url[-40:]})"
                    )

                if js_result.endpoints:
                    print(f"\n[*] Internal endpoints found in JS:")
                    for ep in js_result.endpoints[:20]:
                        print(f"  {ep}")

            except ImportError:
                print("[!] JS secret extractor not available")

    finally:
        await session.close()


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    args = parse_args()

    # Recon-only mode — no scanning
    if args.recon_only:
        await run_recon_only(args)
        return 0

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

    # ── Phase 3 config ────────────────────────────────────────────────────────
    config.run_recon              = args.recon
    config.run_subdomain_map      = args.recon
    config.run_js_extract         = args.js_secrets or args.recon
    config.subdomain_wordlist_size = args.subdomain_size
    config.strict_validation      = args.strict_validation

    # ── Phase 1: Flows ────────────────────────────────────────────────────────
    raw_flow_configs = build_flow_configs(args)
    resolved_flows   = resolve_flow_templates(raw_flow_configs, args)
    config.run_flows       = bool(resolved_flows) or args.auto_flows
    config.flow_configs    = resolved_flows
    config.auto_detect_flows = args.auto_flows
    config.product_id      = args.product_id
    config.product_price   = args.product_price

    # ── Phase 1: OAuth ────────────────────────────────────────────────────────
    config.oauth_config   = build_oauth_config(args)
    config.refresh_config = build_refresh_config(args)

    # ── Phase 1: Blind IDOR ───────────────────────────────────────────────────
    config.oracle_samples = args.samples

    # ── Load endpoints ────────────────────────────────────────────────────────
    endpoints = load_endpoints(args.endpoints)
    if not endpoints:
        endpoints = [{"url": "/", "method": "GET", "body": {}, "params": {}}]
        if not args.recon:
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
        try:
            from core.reporting.evidence_report import EvidenceReportGenerator
            EvidenceReportGenerator().generate(
                findings, f"{args.output}/report.html", cfg_dict
            )
        except ImportError:
            generate_html_report(findings, cfg_dict, f"{args.output}/report.html")

    if args.json:
        generate_json_report(findings, cfg_dict, f"{args.output}/report.json")

    if args.md:
        generate_markdown_report(findings, cfg_dict, f"{args.output}/report.md")

    # Print validation stats summary
    skipped = getattr(scanner, "_skipped_endpoints", [])
    if skipped:
        print(f"\n[*] Skipped {len(skipped)} endpoint(s) that failed validation:")
        for url in skipped[:10]:
            print(f"    {url}")
        if len(skipped) > 10:
            print(f"    ... and {len(skipped)-10} more")

    return 1 if any(f.severity.value == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
