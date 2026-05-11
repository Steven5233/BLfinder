#!/usr/bin/env python3
"""
BLFinder v3.1 Phase 4 — CLI Entry Point
All Phase 3 flags retained. New Phase 4 flags:
  --idor-range N         Enumerate N IDs per endpoint (enables mass IDOR)
  --idor-harvest         Use IDs extracted from responses for cross-testing
  --idor-cross-endpoint  Test harvested IDs across all endpoints (BOLA)
  --websocket            Enable WebSocket business logic scanning
  --ws-url URL           Specific WebSocket URL to test directly
  --ws-race-count N      Concurrent WS messages for race test (default: 15)
  --graphql-deep         Enable full GraphQL attack suite
  --version-scan         Enable API version downgrade scanning
  --classify             Print attack plan before scanning and exit
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="BLFinder v3.1 Phase 4 — Business Logic Flaw Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES:
  # Full Phase 4 scan — all new modules
  python blfinder.py -t https://api.target.com -T token -T2 token2 \\
    -e endpoints.json \\
    --idor-range 200 --idor-harvest --idor-cross-endpoint \\
    --graphql-deep --version-scan --websocket \\
    --html --md -o ~/results -v

  # Print attack plan before scanning
  python blfinder.py -t https://api.target.com -T token -e endpoints.json --classify

  # Mass IDOR only
  python blfinder.py -t https://api.target.com -T user1 -T2 user2 \\
    -e endpoints.json --idor-range 500 --html -o ~/results

  # GraphQL deep scan
  python blfinder.py -t https://api.target.com -T token --graphql-deep \\
    --html -o ~/results

  # WebSocket scan
  python blfinder.py -t https://app.target.com -T token --websocket \\
    --html -o ~/results

  # Full professional bug bounty scan (all phases)
  python blfinder.py \\
    -t https://api.target.com \\
    -T user1_token -T2 user2_token \\
    -e endpoints.json \\
    --recon --js-secrets \\
    --flow ecommerce_checkout --auto-flows \\
    --blind-idor --strict-validation \\
    --idor-range 200 --idor-harvest \\
    --graphql-deep --version-scan --websocket \\
    --html --json --md -o ~/results -v
""",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    p.add_argument("-t",  "--target",      required=True,            help="Target base URL")
    p.add_argument("-T",  "--token",       default="",               help="Auth token for User 1")
    p.add_argument("-T2", "--token2",      default="",               help="Auth token for User 2 (IDOR confirmation)")
    p.add_argument("-T3", "--token3",      default="",               help="Auth token for User 3")
    p.add_argument("-e",  "--endpoints",   default="",               help="Endpoints JSON file")
    p.add_argument("-H",  "--header",      action="append", default=[], metavar="Key:Value")
    p.add_argument("-c",  "--cookie",      action="append", default=[], metavar="name=value")
    p.add_argument("--proxy",              default="",               help="HTTP proxy e.g. http://127.0.0.1:8080")
    p.add_argument("-r",  "--rate",        type=float, default=0.3,  help="Base request delay (default: 0.3)")
    p.add_argument("--timeout",            type=int,   default=20,   help="Request timeout seconds (default: 20)")
    p.add_argument("--no-discover",        action="store_true",      help="Disable smart endpoint discovery")
    p.add_argument("--no-ssl-verify",      action="store_true",      help="Disable SSL verification")
    p.add_argument("--fuzz-depth",         type=int,   default=2,    help="Nested JSON mutation depth (default: 2)")
    p.add_argument("--min-confidence",     type=int,   default=40,   help="Min confidence %% to report (default: 40)")
    p.add_argument("--confirm-attempts",   type=int,   default=2,    help="Re-verification attempts (default: 2)")

    # ── Phase 3: Recon + Validation ───────────────────────────────────────────
    p.add_argument("--recon",              action="store_true",
                   help="Enable subdomain mapping + JS secret extraction")
    p.add_argument("--recon-only",         action="store_true",
                   help="Recon only — print targets, do not scan")
    p.add_argument("--js-secrets",         action="store_true",
                   help="Extract secrets from JavaScript files")
    p.add_argument("--subdomain-size",     type=int,   default=50,
                   help="Subdomain wordlist size (default: 50)")
    p.add_argument("--strict-validation",  action="store_true",
                   help="Skip soft-404 and HTML endpoints before testing")

    # ── Phase 1: Flows ────────────────────────────────────────────────────────
    p.add_argument(
        "--flow",
        action="append", default=[],
        metavar="TEMPLATE_NAME",
        help=(
            "Run a named built-in flow template (repeatable). "
            "Options: ecommerce_checkout, ecommerce_refund, "
            "subscription_upgrade, funds_transfer, withdrawal, "
            "password_reset, user_registration, redeem_reward, "
            "referral_bonus, kyc_verification, api_key_creation"
        ),
    )
    p.add_argument("--flow-file",          default="",               help="Custom flow definitions JSON file")
    p.add_argument("--auto-flows",         action="store_true",      help="Auto-detect and run relevant flow templates")
    p.add_argument("--product-id",         type=int,   default=1,    help="Product ID for e-commerce flows")
    p.add_argument("--product-price",      type=float, default=99.99, help="Product price for e-commerce flows")

    # ── Phase 1: OAuth2 + Token Refresh ───────────────────────────────────────
    p.add_argument("--oauth-url",          default="",               help="OAuth2 token endpoint URL")
    p.add_argument("--oauth-id",           default="",               help="OAuth2 client_id")
    p.add_argument("--oauth-secret",       default="",               help="OAuth2 client_secret")
    p.add_argument("--oauth-grant",        default="client_credentials",
                   choices=["client_credentials", "password", "refresh_token"])
    p.add_argument("--oauth-user",         default="",               help="Username for OAuth2 password grant")
    p.add_argument("--oauth-pass",         default="",               help="Password for OAuth2 password grant")
    p.add_argument("--oauth-scope",        default="",               help="OAuth2 scope")
    p.add_argument("--refresh-url",        default="",               help="Token refresh endpoint URL")
    p.add_argument("--refresh-token",      default="",               help="Refresh token value")
    p.add_argument("--login-url",          default="",               help="Re-login URL for fallback refresh")
    p.add_argument("--login-body",         default="",               help="Re-login body as JSON string")

    # ── Phase 1: Blind IDOR ───────────────────────────────────────────────────
    p.add_argument("--blind-idor",         action="store_true",      help="Enable blind IDOR oracle scanning")
    p.add_argument("--samples",            type=int,   default=4,    help="Oracle sample count (default: 4)")

    # ── Phase 4: Mass IDOR ────────────────────────────────────────────────────
    p.add_argument("--idor-range",         type=int,   default=0,
                   help="Enumerate N IDs per endpoint (0=disabled, default: 0)")
    p.add_argument("--idor-harvest",       action="store_true",
                   help="Harvest IDs from all responses and test cross-endpoint")
    p.add_argument("--idor-cross-endpoint", action="store_true",
                   help="Test harvested IDs across all endpoints (BOLA detection)")
    p.add_argument("--idor-batch-size",    type=int,   default=20,
                   help="Concurrent batch size for IDOR enumeration (default: 20)")

    # ── Phase 4: WebSocket ────────────────────────────────────────────────────
    p.add_argument("--websocket",          action="store_true",
                   help="Enable WebSocket business logic scanning")
    p.add_argument("--ws-url",             default="",
                   help="Specific WebSocket URL to test (in addition to discovery)")
    p.add_argument("--ws-race-count",      type=int,   default=15,
                   help="Concurrent WS messages for race condition test (default: 15)")

    # ── Phase 4: GraphQL Deep ─────────────────────────────────────────────────
    p.add_argument("--graphql-deep",       action="store_true",
                   help="Enable full GraphQL attack suite (alias IDOR, batch bypass, mutations)")

    # ── Phase 4: API Version Abuse ────────────────────────────────────────────
    p.add_argument("--version-scan",       action="store_true",
                   help="Enable API version downgrade scanning")

    # ── Phase 4: Business Classifier ─────────────────────────────────────────
    p.add_argument("--classify",           action="store_true",
                   help="Print attack plan with endpoint classification before scanning")

    # ── Output ────────────────────────────────────────────────────────────────
    p.add_argument("-o",  "--output",      default=".",              help="Output directory for reports")
    p.add_argument("--html",               action="store_true",      help="Generate HTML evidence report")
    p.add_argument("--json",               action="store_true",      help="Generate JSON report")
    p.add_argument("--md",                 action="store_true",      help="Generate Markdown / HackerOne report")
    p.add_argument("-v",  "--verbose",     action="store_true",      help="Verbose request logging")
    p.add_argument("--no-color",           action="store_true",      help="Disable ANSI colors")

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
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Flow file error: {e}")
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
                pass
        return RefreshConfig(
            refresh_url=args.refresh_url,
            refresh_token_value=args.refresh_token,
            login_url=args.login_url,
            login_body=login_body,
        )
    except ImportError:
        return None


def build_flow_configs(args) -> list:
    configs = []
    for name in args.flow:
        configs.append({"__template__": name})
    for flow_def in load_flow_file(args.flow_file):
        configs.append(flow_def)
    return configs


def resolve_flow_templates(flow_configs: list, args) -> list:
    try:
        from core.flows.flow_templates import FlowTemplates
    except ImportError:
        return flow_configs
    resolved = []
    for fc in flow_configs:
        if isinstance(fc, dict) and "__template__" in fc:
            name = fc["__template__"]
            fn   = getattr(FlowTemplates, name, None)
            if fn is None:
                print(f"[!] Unknown flow template: {name}")
                continue
            try:
                steps = (
                    fn(product_id=args.product_id, price=args.product_price)
                    if name == "ecommerce_checkout"
                    else fn()
                )
                resolved.append(steps)
                print(f"[*] Flow template loaded: {name}")
            except Exception as e:
                print(f"[!] Flow template error ({name}): {e}")
        else:
            resolved.append(fc)
    return resolved


# ── classify-only mode ────────────────────────────────────────────────────────

def run_classify(endpoints: list[dict]):
    """Print attack plan without scanning."""
    try:
        from core.intelligence.business_classifier import BusinessClassifier
    except ImportError:
        print("[!] Business classifier not available")
        return

    classifier = BusinessClassifier()
    plan       = classifier.build_plan(endpoints)
    plan.print_report(verbose=True)


# ── Recon-only mode ───────────────────────────────────────────────────────────

async def run_recon_only(args):
    from urllib.parse import urlparse
    target_domain = urlparse(args.target).netloc or args.target
    print(f"[*] BLFinder v3.1 Phase 4 — Recon only: {target_domain}\n")

    try:
        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        session   = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=15),
        )
    except ImportError:
        print("[!] aiohttp required: pip install aiohttp --break-system-packages")
        return

    try:
        try:
            from core.recon.subdomain_mapper import SubdomainMapper
            mapper = SubdomainMapper(verbose=args.verbose)
            result = await mapper.map(
                target_domain, max_wordlist=args.subdomain_size, session=session
            )
            print(f"\n[*] Subdomains for {target_domain}:")
            for sub in result.subdomains:
                if sub.is_live:
                    print(f"  [{sub.priority:<8}] {sub.hostname:<40} score={sub.score}")
            os.makedirs(args.output, exist_ok=True)
            with open(f"{args.output}/targets.json", "w") as fh:
                json.dump(
                    [{"hostname": s.hostname, "priority": s.priority,
                      "score": s.score} for s in result.subdomains if s.is_live],
                    fh, indent=2,
                )
            print(f"[+] Targets → {args.output}/targets.json")
        except ImportError:
            print("[!] Subdomain mapper not available")

        if args.js_secrets:
            try:
                from core.recon.js_secret_extractor import JSSecretExtractor
                extractor = JSSecretExtractor(verbose=args.verbose)
                js_result = await extractor.extract(args.target, session=session)
                print(f"\n[*] JS Secrets: {len(js_result.confirmed_secrets)} found")
                for s in js_result.confirmed_secrets:
                    print(f"  [{s.severity}] {s.pattern_name}: {s.redacted}")
            except ImportError:
                print("[!] JS extractor not available")
    finally:
        await session.close()


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    args = parse_args()

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

    # ── Phase 1 config ────────────────────────────────────────────────────────
    raw_flow_configs   = build_flow_configs(args)
    resolved_flows     = resolve_flow_templates(raw_flow_configs, args)
    config.run_flows   = bool(resolved_flows) or args.auto_flows
    config.flow_configs = resolved_flows
    config.auto_detect_flows = args.auto_flows
    config.product_id  = args.product_id
    config.product_price = args.product_price
    config.oauth_config   = build_oauth_config(args)
    config.refresh_config = build_refresh_config(args)
    config.oracle_samples = args.samples

    # ── Phase 4 config ────────────────────────────────────────────────────────
    config.idor_range          = args.idor_range
    config.idor_harvest        = args.idor_harvest
    config.idor_cross_endpoint = args.idor_cross_endpoint
    config.idor_batch_size     = args.idor_batch_size
    config.run_websocket       = args.websocket
    config.ws_url              = args.ws_url
    config.ws_race_count       = args.ws_race_count
    config.run_graphql_deep    = args.graphql_deep
    config.run_version_scan    = args.version_scan
    config.print_attack_plan   = args.classify

    # ── Load endpoints ────────────────────────────────────────────────────────
    endpoints = load_endpoints(args.endpoints)
    if not endpoints:
        endpoints = [{"url": "/", "method": "GET", "body": {}, "params": {}}]
        if not args.recon:
            print("[*] No endpoints file — using smart discovery only")

    # ── Classify-only mode ────────────────────────────────────────────────────
    if args.classify and endpoints:
        run_classify(endpoints)
        if not args.target:
            return 0
        print("[*] Proceeding with scan...\n")

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

    skipped = getattr(scanner, "_skipped_endpoints", [])
    if skipped:
        print(f"\n[*] Skipped {len(skipped)} endpoint(s) that failed validation")

    return 1 if any(
        f.severity.value == "CRITICAL" for f in findings
    ) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
