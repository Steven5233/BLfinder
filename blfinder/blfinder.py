#!/usr/bin/env python3
"""
BLFinder v3.1 Phase 5+ — CLI Entry Point
Complete platform with all phases integrated + Deep Discovery Engine.

Phases:
  1 : Multi-step flows, blind IDOR, session management, OAuth2
  2 : Evidence capture, real HTTP proof, HackerOne report generation
  3 : Endpoint validation, response classification, subdomain recon,
      JS secret extraction, soft-404 prevention
  4 : Mass IDOR enumeration, GraphQL deep scan, WebSocket scanner,
      API version abuse, business context classifier
  5 : Live dashboard, profile system, DB deduplication,
      findings queue for TUI consumption
  5+: Deep Discovery Engine — JS AST, OpenAPI, smart wordlist,
      version permutation, headless crawl, soft-404 filter,
      priority scoring, schema enrichment

New Phase 5 flags:
  --import-burp FILE       Import Burp Suite XML/JSON traffic export
  --import-har FILE        Import browser HAR file
  --import-mitmproxy FILE  Import mitmproxy flows file
  --import-filter REGEX    Filter imported URLs (e.g. /api/)
  --import-save FILE       Save generated endpoints.json to this path
  --db PATH                SQLite database path (default: ~/.blfinder.db)
  --no-repeat              Skip endpoints already in database (dedup)
  --program HANDLE         Tag findings with HackerOne program handle
  --export-h1 HANDLE       Export new findings to HackerOne as drafts
  --h1-token TOKEN         HackerOne API token (username:api_token)
  --show-history           Print finding history from DB and exit
  --search QUERY           Search past findings and exit
  --profile NAME           Load settings from profiles/NAME.json
  --dashboard              Enable live TUI dashboard

Deep Discovery flags:
  --deep-discovery         Enable full multi-layer discovery pipeline
  --wordlist-depth N       Wordlist depth 1=tiny … 5=exhaustive (default: 2)
  --no-wordlist            Skip wordlist layer entirely
  --openapi-path PATH      Extra path(s) to probe for OpenAPI/Swagger spec
  --discovery-save FILE    Save discovered endpoints JSON to this path
  --no-robots              Skip robots.txt / sitemap.xml parsing
  --no-js-ast              Skip JS AST pass (keep regex-only JS scan)
  --no-openapi             Skip OpenAPI/Swagger/Postman spec probing
  --no-version-permute     Skip API version-shadow discovery
  --business-tags TAGS     Comma-separated business context tags for wordlist

  --discovery-depth N      (cli_args integration) 1-5 depth (default: 2)
  --use-headless           Enable Playwright headless browser crawl
  --headless-interact      Click buttons/forms during headless crawl
  --proto-path FILE        Local .proto file for gRPC extraction (repeatable)
  --discovery-tags TAGS    Comma-separated business tags (alias for --business-tags)
  --save-discovery FILE    Save all discovered endpoints before scanning
  --no-deep-discovery      Disable the deep discovery engine entirely
"""

from __future__ import annotations

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


# ── Discovery CLI-args integration (core/discovery/cli_args.py) ──────────────
# These functions mirror the interface defined in cli_args.py so that the
# module can be imported OR the logic lives here as a safe fallback.

try:
    from core.discovery.cli_args import (
        add_discovery_args,
        apply_discovery_args,
        apply_profile_discovery,
    )
    _HAS_CLI_ARGS = True
except ImportError:
    _HAS_CLI_ARGS = False

    # ── Fallback implementations ─────────────────────────────────────────────
    def add_discovery_args(parser: argparse.ArgumentParser) -> None:
        """Add deep-discovery flags. Fallback when cli_args.py is absent."""
        grp = parser.add_argument_group(
            "Deep Discovery Engine",
            description=(
                "Multi-layer endpoint discovery: JS analysis, OpenAPI parsing, "
                "smart wordlist, version permutation, optional headless crawl."
            ),
        )
        grp.add_argument(
            "--discovery-depth",
            type=int, default=2, metavar="N",
            dest="discovery_depth",
            help=(
                "Wordlist discovery depth 1-5 (default: 2).\n"
                "  1 = ~200 high-signal paths (fast, Termux-friendly)\n"
                "  2 = ~500 paths (default)\n"
                "  3 = ~1500 paths + full sub-resource tree\n"
                "  4 = ~3000 paths + full version matrix\n"
                "  5 = exhaustive (~10000 paths, slow on mobile)"
            ),
        )
        grp.add_argument(
            "--use-headless",
            action="store_true", dest="use_headless",
            help=(
                "Enable Playwright headless browser crawl.\n"
                "Intercepts all XHR/fetch calls the SPA makes during navigation.\n"
                "Requires: pip install playwright --break-system-packages\n"
                "          playwright install chromium"
            ),
        )
        grp.add_argument(
            "--headless-interact",
            action="store_true", dest="headless_interact",
            help=(
                "Click buttons and submit forms during headless crawl.\n"
                "Use with --use-headless."
            ),
        )
        grp.add_argument(
            "--openapi-path",
            action="append", default=[], dest="openapi_paths",
            metavar="PATH",
            help=(
                "Explicit OpenAPI/Swagger spec path to parse (repeatable).\n"
                "Example: --openapi-path /api/v1/openapi.json"
            ),
        )
        grp.add_argument(
            "--proto-path",
            action="append", default=[], dest="proto_paths",
            metavar="FILE",
            help=(
                "Local .proto file for gRPC endpoint extraction (repeatable).\n"
                "Example: --proto-path ./protos/user_service.proto"
            ),
        )
        grp.add_argument(
            "--discovery-tags",
            default="", metavar="TAGS", dest="discovery_tags",
            help=(
                "Comma-separated business tags to seed the discovery wordlist.\n"
                "Available: payment, order, admin, user, auth, fintech, product,\n"
                "           transfer, report\n"
                "Example: --discovery-tags payment,order,admin"
            ),
        )
        grp.add_argument(
            "--no-wordlist",
            action="store_true", dest="no_wordlist",
            help="Disable wordlist-based path discovery.",
        )
        grp.add_argument(
            "--save-discovery",
            default="", metavar="FILE", dest="save_discovery",
            help=(
                "Save all discovered endpoints to a JSON file before scanning.\n"
                "Example: --save-discovery ~/discovered_endpoints.json"
            ),
        )
        grp.add_argument(
            "--no-deep-discovery",
            action="store_true", dest="no_deep_discovery",
            help=(
                "Disable the deep discovery engine entirely.\n"
                "Falls back to the original smart_discover() regex crawl."
            ),
        )

    def apply_discovery_args(args: argparse.Namespace, config) -> None:
        """Copy discovery-related argparse values onto the ScanConfig object."""
        config.discovery_depth  = getattr(args, "discovery_depth",  2)
        config.use_headless     = getattr(args, "use_headless",     False)
        config.headless_interact = getattr(args, "headless_interact", False)
        config.openapi_paths    = getattr(args, "openapi_paths",    [])
        config.proto_paths      = getattr(args, "proto_paths",      [])
        config.no_wordlist      = getattr(args, "no_wordlist",      False)
        config.save_discovery   = getattr(args, "save_discovery",   "")
        config.no_deep_discovery = getattr(args, "no_deep_discovery", False)

        raw_tags = getattr(args, "discovery_tags", "")
        if isinstance(raw_tags, str):
            config.discovery_tags = [
                t.strip() for t in raw_tags.split(",") if t.strip()
            ]
        elif isinstance(raw_tags, list):
            config.discovery_tags = raw_tags
        else:
            config.discovery_tags = []

        # If smart_discovery explicitly disabled, also disable deep discovery
        if not getattr(config, "smart_discovery", True):
            config.no_deep_discovery = True

    def apply_profile_discovery(profile: dict, args: argparse.Namespace, config) -> None:
        """Apply profile-level discovery settings; CLI args take priority."""
        if not profile:
            return
        settings = profile.get("settings", {})

        if settings.get("discovery_depth") and getattr(args, "discovery_depth", 2) == 2:
            config.discovery_depth = settings["discovery_depth"]

        if settings.get("business_tags") and not getattr(config, "discovery_tags", []):
            config.discovery_tags = settings["business_tags"]

        if settings.get("no_wordlist") and not getattr(config, "no_wordlist", False):
            config.no_wordlist = True

        if settings.get("use_headless") and not getattr(args, "no_deep_discovery", False):
            config.use_headless = True


# ─────────────────────────────────────────────────────────────────────────────
# Profile loader
# ─────────────────────────────────────────────────────────────────────────────

def load_profile(name: str) -> dict:
    """Load a scan profile from the profiles/ directory."""
    search_dirs = [
        Path(__file__).parent / "profiles",
        Path.home() / ".blfinder" / "profiles",
        Path.cwd() / "profiles",
    ]
    for dir_path in search_dirs:
        profile_path = dir_path / f"{name}.json"
        if profile_path.exists():
            try:
                with open(profile_path) as f:
                    data = json.load(f)
                print(f"[*] Profile loaded: {name} ({profile_path})")
                return data
            except json.JSONDecodeError as e:
                print(f"[!] Profile JSON error ({profile_path}): {e}")
            except OSError as e:
                print(f"[!] Profile read error ({profile_path}): {e}")

    print(f"[!] Profile not found: {name}")
    print(
        "[!] Available profiles: "
        "ecommerce, fintech, saas, stealth, fast, graphql, api_only, thorough"
    )
    return {}


def merge_profile_with_args(profile: dict, args: argparse.Namespace) -> dict:
    """
    Merge profile settings with CLI args.
    CLI args always take priority over profile settings.
    Returns a dict of merged settings ready to apply to ScanConfig.
    """
    settings = dict(profile.get("settings", {}))

    # Remove keys where the user supplied an explicit CLI override
    cli_defaults = {
        "rate_limit":       0.3,
        "min_confidence":   40,
        "confirm_attempts": 2,
        "fuzz_depth":       2,
    }
    cli_attr_map = {
        "rate_limit":       "rate",
        "min_confidence":   "min_confidence",
        "confirm_attempts": "confirm_attempts",
        "fuzz_depth":       "fuzz_depth",
    }
    for key, default in cli_defaults.items():
        attr = cli_attr_map[key]
        if getattr(args, attr, default) != default:
            settings.pop(key, None)  # CLI override wins → drop profile value

    # Boolean flags: if the user passed them on the CLI, enable in settings
    flag_map = [
        ("strict_validation", "strict_validation"),
        ("run_blind_idor",    "blind_idor"),
        ("run_graphql_deep",  "graphql_deep"),
        ("run_websocket",     "websocket"),
        ("run_version_scan",  "version_scan"),
        ("run_recon",         "recon"),
        ("run_js_extract",    "js_secrets"),
        ("deep_discovery",    "deep_discovery"),
    ]
    for settings_key, arg_attr in flag_map:
        if getattr(args, arg_attr, False):
            settings[settings_key] = True

    return settings


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="BLFinder v3.1 Phase 5+ — Business Logic Flaw Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
EXAMPLES:
  # Basic scan with token
  python blfinder.py -t https://api.target.com -T mytoken

  # Import from Burp, use ecommerce profile, save to DB
  python blfinder.py -t https://shop.target.com -T token \\
    --import-burp burp_export.xml --profile ecommerce \\
    --db ~/.blfinder.db --program target_h1 \\
    --html --md -o ~/results

  # Full Phase 5+ professional scan with deep discovery
  python blfinder.py \\
    -t https://api.target.com \\
    -T user1_token -T2 user2_token \\
    --import-burp traffic.xml \\
    --profile thorough \\
    --deep-discovery --wordlist-depth 3 --discovery-depth 3 \\
    --db ~/.blfinder.db --program target_h1 \\
    --dashboard \\
    --html --json --md -o ~/results

  # Deep discovery only — dump endpoints, skip attack modules
  python blfinder.py -t https://api.target.com -T token \\
    --deep-discovery --wordlist-depth 2 \\
    --save-discovery discovered.json --no-scan

  # Headless crawl with interaction
  python blfinder.py -t https://app.target.com -T token \\
    --use-headless --headless-interact --deep-discovery

  # Show finding history
  python blfinder.py --show-history --db ~/.blfinder.db

  # Search past findings
  python blfinder.py --search "IDOR payment" --db ~/.blfinder.db

  # Export findings to HackerOne
  python blfinder.py --export-h1 target_program \\
    --h1-token username:api_token --db ~/.blfinder.db

  # Recon only
  python blfinder.py -t https://target.com --recon-only -o ~/recon
""",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    core = p.add_argument_group("Core")
    core.add_argument("-t", "--target",    default="",   help="Target base URL")
    core.add_argument("-T", "--token",     default="",   help="Auth token for User 1")
    core.add_argument("-T2", "--token2",   default="",   help="Auth token for User 2")
    core.add_argument("-T3", "--token3",   default="",   help="Auth token for User 3")
    core.add_argument(
        "-e", "--endpoints", default="",
        help="Endpoints JSON file (list of {url, method, body, params})",
    )
    core.add_argument(
        "-H", "--header",
        action="append", default=[], metavar="Key:Value",
        help="Extra request header (repeatable)",
    )
    core.add_argument(
        "-c", "--cookie",
        action="append", default=[], metavar="name=value",
        help="Extra cookie (repeatable)",
    )
    core.add_argument("--proxy",             default="",            help="HTTP proxy URL")
    core.add_argument(
        "-r", "--rate", type=float, default=0.3, metavar="SECS",
        help="Base delay between requests in seconds (default: 0.3)",
    )
    core.add_argument(
        "--timeout", type=int, default=20, metavar="SECS",
        help="Per-request timeout in seconds (default: 20)",
    )
    core.add_argument("--no-discover",      action="store_true",   help="Disable smart discovery")
    core.add_argument("--no-ssl-verify",    action="store_true",   help="Disable TLS certificate verification")
    core.add_argument("--fuzz-depth",       type=int, default=2,   help="Nested-object mutation depth (default: 2)")
    core.add_argument("--min-confidence",   type=int, default=40,  help="Minimum confidence %% to report (default: 40)")
    core.add_argument("--confirm-attempts", type=int, default=2,   help="Re-verification attempts (default: 2)")
    core.add_argument(
        "--no-scan", action="store_true",
        help="Run discovery only, skip all attack modules",
    )

    # ── Profile ───────────────────────────────────────────────────────────────
    prof = p.add_argument_group("Profile")
    prof.add_argument(
        "--profile", default="",
        help=(
            "Load settings from profiles/NAME.json\n"
            "Built-in: ecommerce | fintech | saas | stealth | fast | "
            "graphql | api_only | thorough"
        ),
    )

    # ── Import ────────────────────────────────────────────────────────────────
    imp = p.add_argument_group("Traffic Import")
    imp.add_argument("--import-burp",       default="", metavar="FILE",  help="Import Burp Suite XML/JSON export")
    imp.add_argument("--import-har",        default="", metavar="FILE",  help="Import browser HAR file")
    imp.add_argument("--import-mitmproxy",  default="", metavar="FILE",  help="Import mitmproxy flows file")
    imp.add_argument(
        "--import-filter", default="", metavar="REGEX",
        help="Regex to filter imported URLs (e.g. /api/)",
    )
    imp.add_argument(
        "--import-save", default="", metavar="FILE",
        help="Save generated endpoints JSON to this path",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    db_grp = p.add_argument_group("Database / HackerOne")
    db_grp.add_argument("--db",         default="~/.blfinder.db",  help="SQLite database path")
    db_grp.add_argument(
        "--no-repeat", action="store_true",
        help="Skip endpoints already confirmed vulnerable in DB",
    )
    db_grp.add_argument("--program",    default="", help="Tag findings with this HackerOne program handle")
    db_grp.add_argument(
        "--export-h1", default="",
        help="Export new findings to HackerOne as drafts (requires --h1-token)",
    )
    db_grp.add_argument("--h1-token",   default="", help="HackerOne API token (username:api_token)")
    db_grp.add_argument("--show-history", action="store_true", help="Print finding history from DB and exit")
    db_grp.add_argument("--search",     default="", metavar="QUERY", help="Search past findings and exit")

    # ── Dashboard ─────────────────────────────────────────────────────────────
    dash = p.add_argument_group("Dashboard")
    dash.add_argument("--dashboard",    action="store_true", help="Enable live TUI dashboard during scan")
    dash.add_argument(
        "--force-ansi", action="store_true",
        help="Force ANSI output even when curses is available",
    )

    # ── Deep Discovery (layer flags) ──────────────────────────────────────────
    disc = p.add_argument_group(
        "Deep Discovery (layer pipeline)",
        description=(
            "Flags controlling the outer discovery pipeline invoked from main(). "
            "These work alongside the engine-level flags added by add_discovery_args()."
        ),
    )
    disc.add_argument(
        "--deep-discovery", action="store_true",
        help="Enable full multi-layer discovery pipeline",
    )
    disc.add_argument(
        "--wordlist-depth", type=int, default=2, metavar="N",
        help="Wordlist depth 1=tiny … 5=exhaustive (default: 2)",
    )
    disc.add_argument("--no-robots",        action="store_true",  help="Skip robots.txt / sitemap.xml parsing")
    disc.add_argument("--no-js-ast",        action="store_true",  help="Skip JS AST endpoint extraction")
    disc.add_argument("--no-openapi",       action="store_true",  help="Skip OpenAPI/Swagger/Postman spec probing")
    disc.add_argument("--no-version-permute", action="store_true", help="Skip API version-shadow discovery")
    disc.add_argument(
        "--business-tags", default="", metavar="TAGS",
        help="Comma-separated business context tags (e.g. payment,order,user)",
    )
    disc.add_argument(
        "--discovery-save", default="", metavar="FILE",
        help="Save deep-discovered endpoints JSON to this path (outer pipeline alias)",
    )

    # ── Phase 5+: Deep Discovery Engine (inner, add_discovery_args) ───────────
    # NOTE: add_discovery_args() adds --discovery-depth, --use-headless,
    #       --headless-interact, --openapi-path, --proto-path,
    #       --discovery-tags, --no-wordlist, --save-discovery,
    #       --no-deep-discovery  into a named group.
    add_discovery_args(p)

    # ── Phase 3: Recon ────────────────────────────────────────────────────────
    recon = p.add_argument_group("Recon")
    recon.add_argument("--recon",       action="store_true", help="Enable subdomain + JS recon phase")
    recon.add_argument("--recon-only",  action="store_true", help="Run recon and exit (no attack modules)")
    recon.add_argument("--js-secrets",  action="store_true", help="Enable JS secret extraction")
    recon.add_argument(
        "--subdomain-size", type=int, default=50,
        help="Max subdomain wordlist size (default: 50)",
    )
    recon.add_argument(
        "--strict-validation", action="store_true",
        help="Strict endpoint pre-validation (reject soft-404 / WAF-blocked)",
    )

    # ── Phase 1: Flows ────────────────────────────────────────────────────────
    flows = p.add_argument_group("Flows / Auth")
    flows.add_argument(
        "--flow", action="append", default=[], metavar="TEMPLATE",
        help="Built-in flow template to run (repeatable)",
    )
    flows.add_argument("--flow-file",       default="", metavar="FILE", help="JSON file containing flow steps")
    flows.add_argument("--auto-flows",      action="store_true", help="Auto-detect and run e-commerce flows")
    flows.add_argument("--product-id",      type=int,   default=1,     help="Product ID for checkout flows")
    flows.add_argument("--product-price",   type=float, default=99.99, help="Product price for checkout flows")
    flows.add_argument("--oauth-url",       default="",  help="OAuth2 token endpoint URL")
    flows.add_argument("--oauth-id",        default="",  help="OAuth2 client_id")
    flows.add_argument("--oauth-secret",    default="",  help="OAuth2 client_secret")
    flows.add_argument(
        "--oauth-grant", default="client_credentials",
        choices=["client_credentials", "password", "refresh_token"],
        help="OAuth2 grant type",
    )
    flows.add_argument("--oauth-user",      default="",  help="OAuth2 resource-owner username")
    flows.add_argument("--oauth-pass",      default="",  help="OAuth2 resource-owner password")
    flows.add_argument("--oauth-scope",     default="",  help="OAuth2 requested scope")
    flows.add_argument("--refresh-url",     default="",  help="Token refresh endpoint URL")
    flows.add_argument("--refresh-token",   default="",  help="Initial refresh token value")
    flows.add_argument("--login-url",       default="",  help="Login endpoint for auto token refresh")
    flows.add_argument("--login-body",      default="",  help='Login body JSON (e.g. {"user":"u","pass":"p"})')
    flows.add_argument("--blind-idor",      action="store_true", help="Enable blind IDOR oracle scanning")
    flows.add_argument(
        "--samples", type=int, default=4, metavar="N",
        help="Baseline samples for blind oracle (default: 4)",
    )

    # ── Phase 4: Attack Surface ───────────────────────────────────────────────
    atk = p.add_argument_group("Phase 4 — Attack Surface")
    atk.add_argument("--idor-range",        type=int, default=0,    help="IDOR enumeration range (0 = disabled)")
    atk.add_argument("--idor-harvest",      action="store_true",    help="Harvest IDs from responses for IDOR")
    atk.add_argument("--idor-cross-endpoint", action="store_true",  help="Cross-endpoint IDOR testing")
    atk.add_argument("--idor-batch-size",   type=int, default=20,   help="IDOR batch concurrency size (default: 20)")
    atk.add_argument("--websocket",         action="store_true",    help="Enable WebSocket scanning")
    atk.add_argument("--ws-url",            default="",             help="Override WebSocket URL")
    atk.add_argument("--ws-race-count",     type=int, default=15,   help="WebSocket race condition attempt count")
    atk.add_argument("--graphql-deep",      action="store_true",    help="Enable deep GraphQL introspection scan")
    atk.add_argument("--version-scan",      action="store_true",    help="Enable API version-abuse scanning")
    atk.add_argument("--classify",          action="store_true",    help="Print business logic attack plan and exit")

    # ── Output ────────────────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",  default=".",  help="Output directory (default: current dir)")
    out.add_argument("--html",          action="store_true", help="Generate HTML report")
    out.add_argument("--json",          action="store_true", help="Generate JSON report")
    out.add_argument("--md",            action="store_true", help="Generate Markdown report")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("--no-color",      action="store_true", help="Disable ANSI colour output")

    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def load_endpoints(path: str) -> list[dict]:
    """Load endpoints list from a JSON file. Returns [] on any error."""
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        # Support {"endpoints": [...]} wrapper
        if isinstance(data, dict) and "endpoints" in data:
            return data["endpoints"]
        print(f"[!] Endpoints file has unexpected structure: {path}")
    except FileNotFoundError:
        print(f"[!] Endpoints file not found: {path}")
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in endpoints file ({path}): {e}")
    return []


def load_flow_file(path: str) -> list[dict]:
    """Load flow definitions from a JSON file."""
    if not path:
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "steps" in data:
            return [data]
        print(f"[!] Flow file has unexpected structure: {path}")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Flow file error ({path}): {e}")
    return []


def parse_headers(header_list: list[str]) -> dict:
    """Parse ['Key: Value', ...] into a dict."""
    headers: dict = {}
    for item in header_list:
        if ":" in item:
            k, _, v = item.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def parse_cookies(cookie_list: list[str]) -> dict:
    """Parse ['name=value', ...] into a dict."""
    cookies: dict = {}
    for item in cookie_list:
        if "=" in item:
            k, _, v = item.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def build_oauth_config(args: argparse.Namespace):
    """Build OAuthConfig from CLI args, or None if not configured."""
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
        print("[!] OAuthConfig not available — install core.auth.oauth_handler")
        return None


def build_refresh_config(args: argparse.Namespace):
    """Build RefreshConfig from CLI args, or None if not configured."""
    if not args.refresh_url and not args.login_url:
        return None
    try:
        from core.auth.session_manager import RefreshConfig
        login_body: dict = {}
        if args.login_body:
            try:
                login_body = json.loads(args.login_body)
            except json.JSONDecodeError as e:
                print(f"[!] --login-body is not valid JSON: {e}")
        return RefreshConfig(
            refresh_url=args.refresh_url,
            refresh_token_value=args.refresh_token,
            login_url=args.login_url,
            login_body=login_body,
        )
    except ImportError:
        print("[!] RefreshConfig not available — install core.auth.session_manager")
        return None


def build_flow_configs(args: argparse.Namespace, profile: dict) -> list:
    """Collect raw flow configs from CLI flags, flow file, and profile."""
    configs: list = []
    for name in args.flow:
        configs.append({"__template__": name})
    for flow_def in load_flow_file(args.flow_file):
        configs.append(flow_def)
    # Profile flows only when CLI provided none
    if not args.flow and not args.flow_file:
        for name in profile.get("flows", []):
            configs.append({"__template__": name})
    return configs


def resolve_flow_templates(flow_configs: list, args: argparse.Namespace) -> list:
    """Expand __template__ markers into concrete FlowStep lists."""
    try:
        from core.flows.flow_templates import FlowTemplates
    except ImportError:
        print("[!] FlowTemplates not available — flow templates will be skipped")
        return [fc for fc in flow_configs if "__template__" not in fc]

    resolved: list = []
    for fc in flow_configs:
        if isinstance(fc, dict) and "__template__" in fc:
            name = fc["__template__"]
            fn = getattr(FlowTemplates, name, None)
            if fn is None:
                print(f"[!] Unknown flow template: {name}")
                continue
            try:
                if name == "ecommerce_checkout":
                    steps = fn(product_id=args.product_id, price=args.product_price)
                else:
                    steps = fn()
                resolved.append(steps)
                print(f"[*] Flow template loaded: {name}")
            except Exception as e:
                print(f"[!] Flow template error ({name}): {e}")
        else:
            resolved.append(fc)
    return resolved


def build_discovery_config_from_args(args: argparse.Namespace, profile: dict):
    """
    Build a DiscoveryConfig for the *outer* pipeline (run_deep_discovery).
    Merges CLI flags with profile discovery settings.
    """
    try:
        from core.discovery.models import DiscoveryConfig
    except ImportError:
        return None

    prof_disc = profile.get("discovery", {})

    # Business tags: CLI wins; fall back to profile
    business_tags: list[str] = []
    raw_bt = args.business_tags or ""
    if raw_bt:
        business_tags = [t.strip() for t in raw_bt.split(",") if t.strip()]
    elif prof_disc.get("business_tags"):
        business_tags = prof_disc["business_tags"]

    # Merge openapi_paths from both pipeline flags and engine flags
    openapi_paths: list[str] = list(args.openapi_paths or [])
    for p_path in prof_disc.get("openapi_paths", []):
        if p_path not in openapi_paths:
            openapi_paths.append(p_path)

    # save_discovery: prefer engine flag, fall back to outer flag
    save_path = (
        getattr(args, "save_discovery", "")
        or getattr(args, "discovery_save", "")
        or ""
    )

    return DiscoveryConfig(
        auth_token              = args.token,
        second_token            = args.token2,
        timeout_s               = args.timeout,
        verbose                 = args.verbose,
        use_headless            = getattr(args, "use_headless", False),
        headless_interact       = getattr(args, "headless_interact", False),
        headless_timeout_s      = prof_disc.get("headless_timeout_s", 30),
        wordlist_depth          = getattr(args, "discovery_depth", args.wordlist_depth),
        no_wordlist             = getattr(args, "no_wordlist", False),
        follow_js_imports       = not args.no_js_ast,
        max_js_files            = prof_disc.get("max_js_files", 30),
        graphql_deep            = args.graphql_deep,
        openapi_paths           = openapi_paths,
        proto_paths             = getattr(args, "proto_paths", []),
        include_versions        = prof_disc.get(
            "include_versions",
            ["v1", "v2", "v3", "internal", "legacy", "beta"],
        ),
        business_tags           = business_tags,
        subdomain_wordlist_size = args.subdomain_size,
        save_discovery_path     = save_path,
        max_depth               = prof_disc.get("max_depth", 4),
        use_shodan              = False,
    )


def import_traffic(args: argparse.Namespace) -> list[dict]:
    """Import endpoints from Burp / HAR / mitmproxy files."""
    if not any([args.import_burp, args.import_har, args.import_mitmproxy]):
        return []

    try:
        from core.integrations.burp_importer import TrafficImporter
    except ImportError:
        print(
            "[!] TrafficImporter not available "
            "— check core/integrations/burp_importer.py"
        )
        return []

    importer = TrafficImporter(verbose=args.verbose)
    imported: list[dict] = []
    url_filter = args.import_filter if args.import_filter else None

    sources = [
        (args.import_burp,      "Burp"),
        (args.import_har,       "HAR"),
        (args.import_mitmproxy, "mitmproxy"),
    ]
    for import_path, label in sources:
        if not import_path:
            continue
        try:
            result = importer.import_file(import_path, url_filter=url_filter)
            print(f"[+] {label} import: {result.summary()}")
            imported.extend(result.endpoints)
            if args.import_save:
                importer.save(result.endpoints, args.import_save)
                print(f"[+] Endpoints saved → {args.import_save}")
        except FileNotFoundError:
            print(f"[!] {label} file not found: {import_path}")
        except Exception as e:
            print(f"[!] {label} import error: {e}")

    return imported


# ─────────────────────────────────────────────────────────────────────────────
# DB-only commands
# ─────────────────────────────────────────────────────────────────────────────

async def cmd_show_history(args: argparse.Namespace) -> None:
    """Print finding history from the database."""
    try:
        from core.storage.scan_database import ScanDatabase
    except ImportError:
        print("[!] ScanDatabase not available — check core/storage/scan_database.py")
        return

    db_path = os.path.expanduser(args.db)
    try:
        async with ScanDatabase(db_path) as db:
            stats = await db.get_stats(program=args.program or None)
            db.print_stats(stats)
            findings = await db.get_findings(
                program=args.program or None,
                limit=50,
            )
            db.print_findings(findings)
    except Exception as e:
        print(f"[!] Database error: {e}")


async def cmd_search(args: argparse.Namespace, query: str) -> None:
    """Search past findings."""
    try:
        from core.storage.scan_database import ScanDatabase
    except ImportError:
        print("[!] ScanDatabase not available — check core/storage/scan_database.py")
        return

    db_path = os.path.expanduser(args.db)
    try:
        async with ScanDatabase(db_path) as db:
            findings = await db.search(query)
            print(f"\n[*] Search results for '{query}': {len(findings)} findings\n")
            db.print_findings(findings)
    except Exception as e:
        print(f"[!] Database error: {e}")


async def cmd_export_h1(args: argparse.Namespace) -> None:
    """Export unreported findings to HackerOne as draft reports."""
    if not args.h1_token:
        print("[!] --h1-token required for HackerOne export")
        return
    if not args.export_h1:
        print("[!] --export-h1 PROGRAM_HANDLE required")
        return

    try:
        from core.storage.scan_database import ScanDatabase
    except ImportError:
        print("[!] ScanDatabase not available — check core/storage/scan_database.py")
        return

    db_path = os.path.expanduser(args.db)
    try:
        async with ScanDatabase(db_path) as db:
            findings = await db.get_findings(
                program=args.program or args.export_h1,
                status="new",
            )
            print(
                f"[*] Exporting {len(findings)} new findings "
                f"to HackerOne/{args.export_h1}..."
            )
            success = 0
            for f in findings:
                try:
                    result = await db.export_to_hackerone(
                        finding_id=f.id,
                        h1_token=args.h1_token,
                        program_handle=args.export_h1,
                    )
                    print(f"  [+] Exported: {result['report_url']}")
                    success += 1
                except Exception as e:
                    title_short = getattr(f, "title", "unknown")[:40]
                    print(f"  [!] Export failed ({title_short}): {e}")
            print(f"\n[+] Exported {success}/{len(findings)} findings to HackerOne")
    except Exception as e:
        print(f"[!] Database error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Recon-only mode
# ─────────────────────────────────────────────────────────────────────────────

async def run_recon_only(args: argparse.Namespace) -> None:
    """Run subdomain recon (and optionally JS secret extraction), then exit."""
    from urllib.parse import urlparse

    if not args.target:
        print("[!] --target is required for --recon-only")
        return

    target_domain = urlparse(args.target).netloc or args.target
    print(f"[*] BLFinder v3.1 Phase 5+ — Recon: {target_domain}\n")

    try:
        import aiohttp
    except ImportError:
        print("[!] aiohttp required: pip install aiohttp --break-system-packages")
        return

    connector = aiohttp.TCPConnector(ssl=not args.no_ssl_verify, limit=20)
    timeout   = aiohttp.ClientTimeout(total=args.timeout)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Subdomain recon
        try:
            from core.recon.subdomain_mapper import SubdomainMapper
            mapper = SubdomainMapper(verbose=args.verbose)
            result = await mapper.map(
                target_domain,
                max_wordlist=args.subdomain_size,
                session=session,
            )
            print(
                f"[*] Subdomains: {result.live_count} live, "
                f"{result.api_count} API surface"
            )
            for sub in result.subdomains:
                if sub.is_live:
                    print(
                        f"  [{sub.priority:<8}] {sub.hostname:<40} "
                        f"score={sub.score}"
                    )
            os.makedirs(args.output, exist_ok=True)
            targets_path = os.path.join(args.output, "targets.json")
            with open(targets_path, "w") as fh:
                json.dump(
                    [
                        {
                            "hostname":  sub.hostname,
                            "priority":  sub.priority,
                            "score":     sub.score,
                            "api_paths": sub.api_paths,
                        }
                        for sub in result.subdomains
                        if sub.is_live
                    ],
                    fh,
                    indent=2,
                )
            print(f"[+] Targets saved → {targets_path}")
        except ImportError:
            print("[!] SubdomainMapper not available")

        # JS secret extraction
        if args.js_secrets:
            try:
                from core.recon.js_secret_extractor import JSSecretExtractor
                extractor = JSSecretExtractor(verbose=args.verbose)
                js_result = await extractor.extract(args.target, session=session)
                print(
                    f"\n[*] JS Secrets: "
                    f"{len(js_result.confirmed_secrets)} found"
                )
                for secret in js_result.confirmed_secrets:
                    print(
                        f"  [{secret.severity}] "
                        f"{secret.pattern_name}: {secret.redacted}"
                    )
            except ImportError:
                print("[!] JSSecretExtractor not available")


# ─────────────────────────────────────────────────────────────────────────────
# Deep Discovery pipeline (outer)
# ─────────────────────────────────────────────────────────────────────────────

async def run_deep_discovery(
    args: argparse.Namespace,
    discovery_cfg,
    session,
) -> list[dict]:
    """
    Run the full multi-layer discovery pipeline and return a deduplicated
    list of endpoint dicts suitable for BLFScanner.

    Layer 1  : robots.txt / sitemap.xml          (RobotsParser)
    Layer 2a : JS AST endpoint extraction        (JSASTParser)
    Layer 2b : OpenAPI / Swagger / Postman       (OpenAPIParser)
    Layer 4a : Context-seeded wordlist probing   (SmartWordlist)
    Layer 4b : API version-shadow discovery      (VersionPermuter)
    Layer 5  : URL normalisation + dedup         (normaliser)
    """
    if discovery_cfg is None:
        print("[!] Discovery config is None — skipping deep discovery pipeline")
        return []

    print("[*] Deep Discovery — running multi-layer pipeline...")

    discovered_paths: list[str] = []   # feed forward into wordlist layer
    all_endpoints:    list      = []   # DiscoveredEndpoint objects

    # ── Layer 1: robots.txt + sitemap ────────────────────────────────────────
    if not args.no_robots:
        try:
            from core.discovery.layer1_surface.robots_parser import RobotsParser
            robots = RobotsParser(verbose=args.verbose)
            r1 = await robots.run(
                target_url=args.target,
                session=session,
                config=discovery_cfg,
                auth_token=args.token,
            )
            all_endpoints.extend(r1.endpoints)
            discovered_paths.extend(
                ep.url.split("?")[0] for ep in r1.endpoints
            )
            print(f"  [L1:robots]   {r1.summary()}")
            if args.verbose and getattr(r1, "errors", None):
                for err in r1.errors[:3]:
                    print(f"    [!] {err}")
        except ImportError:
            if args.verbose:
                print("  [L1:robots]   not available — skipped")
        except Exception as e:
            print(f"  [L1:robots]   error: {e}")

    # ── Layer 2a: JS AST + regex endpoint extraction ──────────────────────────
    if not args.no_js_ast:
        try:
            from core.discovery.layer2_static.js_ast_parser import JSASTParser
            js_parser = JSASTParser(verbose=args.verbose)
            r2a = await js_parser.run(
                target_url=args.target,
                session=session,
                config=discovery_cfg,
                auth_token=args.token,
            )
            all_endpoints.extend(r2a.endpoints)
            discovered_paths.extend(
                ep.url.split("?")[0] for ep in r2a.endpoints
            )
            print(f"  [L2:js_ast]   {r2a.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L2:js_ast]   not available — skipped")
        except Exception as e:
            print(f"  [L2:js_ast]   error: {e}")

    # ── Layer 2b: OpenAPI / Swagger / Postman spec probing ───────────────────
    if not args.no_openapi:
        try:
            from core.discovery.layer2_static.openapi_parser import OpenAPIParser
            oa_parser = OpenAPIParser(verbose=args.verbose)
            r2b = await oa_parser.run(
                target_url=args.target,
                session=session,
                config=discovery_cfg,
                auth_token=args.token,
            )
            all_endpoints.extend(r2b.endpoints)
            discovered_paths.extend(
                ep.url.split("?")[0] for ep in r2b.endpoints
            )
            print(f"  [L2:openapi]  {r2b.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L2:openapi]  not available — skipped")
        except Exception as e:
            print(f"  [L2:openapi]  error: {e}")

    # ── Layer 4a: Smart wordlist probing ──────────────────────────────────────
    if not getattr(args, "no_wordlist", False):
        try:
            from core.discovery.layer4_wordlist.smart_wordlist import SmartWordlist
            wl = SmartWordlist(verbose=args.verbose)
            r4a = await wl.run(
                target_url=args.target,
                session=session,
                config=discovery_cfg,
                auth_token=args.token,
                discovered_paths=list(set(discovered_paths)),
                baseline_bodies=[],
            )
            all_endpoints.extend(r4a.endpoints)
            print(f"  [L4:wordlist] {r4a.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L4:wordlist] not available — skipped")
        except Exception as e:
            print(f"  [L4:wordlist] error: {e}")

    # ── Layer 4b: API version permutation ─────────────────────────────────────
    if not args.no_version_permute:
        try:
            from core.discovery.layer4_wordlist.version_permuter import VersionPermuter
            known_urls = [ep.url for ep in all_endpoints]
            vp = VersionPermuter(verbose=args.verbose)
            r4b = await vp.run(
                target_url=args.target,
                session=session,
                config=discovery_cfg,
                auth_token=args.token,
                known_endpoints=known_urls,
            )
            all_endpoints.extend(r4b.endpoints)
            print(f"  [L4:version]  {r4b.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L4:version]  not available — skipped")
        except Exception as e:
            print(f"  [L4:version]  error: {e}")

    # ── Layer 5+: Hidden endpoint hunter ────────────────────────────────────
    # Runs BEFORE dedup so discovered hidden paths are included in dedup pass.
    # Finds: internal/admin/debug paths, framework-specific endpoints,
    # mobile API paths, historical HackerOne corpus paths, path mutations,
    # activation-param triggered endpoints, and HTTP method variants.
    try:
        from core.discovery.hidden_endpoint_hunter import run_hidden_hunter

        known_urls = [
            getattr(ep, "url", ep) if not isinstance(ep, str) else ep
            for ep in all_endpoints
        ]
        hidden_dicts = await run_hidden_hunter(
            target_url  = args.target,
            session     = session,
            auth_token  = args.token,
            known_paths = known_urls,
            verbose     = args.verbose,
            timeout_s   = min(args.timeout, 10),
            max_workers = 8,
        )

        # Convert dicts to simple namespace objects so dedup layer handles them
        class _EP:
            def __init__(self, d):
                self.url    = d["url"]
                self.method = d.get("method", "GET")
                self.body   = d.get("body",   {})
                self.params = d.get("params", {})
                self._meta  = d.get("_meta",  {})

        hidden_eps = [_EP(d) for d in hidden_dicts]
        all_endpoints.extend(hidden_eps)
        if hidden_eps:
            print(f"  [L5+:hunter]  {len(hidden_eps)} hidden endpoints added")
    except ImportError:
        if args.verbose:
            print("  [L5+:hunter]  not available — place hidden_endpoint_hunter.py "
                  "in core/discovery/")
    except Exception as e:
        print(f"  [L5+:hunter]  error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

    # ── Layer 5: Normalise + dedup ────────────────────────────────────────────
    try:
        from core.discovery.layer5_dedup.normaliser import dedup_key
        seen_keys: set[str] = set()
        unique_eps = []
        for ep in all_endpoints:
            k = dedup_key(ep.url, ep.method)
            if k not in seen_keys:
                seen_keys.add(k)
                unique_eps.append(ep)
        dropped = len(all_endpoints) - len(unique_eps)
        all_endpoints = unique_eps
        if dropped and args.verbose:
            print(f"  [L5:dedup]    removed {dropped} duplicate endpoints")
    except ImportError:
        if args.verbose:
            print("  [L5:dedup]    not available — skipped")
    except Exception as e:
        print(f"  [L5:dedup]    error: {e}")

    # Convert DiscoveredEndpoint → plain dicts for BLFScanner
    result_dicts: list[dict] = []
    for ep in all_endpoints:
        result_dicts.append({
            "url":    ep.url,
            "method": getattr(ep, "method", "GET"),
            "body":   getattr(ep, "body",   None) or {},
            "params": getattr(ep, "params", None) or {},
        })

    print(
        f"\n[*] Deep discovery complete: "
        f"{len(result_dicts)} unique endpoints found\n"
    )

    # Optionally save discovered endpoints
    save_path = (
        getattr(discovery_cfg, "save_discovery_path", "")
        or getattr(args, "save_discovery", "")
        or getattr(args, "discovery_save", "")
        or ""
    )
    if save_path and result_dicts:
        try:
            parent = os.path.dirname(os.path.abspath(save_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(save_path, "w") as fh:
                json.dump(result_dicts, fh, indent=2)
            print(f"[+] Discovery results saved → {save_path}")
        except OSError as e:
            print(f"[!] Could not save discovery results: {e}")

    return result_dicts


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> int:  # noqa: C901  (intentionally long — orchestration only)
    args = parse_args()

    # ── DB-only / utility commands ────────────────────────────────────────────
    if args.show_history:
        await cmd_show_history(args)
        return 0

    if args.search:
        await cmd_search(args, args.search)
        return 0

    # Note: --export-h1 is also a post-scan action; handled below after scan
    # when used together with --target.  Pure export (no target) exits here.
    if args.export_h1 and not args.target:
        await cmd_export_h1(args)
        return 0

    if args.recon_only:
        await run_recon_only(args)
        return 0

    # ── Require target for scanning ───────────────────────────────────────────
    if not args.target:
        print("[!] --target is required for scanning")
        print(
            "[!] For DB operations use: "
            "--show-history | --search QUERY | --export-h1 HANDLE"
        )
        return 1

    # ── Load profile ──────────────────────────────────────────────────────────
    profile: dict = {}
    if args.profile:
        profile = load_profile(args.profile)
        if not profile:
            print("[!] Continuing without profile settings")

    merged_settings = merge_profile_with_args(profile, args) if profile else {}

    # ── Import traffic ────────────────────────────────────────────────────────
    imported_endpoints = import_traffic(args)

    # ── Build discovery configs ───────────────────────────────────────────────
    # Outer pipeline config (run_deep_discovery)
    outer_disc_cfg = build_discovery_config_from_args(args, profile)

    # ── Core imports ──────────────────────────────────────────────────────────
    try:
        from core.models  import ScanConfig
        from core.scanner import BLFScanner
        from core.reporter import (
            print_terminal_summary,
            generate_html_report,
            generate_json_report,
            generate_markdown_report,
        )
    except ImportError as e:
        print(f"[!] Critical import error: {e}")
        print("[!] Ensure the core/ package is on your PYTHONPATH")
        return 1

    # ── Build ScanConfig ──────────────────────────────────────────────────────
    config = ScanConfig(
        target_url            = args.target.rstrip("/"),
        auth_token            = args.token,
        second_user_token     = args.token2,
        third_user_token      = args.token3,
        headers               = parse_headers(args.header),
        cookies               = parse_cookies(args.cookie),
        proxy                 = args.proxy,
        rate_limit            = merged_settings.get("rate_limit", args.rate),
        timeout               = args.timeout,
        verify_ssl            = not args.no_ssl_verify,
        smart_discovery       = not args.no_discover,
        fuzz_depth            = merged_settings.get("fuzz_depth", args.fuzz_depth),
        output_dir            = args.output,
        verbose               = args.verbose,
        no_auth_check         = True,
        min_confidence        = merged_settings.get("min_confidence", args.min_confidence),
        confirmation_attempts = merged_settings.get("confirm_attempts", args.confirm_attempts),
    )

    # ── Apply discovery args (engine-level flags → ScanConfig) ────────────────
    apply_discovery_args(args, config)

    # ── Phase 3: Recon ────────────────────────────────────────────────────────
    config.run_recon              = args.recon or merged_settings.get("run_recon", False)
    config.run_subdomain_map      = config.run_recon
    config.run_js_extract         = (
        args.js_secrets
        or merged_settings.get("run_js_extract", False)
        or config.run_recon
    )
    config.subdomain_wordlist_size = args.subdomain_size
    config.strict_validation      = (
        args.strict_validation
        or merged_settings.get("strict_validation", False)
    )

    # ── Phase 1: Flows / Auth ─────────────────────────────────────────────────
    raw_flow_configs = build_flow_configs(args, profile)
    resolved_flows   = resolve_flow_templates(raw_flow_configs, args)
    auto_flows       = args.auto_flows or profile.get("auto_flows", False)
    config.run_flows         = bool(resolved_flows) or auto_flows
    config.flow_configs      = resolved_flows
    config.auto_detect_flows = auto_flows
    config.product_id        = args.product_id
    config.product_price     = args.product_price
    config.oauth_config      = build_oauth_config(args)
    config.refresh_config    = build_refresh_config(args)
    config.oracle_samples    = args.samples
    config.run_blind_idor    = args.blind_idor

    # ── Phase 4: Attack Surface ───────────────────────────────────────────────
    prof_settings = profile.get("settings", {})
    config.idor_range          = args.idor_range   or prof_settings.get("idor_range", 0)
    config.idor_harvest        = args.idor_harvest  or prof_settings.get("idor_harvest", False)
    config.idor_cross_endpoint = args.idor_cross_endpoint or prof_settings.get("idor_cross_endpoint", False)
    config.idor_batch_size     = args.idor_batch_size
    config.run_websocket       = args.websocket     or prof_settings.get("run_websocket", False)
    config.ws_url              = args.ws_url
    config.ws_race_count       = args.ws_race_count
    config.run_graphql_deep    = args.graphql_deep  or prof_settings.get("run_graphql_deep", False)
    config.run_version_scan    = args.version_scan  or prof_settings.get("run_version_scan", False)
    config.print_attack_plan   = args.classify

    # ── Phase 5: Database ─────────────────────────────────────────────────────
    config.db_path   = os.path.expanduser(args.db)
    config.program   = args.program
    config.no_repeat = args.no_repeat
    # Activate DB when any DB-related flag is explicitly set
    config.use_db = bool(
        args.db != "~/.blfinder.db"
        or args.program
        or args.no_repeat
        or args.export_h1
    )

    # ── Deep discovery flags on ScanConfig ───────────────────────────────────
    config.deep_discovery     = (
        args.deep_discovery
        or merged_settings.get("deep_discovery", False)
    )
    config.discovery_cfg      = outer_disc_cfg
    config.no_js_ast          = args.no_js_ast
    config.no_robots          = args.no_robots
    config.no_openapi         = args.no_openapi
    config.no_version_permute = args.no_version_permute

    # Apply profile-level discovery (fills gaps left by CLI defaults)
    apply_profile_discovery(profile, args, config)

    # ── Load endpoints ────────────────────────────────────────────────────────
    endpoints: list[dict] = load_endpoints(args.endpoints)
    endpoints.extend(imported_endpoints)

    if not endpoints:
        # Seed with root so discovery has somewhere to start
        endpoints = [{"url": "/", "method": "GET", "body": {}, "params": {}}]
        if not args.recon:
            print("[*] No endpoints supplied — relying on discovery")

    # ── Classify-only (preview attack plan and exit) ──────────────────────────
    if args.classify:
        try:
            from core.intelligence.business_classifier import BusinessClassifier
            classifier = BusinessClassifier()
            plan = classifier.build_plan(endpoints)
            plan.print_report(verbose=args.verbose)
        except ImportError:
            print("[!] BusinessClassifier not available")
        if not args.target:
            return 0
        # If a target was given, fall through to the full scan

    # ── Initialise database ───────────────────────────────────────────────────
    db      = None
    scan_id = None
    if config.use_db:
        try:
            from core.storage.scan_database import ScanDatabase
            db = ScanDatabase(config.db_path)
            await db.init()
            scan_id = await db.start_scan(
                target=args.target,
                program=args.program,
                config={"profile": args.profile, "endpoints": len(endpoints)},
            )
            if args.program:
                await db.register_program(args.program)
            print(f"[*] Database: {config.db_path} (scan #{scan_id})")
        except Exception as e:
            print(f"[!] Database init failed: {e} — continuing without DB")
            db = None

    # ── Outer deep discovery pipeline (if requested) ──────────────────────────
    if config.deep_discovery and outer_disc_cfg is not None:
        # Patch version_permuter BEFORE running discovery so that individual
        # probe failures (timeout, SSL error, connection refused) are caught
        # per-probe and never crash the whole pipeline.
        try:
            from core.discovery.version_permuter_patch import (
                apply_version_permuter_patch,
            )
            apply_version_permuter_patch()
            if args.verbose:
                print("[*] version_permuter_patch applied")
        except ImportError:
            pass  # patch file absent — permuter runs unpatched

        try:
            import aiohttp
            disc_connector = aiohttp.TCPConnector(
                ssl=not args.no_ssl_verify, limit=20
            )
            disc_timeout = aiohttp.ClientTimeout(total=args.timeout)
            async with aiohttp.ClientSession(
                connector=disc_connector, timeout=disc_timeout
            ) as disc_session:
                discovered = await run_deep_discovery(args, outer_disc_cfg, disc_session)

            # Merge, deduplicate by (url, method)
            existing_keys: set[tuple] = {
                (ep["url"], ep.get("method", "GET")) for ep in endpoints
            }
            added = 0
            for ep in discovered:
                key = (ep["url"], ep.get("method", "GET"))
                if key not in existing_keys:
                    endpoints.append(ep)
                    existing_keys.add(key)
                    added += 1
            if added:
                print(f"[*] Outer deep discovery added {added} new endpoints")
        except ImportError:
            print("[!] aiohttp required for deep discovery")
        except Exception as e:
            print(f"[!] Outer deep discovery error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    # ── No-scan mode: discovery only ──────────────────────────────────────────
    if args.no_scan:
        os.makedirs(args.output, exist_ok=True)
        out_path = os.path.join(args.output, "discovered_endpoints.json")
        try:
            with open(out_path, "w") as fh:
                json.dump(endpoints, fh, indent=2)
            print(f"[+] {len(endpoints)} endpoints saved → {out_path}")
        except OSError as e:
            print(f"[!] Could not save endpoints: {e}")
        if db:
            try:
                await db.finish_scan(scan_id, finding_count=0)
                await db.close()
            except Exception:
                pass
        return 0

    # ── Apply patches ─────────────────────────────────────────────────────────
    # Patch 1: scanner_patch — fixes coroutine leak + soft-404 over-skip
    #   (core/discovery/scanner_patch.py)
    if not getattr(config, "no_deep_discovery", False):
        try:
            from core.discovery.scanner_patch import apply_patch
            apply_patch()
            if args.verbose:
                print("[*] scanner_patch applied (coroutine fix + soft-404 threshold)")
        except ImportError:
            pass  # Engine absent — BLFScanner uses its built-in fallback

    # Patch 2: verifier_patch — fixes over-aggressive re-verification
    #   Lowers similarity threshold 0.75→0.45, adds majority voting,
    #   adds leniency for already-confirmed (cross-user) findings.
    #   (core/verifier_patch.py)
    try:
        from core.verifier_patch import apply_verifier_patch
        patched = apply_verifier_patch()
        if args.verbose and patched:
            print("[*] verifier_patch applied (relaxed re-verification thresholds)")
    except ImportError:
        pass  # Patch file absent — verifier runs with original thresholds

    # ── Run scanner ───────────────────────────────────────────────────────────
    findings = []
    scanner_error: Exception | None = None

    async with BLFScanner(config) as scanner:
        # Apply profile to scanner instance
        if profile:
            scanner.apply_profile(profile)

        # Setup TUI dashboard
        dashboard     = None
        dash_task     = None
        if args.dashboard:
            try:
                from core.tui.live_dashboard import create_dashboard
                dashboard, dash_state = create_dashboard(
                    target=args.target,
                    total_endpoints=len(endpoints),
                    verbose=args.verbose,
                    force_ansi=args.force_ansi,
                )
                scanner.set_dashboard_state(dash_state)
                dash_task = asyncio.create_task(dashboard.run())
                print("[*] Dashboard started (press q to quit)")
            except ImportError:
                print("[!] TUI dashboard not available")
            except Exception as e:
                print(f"[!] Dashboard init error: {e}")

        try:
            findings = await scanner.run_all_modules(endpoints)
        except Exception as e:
            scanner_error = e
            print(f"[!] Scanner error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
        finally:
            if dashboard:
                try:
                    await dashboard.stop()
                except Exception:
                    pass
            if dash_task and not dash_task.done():
                dash_task.cancel()
                try:
                    await dash_task
                except asyncio.CancelledError:
                    pass

    if scanner_error and not findings:
        if db:
            try:
                await db.finish_scan(scan_id, finding_count=0)
                await db.close()
            except Exception:
                pass
        return 1

    # ── Save findings to database ─────────────────────────────────────────────
    if db and findings:
        try:
            new_count, dupe_count = await db.save_findings(
                findings,
                scan_id=scan_id,
                program=args.program or "",
            )
            await db.finish_scan(scan_id, finding_count=new_count)
            print(f"[*] Database: {new_count} new, {dupe_count} duplicates")

            # Post-scan HackerOne export
            if args.export_h1 and args.h1_token and new_count > 0:
                await cmd_export_h1(args)
        except Exception as e:
            print(f"[!] Database save error: {e}")
        finally:
            try:
                await db.close()
            except Exception:
                pass
    elif db:
        try:
            await db.finish_scan(scan_id, finding_count=0)
            await db.close()
        except Exception:
            pass

    # ── Generate reports ──────────────────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)
    cfg_dict = {"target_url": config.target_url}

    if not args.no_color:
        try:
            print_terminal_summary(findings, cfg_dict)
        except Exception as e:
            print(f"\n[+] Scan complete. {len(findings)} findings. (summary error: {e})")
    else:
        print(f"\n[+] Scan complete. {len(findings)} findings.")

    # HTML report — try full evidence report first, fall back gracefully
    if args.html or not (args.json or args.md):
        html_path = os.path.join(args.output, "report.html")
        generated = False
        for reporter_path in [
            "core.reporting",
            "core.reporting.core.reporting.evidence_report",
        ]:
            try:
                mod = __import__(reporter_path, fromlist=["EvidenceReportGenerator"])
                mod.EvidenceReportGenerator().generate(findings, html_path, cfg_dict)
                generated = True
                break
            except (ImportError, AttributeError):
                continue
        if not generated:
            try:
                generate_html_report(findings, cfg_dict, html_path)
            except Exception as e:
                print(f"[!] HTML report error: {e}")

    if args.json:
        json_path = os.path.join(args.output, "report.json")
        try:
            generate_json_report(findings, cfg_dict, json_path)
        except Exception as e:
            print(f"[!] JSON report error: {e}")

    if args.md:
        md_path = os.path.join(args.output, "report.md")
        try:
            generate_markdown_report(findings, cfg_dict, md_path)
        except Exception as e:
            print(f"[!] Markdown report error: {e}")

    # Exit 1 when any CRITICAL finding confirmed — useful in CI pipelines
    return 1 if any(
        getattr(f.severity, "value", str(f.severity)) == "CRITICAL"
        for f in findings
    ) else 0


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
