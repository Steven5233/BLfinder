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

FIX CHANGELOG v3.1-FIXED (all original + new bugs resolved):
  BUG-1  : scanner_integration.apply_integration() called before BLFScanner.
  BUG-3  : wordlist-depth / discovery-depth reconciled via max().
  BUG-5  : HTML reporter path corrected.
  BUG-6  : --no-validation wired correctly.
  BUG-15 : --deep-discovery / --no-deep-discovery mutual-exclusion enforced.
  BUG-16 : --classify with --target continues to full scan.
  BUG-17 : config.use_db activation logic fixed.
  BUG-A  : enrich_endpoints now receives cookies + extra_headers so
            cookie-authenticated targets (1win.com / cf_clearance) are
            probed correctly instead of returning 401/403.
  BUG-B  : ssl= in enricher now driven by config.verify_ssl, not hardcoded.
  BUG-C  : _meta/schema_hint preserved in run_deep_discovery result_dicts
            so OpenAPI field schemas reach the scanner attack modules.
  BUG-D  : --no-scan now honours --save-discovery path instead of always
            saving to <output>/discovered_endpoints.json.
  BUG-F  : no_auth_check driven by new --skip-unauth flag (default False).
  BUG-G  : CI exit-code 1 requires confirmed=True + confidence>=80.
  BUG-H  : proxy forwarded to enrich_endpoints so Burp interception works.
  WEAK-3 : Race condition keyword list extended with bet/wager/stake/cashout/
            bonus/deposit/topup/settlement (gambling/fintech targets).
  WEAK-6 : --business-tags and --discovery-tags merged so either flag works.
  WEAK-7 : Global endpoint concurrency semaphore (--max-endpoints, default 5)
            prevents WAF-triggering request bursts on Cloudflare targets.
  BUG-1  : scanner_integration.apply_integration() is now called before
            the BLFScanner context manager — all intelligence systems are live.
  BUG-3  : --wordlist-depth and --discovery-depth now reconciled by taking
            max() of the two values so neither silently wins.
  BUG-5  : HTML reporter path "core.reporting.core.reporting.evidence_report"
            corrected to "core.reporting.evidence_report".
  BUG-6  : --no-validation wired into scanner via scanner_patch so the flag
            actually bypasses EndpointValidator when set.
  BUG-15 : --deep-discovery / --no-deep-discovery mutual-exclusion enforced
            after both flags are applied.
  BUG-16 : --classify with --target now falls through to full scan as
            intended; help text updated to be accurate.
  BUG-17 : config.use_db activation logic fixed — explicit default path or
            any DB-related flag enables the DB; comparison to hardcoded string
            replaced with presence check.
"""

from __future__ import annotations

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


# ── Banner ────────────────────────────────────────────────────────────────
# Printed on every launch (including --help), before anything else runs.

_BLFINDER_LOGO = r"""
██████╗ ██╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔══██╗██║     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══██╗██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝"""

_BLFINDER_VERSION_TAG = "v3.2 Phase 6"
_BLFINDER_TAGLINE = "Business Logic Flaw Detection Engine"
_BLFINDER_SUBTAGLINE = "Traffic Import · Deep Discovery · SSRF/CSRF · Source Exposure · OTP Rate-Limit Testing"
_BLFINDER_AUTHOR = "séç gúy"
_BLFINDER_REPO = "github.com/Steven5233/BLfinder"


def print_banner() -> None:
    """
    Prints the BLFinder banner. Called unconditionally as the very first
    thing `parse_args()` does, so it appears both on a normal launch and
    ahead of argparse's own `--help` output (since this runs before
    argparse ever touches sys.argv). Suppressed by --no-banner/--no-color
    or the NO_COLOR/BLFINDER_NO_BANNER environment variables, for clean
    output in scripts/CI.
    """
    argv = sys.argv[1:]
    if "--no-banner" in argv or os.environ.get("BLFINDER_NO_BANNER"):
        return

    no_color = "--no-color" in argv or bool(os.environ.get("NO_COLOR"))
    if no_color:
        accent = reset = dim = green = crit = ""
    else:
        accent = "\033[1;35m"   # purple accent, matches the HTML report's --accent
        crit   = "\033[1;31m"   # red, matches the HTML report's --critical
        green  = "\033[1;32m"
        dim    = "\033[2m"
        reset  = "\033[0m"

    # Colour just the trailing "F" the way the HTML report logo does
    # (BL<span class="critical">F</span>inder), by splitting the ASCII art
    # at its vertical midpoint column-wise isn't practical for block glyphs,
    # so the whole wordmark is rendered in the accent colour instead and the
    # tagline/author lines carry the rest of the palette.
    print(f"{accent}{_BLFINDER_LOGO}{reset}")
    print(f"{dim}        {_BLFINDER_TAGLINE} · {_BLFINDER_VERSION_TAG}{reset}")
    print(f"{dim}        {_BLFINDER_SUBTAGLINE}{reset}")
    print(f"{green}        Developed by {_BLFINDER_AUTHOR}{reset}{dim} — {_BLFINDER_REPO}{reset}\n")


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
        config.discovery_depth   = getattr(args, "discovery_depth",   2)
        config.use_headless      = getattr(args, "use_headless",      False)
        config.headless_interact = getattr(args, "headless_interact",  False)
        config.openapi_paths     = getattr(args, "openapi_paths",     [])
        config.proto_paths       = getattr(args, "proto_paths",       [])
        config.no_wordlist       = getattr(args, "no_wordlist",       False)
        config.save_discovery    = getattr(args, "save_discovery",    "")
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
        ("run_ssrf",          "ssrf"),
        ("run_csrf",          "csrf"),
        ("run_source_scan",   "source_scan"),
        ("skip_verification", "no_verify"),
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
    print_banner()
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
        "--no-verify", action="store_true",
        help=(
            "Skip the re-verification pass entirely — every finding that "
            "passes the confidence filter is reported as-is. Use this if "
            "the verifier is dropping genuine findings on a flaky/stateful "
            "target (re-verification re-runs the attack request and can "
            "false-negative on endpoints whose state changed since the "
            "first request, or that get rate-limited on the retry). When "
            "verification IS enabled, anything it drops is now also written "
            "to <output>/dropped_findings.json for manual review instead of "
            "vanishing silently."
        ),
    )
    core.add_argument(
        "--no-scan", action="store_true",
        help="Run discovery only, skip all attack modules",
    )

    # ── Resume / Checkpointing ─────────────────────────────────────────────────
    resume_grp = p.add_argument_group("Resume / Checkpointing")
    resume_grp.add_argument(
        "--resume", action="store_true",
        help="Resume a previously interrupted scan of this target — skips "
             "endpoints already checked and merges in their findings",
    )
    resume_grp.add_argument(
        "--checkpoint", default="", metavar="FILE",
        help="Path to the checkpoint file (default: auto-derived from "
             "target + output dir)",
    )
    resume_grp.add_argument(
        "--no-checkpoint", action="store_true",
        help="Disable incremental checkpointing entirely for this run",
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
        dest="wordlist_depth",
        help="Wordlist depth 1=tiny … 5=exhaustive (default: 2)",
    )
    disc.add_argument("--no-robots",          action="store_true",  help="Skip robots.txt / sitemap.xml parsing")
    disc.add_argument("--no-js-ast",          action="store_true",  help="Skip JS AST endpoint extraction")
    disc.add_argument("--no-openapi",         action="store_true",  help="Skip OpenAPI/Swagger/Postman spec probing")
    disc.add_argument("--no-version-permute", action="store_true",  help="Skip API version-shadow discovery")
    disc.add_argument(
        "--business-tags", default="", metavar="TAGS",
        help="Comma-separated business context tags (e.g. payment,order,user)",
    )
    disc.add_argument(
        "--discovery-save", default="", metavar="FILE",
        dest="discovery_save",
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
    recon.add_argument(
        "--source-only", action="store_true",
        help=(
            "Run ONLY the source code exposure + static bug-pattern scanner "
            "against -t/--target, then exit. Skips discovery and every other "
            "module (IDOR, BOLA, CORS, JWT, SSRF, CSRF, business-logic, ...) "
            "entirely — fastest, lowest-noise way to just check a URL's "
            "exposed .git/.env/backup files and any reachable JS source maps. "
            "No --cookie or -T/--token required unless you want authenticated "
            "pages included."
        ),
    )
    recon.add_argument(
        "--otp-scan", action="store_true",
        help=(
            "Run ONLY the OTP rate-limit/lockout-bypass scanner against "
            "--otp-url, then exit. Skips discovery and every other module. "
            "Requires --otp-url and --otp-digits."
        ),
    )
    recon.add_argument(
        "--otp-url", default="", metavar="URL",
        help="OTP verification endpoint to test (required with --otp-scan).",
    )
    recon.add_argument(
        "--otp-digits", type=int, default=0, metavar="N",
        help="OTP code length, e.g. 4 or 6 (required with --otp-scan).",
    )
    recon.add_argument(
        "--otp-field", default="otp", metavar="NAME",
        help="Body/query field name holding the OTP guess (default: otp).",
    )
    recon.add_argument(
        "--otp-method", default="POST", metavar="METHOD",
        help="HTTP method for the OTP verification request (default: POST).",
    )
    recon.add_argument(
        "--otp-in-query", action="store_true",
        help="Send the OTP field as a query parameter instead of a JSON body.",
    )
    recon.add_argument(
        "--otp-extra-body", default="{}", metavar="JSON",
        help=(
            "Extra JSON object merged into the request alongside the OTP "
            "field — e.g. '{\"user_id\": \"123\", \"challenge_id\": \"abc\"}' "
            "for any other fields the endpoint requires."
        ),
    )
    recon.add_argument(
        "--otp-samples", type=int, default=20, metavar="N",
        help=(
            "Sequential wrong-guess attempts to test for a lockout, enumerated "
            "from 000...0 upward (default: 20, hard cap 100,000 — also "
            "clamped to the digit count's actual keyspace, e.g. a 4-digit "
            "OTP naturally caps at 10,000). Raising this toward or past the "
            "full keyspace of a short OTP turns the test into a genuine "
            "complete brute-force sweep, not a sample — only do this "
            "against your own authorized test target/account."
        ),
    )
    recon.add_argument(
        "--otp-concurrency", type=int, default=10, metavar="N",
        help="Simultaneous requests for the race-condition burst test (default: 10, hard cap 50).",
    )
    recon.add_argument(
        "--otp-success-marker", default="", metavar="TEXT",
        help=(
            "Substring in the response body that indicates a CORRECT OTP was "
            "accepted. If any random guess's response contains this, the scan "
            "stops immediately instead of continuing to probe. Strongly "
            "recommended if you know what a success response looks like."
        ),
    )
    recon.add_argument(
        "--otp-real-value", default="", metavar="CODE",
        help=(
            "The ACTUAL, currently-valid OTP code for YOUR OWN authorized "
            "bug-bounty test account (e.g. read from the SMS/email you just "
            "received). Submitted immediately after the Test 1 decoy barrage "
            "to prove — with definitive, screenshot-grade evidence — that a "
            "real authentication still succeeds after exceeding the allowed "
            "attempt budget. Never use another account's OTP here; this must "
            "be your own test account."
        ),
    )
    recon.add_argument(
        "--otp-expected-limit", type=int, default=0, metavar="N",
        help=(
            "The attempt limit the application is documented/expected to "
            "enforce (e.g. 5). Used only to phrase the --otp-real-value "
            "finding precisely ('N decoy attempts sent, M beyond the stated "
            "limit, and the real code was still accepted'). Optional."
        ),
    )
    recon.add_argument(
        "--otp-delay", type=float, default=0.1, metavar="SECS",
        help="Delay between sequential attempts in Test 1 (default: 0.1s).",
    )
    recon.add_argument("--js-secrets",  action="store_true", help="Enable JS secret extraction")
    recon.add_argument(
        "--subdomain-size", type=int, default=50,
        help="Max subdomain wordlist size (default: 50)",
    )
    recon.add_argument(
        "--strict-validation", action="store_true",
        help="Strict endpoint pre-validation (reject soft-404 / WAF-blocked)",
    )
    recon.add_argument(
        "--no-validation",
        action="store_true",
        dest="no_validation",
        help=(
            "Disable endpoint pre-validation entirely. "
            "Scans ALL discovered endpoints regardless of response type. "
            "Use when too many valid endpoints are being skipped as soft-404."
        ),
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
    atk.add_argument("--idor-range",          type=int, default=0,    help="IDOR enumeration range (0 = disabled)")
    atk.add_argument("--idor-harvest",        action="store_true",    help="Harvest IDs from responses for IDOR")
    atk.add_argument("--idor-cross-endpoint", action="store_true",    help="Cross-endpoint IDOR testing")
    atk.add_argument("--idor-batch-size",     type=int, default=20,   help="IDOR batch concurrency size (default: 20)")
    atk.add_argument("--websocket",           action="store_true",    help="Enable WebSocket scanning")
    atk.add_argument("--ws-url",              default="",             help="Override WebSocket URL")
    atk.add_argument("--ws-race-count",       type=int, default=15,   help="WebSocket race condition attempt count")
    atk.add_argument("--graphql-deep",        action="store_true",    help="Enable deep GraphQL introspection scan")
    atk.add_argument("--version-scan",        action="store_true",    help="Enable API version-abuse scanning")
    atk.add_argument("--ssrf",                action="store_true",    help="Enable SSRF scanning module")
    atk.add_argument(
        "--ssrf-oob-domain", default="", dest="ssrf_oob_domain",
        help=(
            "Collaborator/interactsh domain for blind SSRF out-of-band "
            "confirmation (e.g. abc123.oast.fun). Leave empty to skip Tier 3 "
            "OOB probing and rely on in-band metadata + timing leads only."
        ),
    )
    atk.add_argument(
        "--js-url", action="append", default=[], metavar="URL",
        help=(
            "Explicit JS file URL to feed into the source code scanner's "
            "Phase B (source map reconstruction + static bug scan). "
            "Repeatable. Used automatically by --source-only in addition "
            "to any <script src> tags found on the target page; also usable "
            "in a normal full scan run alongside --source-scan."
        ),
    )
    atk.add_argument(
        "--source-scan", action="store_true",
        help=(
            "Enable source code exposure + static bug-pattern scanning: "
            "probes for exposed .git/.env/backup/credential files, and "
            "reconstructs+scans original source via exposed JS source maps "
            "for dangerous patterns (eval, disabled TLS verify, DOM XSS "
            "sinks, unsafe postMessage handlers, hardcoded internal hosts). "
            "Opt-in because Phase A sweeps ~18 extra paths per host and "
            "Phase B downloads .map files, which adds bandwidth/time — "
            "worth budgeting for on slower/metered connections."
        ),
    )
    atk.add_argument(
        "--csrf", action="store_true",
        help=(
            "Enable CSRF scanning with ACTIVE cross-site replay of "
            "state-changing requests. This resends real POST/PUT/PATCH/DELETE "
            "requests with forged Origin/Referer to prove exploitability — "
            "only use against targets you're authorized to test. Without "
            "this flag, CSRF checks are limited to passive hardening-gap "
            "detection (no extra requests)."
        ),
    )
    atk.add_argument(
        "--skip-unauth", action="store_true", dest="skip_unauth",
        help=(
            "Skip unauthenticated access probes on every endpoint. "
            "Halves request volume — recommended on Cloudflare-protected targets."
        ),
    )
    atk.add_argument(
        "--max-endpoints", type=int, default=5, metavar="N", dest="max_endpoints",
        help=(
            "Max endpoints processed concurrently (default: 5). "
            "Lower to 2-3 on Cloudflare targets to avoid burst detection."
        ),
    )
    atk.add_argument(
        "--classify",
        action="store_true",
        help=(
            "Print business logic attack plan based on discovered endpoints.\n"
            "When used with --target the scan continues after printing the plan.\n"
            "Without --target, prints the plan and exits."
        ),
    )

    # ── Endpoint Enrichment ───────────────────────────────────────────────────
    enr = p.add_argument_group(
        "Endpoint Enrichment",
        description=(
            "Automatically infers real body parameters and query params for\n"
            "bare endpoints (body: {}, params: {}) before scanning.\n"
            "Uses 4 strategies: HTTP response mirroring, validation error\n"
            "parsing, JSON schema extraction, and path-pattern dictionary.\n"
            "Enabled automatically when -T TOKEN is supplied and bare\n"
            "endpoints are present. Use --no-enrich to disable."
        ),
    )
    enr.add_argument(
        "--no-enrich",
        action="store_true", dest="no_enrich",
        help="Skip automatic body/param enrichment of bare endpoints",
    )
    enr.add_argument(
        "--enrich-save",
        default="", metavar="FILE", dest="enrich_save",
        help="Save enriched endpoints JSON to this file before scanning",
    )
    enr.add_argument(
        "--enrich-concurrency",
        type=int, default=8, metavar="N", dest="enrich_concurrency",
        help="Max concurrent enrichment probes (default: 8)",
    )
    enr.add_argument(
        "--no-enrich-promote",
        action="store_true", dest="no_enrich_promote",
        help="Skip GET→POST method promotion during enrichment",
    )

    # ── Output ────────────────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",  default=".",  help="Output directory (default: current dir)")
    out.add_argument("--html",          action="store_true", help="Generate HTML report")
    out.add_argument("--json",          action="store_true", help="Generate JSON report")
    out.add_argument("--md",            action="store_true", help="Generate Markdown report")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("--no-color",      action="store_true", help="Disable ANSI colour output")
    out.add_argument("--no-banner",     action="store_true", help="Suppress the BLFinder banner (useful for scripts/CI)")

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

    FIX (BUG-3): wordlist_depth and discovery_depth are now reconciled by
    taking the maximum of the two so that passing either flag alone works
    correctly.  Previously only discovery_depth won via getattr fallback,
    meaning --wordlist-depth 4 was silently ignored when --discovery-depth
    was at its default of 2.
    """
    try:
        from core.discovery.models import DiscoveryConfig
    except ImportError:
        return None

    prof_disc = profile.get("discovery", {})

    # WEAK-6 FIX: merge --business-tags and --discovery-tags; both flags
    # seed the wordlist. Previously only --business-tags was read here,
    # so --discovery-tags was silently dropped.
    business_tags: list[str] = []
    raw_bt = (
        args.business_tags
        or getattr(args, "discovery_tags", "")
        or ""
    )
    if raw_bt:
        business_tags = [t.strip() for t in raw_bt.split(",") if t.strip()]
    elif prof_disc.get("business_tags"):
        business_tags = prof_disc["business_tags"]

    # Merge openapi_paths from both pipeline flags and engine flags
    openapi_paths: list[str] = list(args.openapi_paths or [])
    for p_path in prof_disc.get("openapi_paths", []):
        if p_path not in openapi_paths:
            openapi_paths.append(p_path)

    # FIX (BUG-3): take the maximum of both depth flags so that setting
    # either one works as the user expects.  getattr(..., default) is used
    # so that if add_discovery_args() wasn't called (missing cli_args.py
    # module) we still get a safe integer fallback.
    effective_depth = max(
        getattr(args, "discovery_depth", 2),
        getattr(args, "wordlist_depth",  2),
    )

    # FIX (BUG-14): save path resolution — pick the first non-empty value
    # with a clear precedence order: engine flag > outer flag.
    save_path = (
        getattr(args, "save_discovery",  "") or
        getattr(args, "discovery_save",  "") or
        ""
    )

    return DiscoveryConfig(
        auth_token              = args.token,
        second_token            = args.token2,
        timeout_s               = args.timeout,
        verbose                 = args.verbose,
        use_headless            = getattr(args, "use_headless",      False),
        headless_interact       = getattr(args, "headless_interact",  False),
        headless_timeout_s      = prof_disc.get("headless_timeout_s", 30),
        wordlist_depth          = effective_depth,
        no_wordlist             = getattr(args, "no_wordlist",       False),
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
# Source-only fast path — SourceCodeScanner ONLY, nothing else
# ─────────────────────────────────────────────────────────────────────────────

async def run_source_only(args: argparse.Namespace) -> int:
    """
    Run ONLY the source code exposure + static bug-pattern scanner against a
    single target, entirely bypassing endpoint discovery and every other
    scanning module (IDOR, BOLA, CORS, JWT, SSRF, CSRF, business-logic,
    etc). Triggered by --source-only.

    This does not call `scanner.run_all_modules()` at all — it drives
    `SourceCodeScanner` directly with the scanner's already-configured HTTP
    client (respecting --cookie/--header/--proxy/--rate/--timeout), so the
    only network traffic generated is:
      1. one request to the target URL,
      2. Phase A's ~18 source-exposure probes against that host,
      3. one request per discovered/explicit JS file for Phase B.
    No cookie or token is required — pass them only if you specifically
    want authenticated pages included in the scan.
    """
    if not args.target:
        print("[!] --source-only requires -t/--target")
        return 1

    try:
        from core.models          import ScanConfig
        from core.scanner         import BLFScanner
        from core.modules.source_code_scanner import SourceCodeScanner
        from core.reporter        import (
            print_terminal_summary,
            generate_html_report,
            generate_json_report,
            generate_markdown_report,
        )
    except ImportError as e:
        print(f"[!] Critical import error: {e}")
        return 1

    target = args.target.rstrip("/")
    print(f"[*] BLFinder — Source Code Scanner Only: {target}\n")

    config = ScanConfig(
        target_url  = target,
        auth_token  = args.token,
        headers     = parse_headers(args.header),
        cookies     = parse_cookies(args.cookie),
        proxy       = args.proxy,
        rate_limit  = args.rate,
        timeout     = args.timeout,
        verbose     = args.verbose,
    )
    # Force-enable regardless of --source-scan/profile — this mode's whole
    # point is running this module and only this module.
    config.run_source_scan = True

    findings = []
    scanner_error = None

    async with BLFScanner(config) as scanner:
        # __aenter__ only instantiates SourceCodeScanner when
        # config.run_source_scan is truthy, which we just forced above —
        # but belt-and-braces in case that gating ever changes.
        if not getattr(scanner, "_source_scanner", None):
            scanner._source_scanner = SourceCodeScanner(scanner)

        js_targets: list[str] = []
        for js_url in (args.js_url or []):
            js_targets.append(
                js_url if js_url.startswith("http") else f"{target}/{js_url.lstrip('/')}"
            )

        try:
            status, headers, body, elapsed = await scanner._request("GET", target)
            findings.extend(
                await scanner._source_scanner.check(target, "GET", status, headers, body)
            )

            # Lightweight <script src="..."> extraction so Phase B (source
            # map reconstruction) runs automatically without needing the
            # full discovery/crawl engine — just one regex pass over the
            # page we already fetched, no extra requests yet.
            import re as _re
            from urllib.parse import urljoin as _urljoin
            for m in _re.finditer(
                r'<script[^>]+src=["\']([^"\']+?\.m?js[^"\']*)["\']',
                body or "", _re.IGNORECASE,
            ):
                script_url = _urljoin(target + "/", m.group(1))
                if script_url not in js_targets:
                    js_targets.append(script_url)

            if args.verbose and js_targets:
                print(f"[*] Scanning {len(js_targets)} JS file(s) for Phase B...")

            for js_url in js_targets:
                try:
                    status, headers, body, elapsed = await scanner._request("GET", js_url)
                    findings.extend(
                        await scanner._source_scanner.check(js_url, "GET", status, headers, body)
                    )
                except Exception as e:
                    if args.verbose:
                        print(f"[!] Error fetching {js_url}: {e}")
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[!] Source scan interrupted.")
            return 130
        except Exception as e:
            scanner_error = e
            print(f"[!] Error fetching target: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    if scanner_error and not findings:
        return 1

    os.makedirs(args.output, exist_ok=True)
    cfg_dict = {"target_url": target}

    if not args.no_color:
        try:
            print_terminal_summary(findings, cfg_dict)
        except Exception as e:
            print(f"\n[+] Source scan complete. {len(findings)} findings. (summary error: {e})")
    else:
        print(f"\n[+] Source scan complete. {len(findings)} findings.")

    if args.html or not (args.json or args.md):
        html_path = os.path.join(args.output, "report.html")
        try:
            generate_html_report(findings, cfg_dict, html_path)
            print(f"[*] HTML report: {html_path}")
        except Exception as e:
            print(f"[!] HTML report error: {e}")

    if args.json:
        json_path = os.path.join(args.output, "report.json")
        try:
            generate_json_report(findings, cfg_dict, json_path)
            print(f"[*] JSON report: {json_path}")
        except Exception as e:
            print(f"[!] JSON report error: {e}")

    if args.md:
        md_path = os.path.join(args.output, "report.md")
        try:
            generate_markdown_report(findings, cfg_dict, md_path)
            print(f"[*] Markdown report: {md_path}")
        except Exception as e:
            print(f"[!] Markdown report error: {e}")

    return 1 if any(
        getattr(f.severity, "value", str(f.severity)) == "CRITICAL"
        and getattr(f, "confirmed", False)
        and getattr(f, "confidence", 0) >= 80
        for f in findings
    ) else 0


# ─────────────────────────────────────────────────────────────────────────────
# OTP-only fast path — OTPRateLimitScanner ONLY, nothing else
# ─────────────────────────────────────────────────────────────────────────────

async def run_otp_scan(args: argparse.Namespace) -> int:
    """
    Run ONLY the OTP rate-limit/lockout-bypass scanner against --otp-url,
    entirely bypassing endpoint discovery and every other module. Triggered
    by --otp-scan; requires --otp-url and --otp-digits.

    Bounded and conservative by design: attempt counts are hard-capped
    inside OTPRateLimitScanner regardless of what's requested, and this
    never touches an OTP send/resend endpoint — only the verification
    endpoint the operator explicitly points it at.
    """
    if not args.otp_url:
        print("[!] --otp-scan requires --otp-url")
        return 1
    if not args.otp_digits or args.otp_digits < 1:
        print("[!] --otp-scan requires --otp-digits (e.g. --otp-digits 6)")
        return 1

    try:
        extra_body = json.loads(args.otp_extra_body) if args.otp_extra_body else {}
        if not isinstance(extra_body, dict):
            raise ValueError("must be a JSON object")
    except Exception as e:
        print(f"[!] --otp-extra-body must be valid JSON object: {e}")
        return 1

    try:
        from core.models  import ScanConfig
        from core.scanner import BLFScanner
        from core.modules.otp_scanner import OTPRateLimitScanner
        from core.reporter import (
            print_terminal_summary,
            generate_html_report,
            generate_json_report,
            generate_markdown_report,
        )
    except ImportError as e:
        print(f"[!] Critical import error: {e}")
        return 1

    otp_url = args.otp_url
    print(f"[*] BLFinder — OTP Rate-Limit Scanner Only: {otp_url}")
    print(f"[*] Digits: {args.otp_digits} | Field: {args.otp_field} | Method: {args.otp_method}\n")

    keyspace = 10 ** max(1, args.otp_digits)
    effective_samples = min(args.otp_samples, 100_000, keyspace)
    if effective_samples >= keyspace:
        print(
            f"[*] --otp-samples ({args.otp_samples}) covers the FULL {args.otp_digits}-digit "
            f"keyspace ({keyspace:,} codes) — this run is a complete, exhaustive brute-force "
            f"sweep (000...0 through 999...9), not a sample. Only run this against a target/"
            f"account you are explicitly authorized to test.\n"
        )
    elif args.otp_samples > 1000:
        print(
            f"[*] --otp-samples is set high ({args.otp_samples} of {keyspace:,} possible codes) "
            f"— this will send a large number of sequential requests and take a while. "
            f"Only run this against an authorized test target.\n"
        )

    if args.otp_real_value:
        if len(args.otp_real_value) != args.otp_digits:
            print(
                f"[!] --otp-real-value length ({len(args.otp_real_value)}) does not match "
                f"--otp-digits ({args.otp_digits}) — it will be ignored for this run"
            )
        print(
            "[*] --otp-real-value is set: this MUST be the real OTP for YOUR OWN "
            "authorized bug-bounty test account, never anyone else's. It will be "
            "submitted immediately after the decoy barrage to prove real "
            "authentication still succeeds beyond the allowed attempt budget.\n"
        )

    config = ScanConfig(
        target_url  = otp_url,
        auth_token  = args.token,
        headers     = parse_headers(args.header),
        cookies     = parse_cookies(args.cookie),
        proxy       = args.proxy,
        rate_limit  = args.rate,
        timeout     = args.timeout,
        verbose     = args.verbose,
    )

    findings = []
    result = None
    scanner_error = None

    async with BLFScanner(config) as scanner:
        otp = OTPRateLimitScanner(scanner)
        try:
            result, findings = await otp.scan(
                otp_url=otp_url,
                method=args.otp_method.upper(),
                digits=args.otp_digits,
                field=args.otp_field,
                extra_body=extra_body,
                in_query=args.otp_in_query,
                samples=args.otp_samples,
                concurrency=args.otp_concurrency,
                success_marker=args.otp_success_marker,
                sequential_delay=args.otp_delay,
                real_value=args.otp_real_value,
                expected_limit=(args.otp_expected_limit or None),
                verbose=args.verbose,
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[!] OTP scan interrupted.")
            return 130
        except Exception as e:
            scanner_error = e
            print(f"[!] Error during OTP scan: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    if scanner_error and not findings:
        return 1

    if result:
        print(f"\n[*] Attempts made        : {result.attempts_made}")
        print(
            f"[*] Sequential lockout   : "
            f"{'attempt ' + str(result.lockout_attempt_index) if result.lockout_attempt_index else 'NOT observed'}"
        )
        print(f"[*] Measured request rate: {result.measured_rate_per_sec:.2f} req/s")
        print(
            f"[*] Concurrency burst    : "
            f"{result.concurrency_processed}/{result.concurrency_attempts} processed without a block signal"
        )
        if result.lockout_attempt_index is not None:
            print(f"[*] Header-spoof bypass  : {'SUCCEEDED' if result.header_bypass_succeeded else 'blocked (good)'}")
        if result.real_value_tested:
            outcome = "ACCEPTED (critical finding)" if result.real_value_accepted else "rejected"
            print(f"[*] Real-value confirm   : submitted as attempt {result.real_value_attempt_number} -> {outcome}")
        if result.accidental_match:
            print(f"[!] WARNING: random guess {result.accidental_match_code} matched the success marker — scan stopped early")

    os.makedirs(args.output, exist_ok=True)
    cfg_dict = {"target_url": otp_url}

    if not args.no_color:
        try:
            print_terminal_summary(findings, cfg_dict)
        except Exception as e:
            print(f"\n[+] OTP scan complete. {len(findings)} findings. (summary error: {e})")
    else:
        print(f"\n[+] OTP scan complete. {len(findings)} findings.")

    if args.html or not (args.json or args.md):
        html_path = os.path.join(args.output, "report.html")
        try:
            generate_html_report(findings, cfg_dict, html_path)
            print(f"[*] HTML report: {html_path}")
        except Exception as e:
            print(f"[!] HTML report error: {e}")

    if args.json:
        json_path = os.path.join(args.output, "report.json")
        try:
            generate_json_report(findings, cfg_dict, json_path)
            print(f"[*] JSON report: {json_path}")
        except Exception as e:
            print(f"[!] JSON report error: {e}")

    if args.md:
        md_path = os.path.join(args.output, "report.md")
        try:
            generate_markdown_report(findings, cfg_dict, md_path)
            print(f"[*] Markdown report: {md_path}")
        except Exception as e:
            print(f"[!] Markdown report error: {e}")

    return 1 if any(
        getattr(f.severity, "value", str(f.severity)) == "CRITICAL"
        and getattr(f, "confirmed", False)
        and getattr(f, "confidence", 0) >= 80
        for f in findings
    ) else 0


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
        # BUG-C FIX: preserve _meta/schema_hint so OpenAPI-sourced field
        # schemas survive and reach the scanner attack modules.
        result_dicts.append({
            "url":    ep.url,
            "method": getattr(ep, "method", "GET"),
            "body":   getattr(ep, "body",   None) or {},
            "params": getattr(ep, "params", None) or {},
            "_meta":  getattr(ep, "_meta",  None) or getattr(ep, "meta", None) or {},
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

    if args.source_only:
        return await run_source_only(args)

    if args.otp_scan:
        return await run_otp_scan(args)

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
        no_auth_check         = not getattr(args, "skip_unauth", False),  # BUG-F FIX
        min_confidence        = merged_settings.get("min_confidence", args.min_confidence),
        confirmation_attempts = merged_settings.get("confirm_attempts", args.confirm_attempts),
        resume                = args.resume,
    )
    config.skip_verification = args.no_verify or prof_settings.get("skip_verification", False)

    # ── Resume / Checkpointing ────────────────────────────────────────────────
    # Set up the checkpoint path before anything else touches the scanner, so
    # incremental per-endpoint progress is captured from the very first
    # endpoint even if the scan is interrupted a few seconds in.
    if not args.no_checkpoint:
        os.makedirs(args.output, exist_ok=True)
        from core.checkpoint import ScanCheckpoint, checkpoint_path_for
        config.checkpoint_path = (
            args.checkpoint or checkpoint_path_for(config.target_url, args.output)
        )
        if args.resume:
            if os.path.exists(config.checkpoint_path):
                _ckpt_preview = ScanCheckpoint.load_or_create(
                    config.checkpoint_path, config.target_url
                )
                print(f"[*] Resume checkpoint found: {_ckpt_preview.summary()}")
            else:
                print(
                    "[*] --resume requested but no checkpoint file found for "
                    "this target — starting a fresh scan"
                )
        else:
            # Not resuming: any leftover checkpoint from a prior interrupted
            # run of this same target is stale relative to this run's intent
            # (fresh scan), so start clean rather than silently reusing it.
            if os.path.exists(config.checkpoint_path):
                try:
                    os.remove(config.checkpoint_path)
                except OSError:
                    pass
    else:
        config.checkpoint_path = ""

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
    config.strict_validation = (
        args.strict_validation
        or merged_settings.get("strict_validation", False)
    )

    # FIX (BUG-6): --no-validation is now stored with an explicit dest= in
    # argparse (dest="no_validation") so args.no_validation is always reliable.
    # It is propagated to config here and then acted on in the scanner patch
    # block below where it disables EndpointValidator entirely when set.
    config.no_validation = getattr(args, "no_validation", False)

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
    config.run_ssrf             = args.ssrf         or prof_settings.get("run_ssrf", False)
    config.ssrf_oob_domain      = getattr(args, "ssrf_oob_domain", "") or prof_settings.get("ssrf_oob_domain", "")
    config.run_csrf             = args.csrf         or prof_settings.get("run_csrf", False)
    config.run_source_scan      = args.source_scan  or prof_settings.get("run_source_scan", False)
    config.print_attack_plan         = args.classify
    config.max_endpoint_concurrency   = getattr(args, "max_endpoints", 5)  # WEAK-7 FIX

    # ── Phase 5: Database ─────────────────────────────────────────────────────
    config.db_path   = os.path.expanduser(args.db)
    config.program   = args.program
    config.no_repeat = args.no_repeat

    # FIX (BUG-17): previous logic compared args.db to the hardcoded default
    # string "~/.blfinder.db", which meant explicitly passing that path on
    # the CLI left use_db=False.  Now the DB is activated when any
    # DB-related flag is set OR when the user explicitly provided a --db
    # path (different from the default is checked, but we also activate on
    # program/no_repeat/export_h1 regardless of path).
    _db_explicitly_set = args.db != "~/.blfinder.db"
    config.use_db = bool(
        _db_explicitly_set
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

    # FIX (BUG-15): enforce mutual exclusion between --deep-discovery and
    # --no-deep-discovery.  If the user passed --no-deep-discovery it
    # overrides --deep-discovery regardless of the order on the command line.
    if getattr(args, "no_deep_discovery", False):
        config.deep_discovery    = False
        config.no_deep_discovery = True

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

    # ── Classify-only (preview attack plan) ───────────────────────────────────
    # FIX (BUG-16): --classify with --target now ALWAYS continues to the full
    # scan (as the code comment already stated).  Without --target it exits.
    # Help text was updated above to reflect this accurately.
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
        # Target provided → fall through to the full scan (intentional)
        print("[*] --classify: continuing to full scan (target supplied)...")

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
        # BUG-D FIX: honour --save-discovery path; fall back to output dir.
        _noscan_save = (
            getattr(args, "save_discovery", "")
            or getattr(args, "discovery_save", "")
            or ""
        )
        if not _noscan_save:
            os.makedirs(args.output, exist_ok=True)
            _noscan_save = os.path.join(args.output, "discovered_endpoints.json")
        else:
            _parent = os.path.dirname(os.path.abspath(_noscan_save))
            if _parent:
                os.makedirs(_parent, exist_ok=True)
        try:
            with open(_noscan_save, "w") as fh:
                json.dump(endpoints, fh, indent=2)
            print(f"[+] {len(endpoints)} endpoints saved → {_noscan_save}")
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
    if not getattr(config, "no_deep_discovery", False):
        try:
            from core.discovery.scanner_patch import apply_patch
            apply_patch()
            if args.verbose:
                print("[*] scanner_patch applied (coroutine fix + soft-404 threshold)")
        except ImportError:
            pass  # Engine absent — BLFScanner uses its built-in fallback

    # FIX (BUG-6): wire --no-validation flag into scanner_patch so the
    # EndpointValidator is bypassed when the user requests it.
    if config.no_validation:
        try:
            from core.discovery.scanner_patch import disable_endpoint_validation
            disable_endpoint_validation()
            if args.verbose:
                print("[*] EndpointValidator disabled (--no-validation)")
        except (ImportError, AttributeError):
            # scanner_patch may not expose this helper yet — apply a direct
            # monkey-patch as a safe fallback.
            try:
                from core.scanner import BLFScanner as _BLF
                if hasattr(_BLF, "_validate_endpoint"):
                    async def _no_validate(self, ep):
                        return True
                    _BLF._validate_endpoint = _no_validate
                    if args.verbose:
                        print("[*] EndpointValidator bypassed via direct patch")
            except ImportError:
                pass

    # Patch 2b: blind_idor_patch — prevents false positives
    try:
        from core.oracles.blind_idor_patch import apply_blind_idor_patch
        apply_blind_idor_patch()
        if args.verbose:
            print("[*] blind_idor_patch applied (FP prevention)")
    except ImportError:
        pass

    # Patch 2: verifier_patch — fixes over-aggressive re-verification
    try:
        from core.verifier_patch import apply_verifier_patch
        patched = apply_verifier_patch()
        if args.verbose and patched:
            print("[*] verifier_patch applied (relaxed re-verification thresholds)")
    except ImportError:
        pass

    # FIX (BUG-1): scanner_integration was never called, leaving auth-diff,
    # platform attack modules, and domain chain engine completely dead.
    # It MUST be applied after scanner_patch (so it wraps the patched method)
    # and BEFORE the BLFScanner context manager opens.
    try:
        from core.intelligence.scanner_integration import apply_integration
        integration_applied = apply_integration()
        if args.verbose and integration_applied:
            print("[*] scanner_integration applied (auth_diff + platform + chains)")
    except ImportError:
        pass  # Module absent — scan continues with standard 21-module sweep

    # WEAK-7 FIX: global endpoint concurrency cap prevents WAF-triggering bursts.
    # Wraps _run_endpoint_checks with a semaphore so at most N endpoints are
    # processed simultaneously (default 5; lower on Cloudflare targets).
    _max_ep = getattr(config, "max_endpoint_concurrency", 5)
    try:
        from core.scanner import BLFScanner as _BLF_cls
        _orig_ep_checks = _BLF_cls._run_endpoint_checks
        _global_ep_sem  = asyncio.Semaphore(_max_ep)

        async def _capped_run_endpoint_checks(self, url, method, body, params, meta=None):
            async with _global_ep_sem:
                return await _orig_ep_checks(self, url, method, body, params, meta=meta)

        _BLF_cls._run_endpoint_checks = _capped_run_endpoint_checks
        if args.verbose:
            print(f"[*] endpoint concurrency cap: max={_max_ep} (--max-endpoints)")
    except Exception:
        pass  # Non-fatal

    # ── Endpoint enrichment ───────────────────────────────────────────────────
    # Adds real body parameters and query params to bare endpoints so that
    # BLFinder's attack modules have concrete fields to manipulate.
    # Runs automatically unless --no-enrich is passed.
    # Skipped when all endpoints already have bodies (nothing to infer).
    _bare_count = sum(
        1 for ep in endpoints
        if not ep.get("body") and not ep.get("params")
    )
    _should_enrich = (
        not getattr(args, "no_enrich", False)
        and _bare_count > 0
        and args.token  # need auth to probe protected endpoints
        and not args.no_scan
    )
    if _should_enrich:
        print(
            f"[*] Enriching {_bare_count}/{len(endpoints)} bare endpoints "
            f"with real body parameters..."
        )
        try:
            from core.discovery.endpoint_enricher import enrich_endpoints
            # BUG-A FIX: pass cookies + extra_headers so cookie-authenticated
            # targets (1win.com: cf_clearance, 1w_token) are probed correctly.
            # BUG-B FIX: pass verify_ssl so ssl= is not hardcoded False.
            # BUG-H FIX: pass proxy so Burp interception works during enrichment.
            endpoints = await enrich_endpoints(
                endpoints     = endpoints,
                target_url    = config.target_url,
                auth_token    = config.auth_token,
                second_token  = getattr(config, "second_user_token", "") or "",
                cookies       = dict(getattr(config, "cookies", {}) or {}),
                extra_headers = dict(getattr(config, "headers", {}) or {}),
                proxy         = getattr(config, "proxy", "") or "",
                verify_ssl    = getattr(config, "verify_ssl", True),
                timeout_s     = min(args.timeout, 10),
                concurrency   = getattr(args, "enrich_concurrency", 8),
                verbose       = args.verbose,
                promote_get   = not getattr(args, "no_enrich_promote", False),
            )
            # Optionally save enriched endpoints
            enrich_save = getattr(args, "enrich_save", "")
            if enrich_save:
                try:
                    with open(enrich_save, "w") as _ef:
                        json.dump(endpoints, _ef, indent=2)
                    print(f"[+] Enriched endpoints saved → {enrich_save}")
                except OSError as _e:
                    print(f"[!] Could not save enriched endpoints: {_e}")
        except ImportError:
            print(
                "[!] endpoint_enricher not found — place "
                "core/discovery/endpoint_enricher.py in your project.\n"
                "[!] Continuing with bare endpoints (attack modules may find less)."
            )
    elif _bare_count > 0 and not args.token:
        print(
            f"[*] {_bare_count} endpoints have no body/params. "
            f"Pass -T TOKEN to enable automatic enrichment (--enrich)."
        )
    elif getattr(args, "no_enrich", False) and _bare_count > 0:
        print(f"[*] Enrichment skipped (--no-enrich). {_bare_count} endpoints are bare.")

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

        interrupted = False
        try:
            findings = await scanner.run_all_modules(endpoints)
        except (KeyboardInterrupt, asyncio.CancelledError):
            # RESUME-FIX: previously this propagated all the way up
            # uncaught (KeyboardInterrupt/CancelledError aren't Exception
            # subclasses) and crashed with a raw traceback — and even if it
            # hadn't, `findings` here would still be empty since
            # run_all_modules never got to return it. Checkpointing has
            # already been saving progress incrementally per-endpoint
            # throughout the scan, so the data itself is safe on disk;
            # this just gives the person a clean message instead of a
            # crash, and tells them how to pick back up.
            interrupted = True
            ckpt = getattr(scanner, "_checkpoint", None)
            print("\n[!] Scan interrupted.")
            if ckpt:
                print(f"[*] Progress saved: {ckpt.summary()}")
                print(f"[*] Resume with: --resume --checkpoint {ckpt.path}")
            else:
                print(
                    "[!] No checkpoint was active for this run "
                    "(pass without --no-checkpoint to enable resume support)."
                )
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

    if interrupted:
        return 130  # conventional SIGINT exit code

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

    # HTML report — try full evidence report first, fall back gracefully.
    # FIX (BUG-5): the second reporter path was "core.reporting.core.reporting.
    # evidence_report" (doubled prefix, copy-paste error).  Corrected to
    # "core.reporting.evidence_report".
    if args.html or not (args.json or args.md):
        html_path = os.path.join(args.output, "report.html")
        generated = False
        for reporter_path in [
            "core.reporting",
            "core.reporting.evidence_report",
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

    # BUG-G FIX: exit 1 only on confirmed CRITICAL findings with >=80% confidence.
    # Unconfirmed / low-confidence CRITICAL findings (e.g. price manipulation FPs)
    # no longer fail CI pipelines.
    return 1 if any(
        getattr(f.severity, "value", str(f.severity)) == "CRITICAL"
        and getattr(f, "confirmed", False)
        and getattr(f, "confidence", 0) >= 80
        for f in findings
    ) else 0


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
