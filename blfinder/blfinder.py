#!/usr/bin/env python3
"""
BLFinder v3.1 Phase 5 — CLI Entry Point
Complete platform with all phases integrated.

New Phase 5 flags:
  --import-burp FILE    Import Burp Suite XML/JSON traffic export
  --import-har FILE     Import browser HAR file
  --import-mitmproxy FILE  Import mitmproxy flows file
  --import-filter REGEX Filter imported URLs (e.g. /api/)
  --import-save FILE    Save generated endpoints.json to this path
  --db PATH             SQLite database path (default: ~/.blfinder.db)
  --no-repeat           Skip endpoints already in database (dedup)
  --program HANDLE      Tag findings with HackerOne program handle
  --export-h1 HANDLE    Export new findings to HackerOne as drafts
  --h1-token TOKEN      HackerOne API token (username:api_token)
  --show-history        Print finding history from DB and exit
  --search QUERY        Search past findings and exit
  --profile NAME        Load settings from profiles/NAME.json
  --dashboard           Enable live TUI dashboard

Deep Discovery flags (new modules):
  --deep-discovery      Enable full multi-layer discovery pipeline
  --wordlist-depth N    Wordlist depth 1=tiny … 5=exhaustive (default: 2)
  --no-wordlist         Skip wordlist layer entirely
  --openapi-path PATH   Extra path to probe for OpenAPI/Swagger spec
  --discovery-save FILE Save discovered endpoints JSON to this path
  --no-robots           Skip robots.txt / sitemap.xml parsing
  --no-js-ast           Skip JS AST pass (keep regex-only JS scan)
  --no-openapi          Skip OpenAPI/Swagger/Postman spec probing
  --no-version-permute  Skip API version-shadow discovery in pipeline
  --business-tags TAGS  Comma-separated business context tags for wordlist
"""

import asyncio
import argparse
import json
import os
import sys
from pathlib import Path


# ── Profile loader ────────────────────────────────────────────────────────────

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
            except Exception as e:
                print(f"[!] Profile load error ({profile_path}): {e}")

    print(f"[!] Profile not found: {name}")
    print(f"[!] Available profiles: ecommerce, fintech, saas, stealth, fast, graphql, api_only, thorough")
    return {}


def merge_profile_with_args(profile: dict, args) -> dict:
    """
    Merge profile settings with CLI args.
    CLI args take priority over profile settings.
    Returns a dict of merged settings to apply to config.
    """
    settings = dict(profile.get("settings", {}))

    cli_overrides = {
        "rate_limit":       args.rate != 0.3,
        "min_confidence":   args.min_confidence != 40,
        "confirm_attempts": args.confirm_attempts != 2,
        "fuzz_depth":       args.fuzz_depth != 2,
    }
    for key, was_overridden in cli_overrides.items():
        if was_overridden:
            settings.pop(key, None)

    for flag, attr in [
        ("strict_validation", "strict_validation"),
        ("blind_idor",        "blind_idor"),
        ("run_graphql_deep",  "graphql_deep"),
        ("run_websocket",     "websocket"),
        ("run_version_scan",  "version_scan"),
        ("run_recon",         "recon"),
        ("js_secrets",        "js_secrets"),
        ("deep_discovery",    "deep_discovery"),
    ]:
        if getattr(args, attr, False):
            settings[flag] = True

    return settings


# ── Argument parser ───────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="BLFinder v3.1 Phase 5 — Business Logic Flaw Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""\
EXAMPLES:
  # Import from Burp and scan with ecommerce profile
  python blfinder.py -t https://shop.target.com -T token \\
    --import-burp burp_export.xml --profile ecommerce \\
    --db ~/.blfinder.db --program target_h1 \\
    --html --md -o ~/results

  # Full Phase 5 professional scan with deep discovery
  python blfinder.py \\
    -t https://api.target.com \\
    -T user1_token -T2 user2_token \\
    --import-burp traffic.xml \\
    --profile thorough \\
    --deep-discovery --wordlist-depth 3 \\
    --db ~/.blfinder.db --program target_h1 \\
    --dashboard \\
    --html --json --md -o ~/results

  # Import HAR and preview attack plan
  python blfinder.py -t https://api.target.com -T token \\
    --import-har requests.har --classify

  # Show finding history
  python blfinder.py --show-history --db ~/.blfinder.db

  # Search past findings
  python blfinder.py --search "IDOR payment" --db ~/.blfinder.db

  # Export finding to HackerOne
  python blfinder.py --export-h1 target_program \\
    --h1-token username:api_token \\
    --db ~/.blfinder.db

  # Recon only
  python blfinder.py -t https://target.com --recon-only -o ~/recon

  # Deep discovery only — dump endpoint list without scanning
  python blfinder.py -t https://api.target.com -T token \\
    --deep-discovery --wordlist-depth 2 \\
    --discovery-save discovered.json --no-scan
""",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    p.add_argument("-t",  "--target",      default="",               help="Target base URL")
    p.add_argument("-T",  "--token",       default="",               help="Auth token for User 1")
    p.add_argument("-T2", "--token2",      default="",               help="Auth token for User 2")
    p.add_argument("-T3", "--token3",      default="",               help="Auth token for User 3")
    p.add_argument("-e",  "--endpoints",   default="",               help="Endpoints JSON file")
    p.add_argument("-H",  "--header",      action="append", default=[], metavar="Key:Value")
    p.add_argument("-c",  "--cookie",      action="append", default=[], metavar="name=value")
    p.add_argument("--proxy",              default="",               help="HTTP proxy")
    p.add_argument("-r",  "--rate",        type=float, default=0.3,  help="Base request delay (default: 0.3)")
    p.add_argument("--timeout",            type=int,   default=20,   help="Request timeout (default: 20)")
    p.add_argument("--no-discover",        action="store_true")
    p.add_argument("--no-ssl-verify",      action="store_true")
    p.add_argument("--fuzz-depth",         type=int,   default=2)
    p.add_argument("--min-confidence",     type=int,   default=40)
    p.add_argument("--confirm-attempts",   type=int,   default=2)
    p.add_argument("--no-scan",            action="store_true",
                   help="Run discovery only, skip attack modules")

    # ── Phase 5: Profile ──────────────────────────────────────────────────────
    p.add_argument("--profile",            default="",
                   help="Load settings from profiles/NAME.json "
                        "(ecommerce|fintech|saas|stealth|fast|graphql|api_only|thorough)")

    # ── Phase 5: Import ───────────────────────────────────────────────────────
    p.add_argument("--import-burp",        default="",               help="Import Burp Suite XML/JSON export")
    p.add_argument("--import-har",         default="",               help="Import browser HAR file")
    p.add_argument("--import-mitmproxy",   default="",               help="Import mitmproxy flows file")
    p.add_argument("--import-filter",      default="",               help="Regex filter for imported URLs (e.g. /api/)")
    p.add_argument("--import-save",        default="",               help="Save generated endpoints.json to this path")

    # ── Phase 5: Database ─────────────────────────────────────────────────────
    p.add_argument("--db",                 default="~/.blfinder.db", help="SQLite database path")
    p.add_argument("--no-repeat",          action="store_true",
                   help="Skip endpoints already confirmed vulnerable in DB")
    p.add_argument("--program",            default="",
                   help="Tag findings with this HackerOne program handle")
    p.add_argument("--export-h1",          default="",
                   help="Export new findings to HackerOne as drafts (requires --h1-token)")
    p.add_argument("--h1-token",           default="",
                   help="HackerOne API token (format: username:api_token)")
    p.add_argument("--show-history",       action="store_true",
                   help="Print finding history from DB and exit")
    p.add_argument("--search",             default="",
                   help="Search past findings by keyword and exit")

    # ── Phase 5: Dashboard ────────────────────────────────────────────────────
    p.add_argument("--dashboard",          action="store_true",
                   help="Enable live TUI dashboard during scan")
    p.add_argument("--force-ansi",         action="store_true",
                   help="Force ANSI output even if curses is available")

    # ── Deep Discovery (new layer system) ─────────────────────────────────────
    p.add_argument("--deep-discovery",     action="store_true",
                   help="Enable full multi-layer discovery pipeline "
                        "(robots, JS AST, OpenAPI, wordlist, version permutation, dedup)")
    p.add_argument("--wordlist-depth",     type=int,   default=2,
                   help="Wordlist depth 1=tiny … 5=exhaustive (default: 2)")
    p.add_argument("--no-wordlist",        action="store_true",
                   help="Skip wordlist layer in deep discovery")
    p.add_argument("--openapi-path",       action="append", default=[], metavar="PATH",
                   help="Extra path(s) to probe for OpenAPI/Swagger/Postman spec")
    p.add_argument("--discovery-save",     default="",
                   help="Save deep-discovered endpoints JSON to this path")
    p.add_argument("--no-robots",          action="store_true",
                   help="Skip robots.txt / sitemap.xml parsing in deep discovery")
    p.add_argument("--no-js-ast",          action="store_true",
                   help="Skip JS AST pass (keep regex-only JS scan in smart_discover)")
    p.add_argument("--no-openapi",         action="store_true",
                   help="Skip OpenAPI/Swagger/Postman spec probing in deep discovery")
    p.add_argument("--no-version-permute", action="store_true",
                   help="Skip API version-shadow discovery in deep discovery pipeline")
    p.add_argument("--business-tags",      default="",
                   help="Comma-separated business context tags for wordlist seeding "
                        "(e.g. payment,order,user,subscription)")

    # ── Phase 3: Recon ────────────────────────────────────────────────────────
    p.add_argument("--recon",              action="store_true")
    p.add_argument("--recon-only",         action="store_true")
    p.add_argument("--js-secrets",         action="store_true")
    p.add_argument("--subdomain-size",     type=int,   default=50)
    p.add_argument("--strict-validation",  action="store_true")

    # ── Phase 1: Flows ────────────────────────────────────────────────────────
    p.add_argument("--flow",               action="append", default=[], metavar="TEMPLATE")
    p.add_argument("--flow-file",          default="")
    p.add_argument("--auto-flows",         action="store_true")
    p.add_argument("--product-id",         type=int,   default=1)
    p.add_argument("--product-price",      type=float, default=99.99)
    p.add_argument("--oauth-url",          default="")
    p.add_argument("--oauth-id",           default="")
    p.add_argument("--oauth-secret",       default="")
    p.add_argument("--oauth-grant",        default="client_credentials",
                   choices=["client_credentials", "password", "refresh_token"])
    p.add_argument("--oauth-user",         default="")
    p.add_argument("--oauth-pass",         default="")
    p.add_argument("--oauth-scope",        default="")
    p.add_argument("--refresh-url",        default="")
    p.add_argument("--refresh-token",      default="")
    p.add_argument("--login-url",          default="")
    p.add_argument("--login-body",         default="")
    p.add_argument("--blind-idor",         action="store_true")
    p.add_argument("--samples",            type=int,   default=4)

    # ── Phase 4: Attack Surface ───────────────────────────────────────────────
    p.add_argument("--idor-range",         type=int,   default=0)
    p.add_argument("--idor-harvest",       action="store_true")
    p.add_argument("--idor-cross-endpoint", action="store_true")
    p.add_argument("--idor-batch-size",    type=int,   default=20)
    p.add_argument("--websocket",          action="store_true")
    p.add_argument("--ws-url",             default="")
    p.add_argument("--ws-race-count",      type=int,   default=15)
    p.add_argument("--graphql-deep",       action="store_true")
    p.add_argument("--version-scan",       action="store_true")
    p.add_argument("--classify",           action="store_true")

    # ── Output ────────────────────────────────────────────────────────────────
    p.add_argument("-o",  "--output",      default=".",              help="Output directory")
    p.add_argument("--html",               action="store_true")
    p.add_argument("--json",               action="store_true")
    p.add_argument("--md",                 action="store_true")
    p.add_argument("-v",  "--verbose",     action="store_true")
    p.add_argument("--no-color",           action="store_true")

    return p.parse_args()


# ── Helper functions ──────────────────────────────────────────────────────────

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
        return data if isinstance(data, list) else ([data] if "steps" in data else [])
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
            token_url=args.oauth_url, client_id=args.oauth_id,
            client_secret=args.oauth_secret, grant_type=args.oauth_grant,
            username=args.oauth_user, password=args.oauth_pass,
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


def build_flow_configs(args, profile: dict) -> list:
    configs = []
    for name in args.flow:
        configs.append({"__template__": name})
    for flow_def in load_flow_file(args.flow_file):
        configs.append(flow_def)
    if not args.flow and not args.flow_file:
        for name in profile.get("flows", []):
            configs.append({"__template__": name})
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
                    if name == "ecommerce_checkout" else fn()
                )
                resolved.append(steps)
                print(f"[*] Flow template: {name}")
            except Exception as e:
                print(f"[!] Flow template error ({name}): {e}")
        else:
            resolved.append(fc)
    return resolved


def build_discovery_config(args, profile: dict):
    """Build a DiscoveryConfig from CLI args and profile settings."""
    try:
        from core.discovery.models import DiscoveryConfig
    except ImportError:
        return None

    prof_disc = profile.get("discovery", {})
    business_tags: list[str] = []
    if args.business_tags:
        business_tags = [t.strip() for t in args.business_tags.split(",") if t.strip()]
    elif prof_disc.get("business_tags"):
        business_tags = prof_disc["business_tags"]

    return DiscoveryConfig(
        subdomain_wordlist_size=args.subdomain_size,
        # Layer 2
        openapi_paths=args.openapi_path or prof_disc.get("openapi_paths", []),
        follow_js_imports=not args.no_js_ast,
        max_js_files=prof_disc.get("max_js_files", 30),
        graphql_deep=args.graphql_deep or prof_disc.get("graphql_deep", False),
        # Layer 4
        wordlist_depth=args.wordlist_depth,
        no_wordlist=args.no_wordlist or prof_disc.get("no_wordlist", False),
        business_tags=business_tags,
        # General
        auth_token=args.token,
        second_token=args.token2,
        timeout_s=args.timeout,
        verbose=args.verbose,
        save_discovery_path=args.discovery_save,
    )


def import_traffic(args) -> list[dict]:
    """Import endpoints from Burp/HAR/mitmproxy if flags are set."""
    imported: list[dict] = []

    try:
        from core.integrations.burp_importer import TrafficImporter
        importer = TrafficImporter(verbose=args.verbose)
    except ImportError:
        if any([args.import_burp, args.import_har, args.import_mitmproxy]):
            print("[!] Burp importer not available — check core/integrations/burp_importer.py")
        return []

    for import_path, flag_name in [
        (args.import_burp,       "Burp"),
        (args.import_har,        "HAR"),
        (args.import_mitmproxy,  "mitmproxy"),
    ]:
        if not import_path:
            continue
        result = importer.import_file(
            import_path,
            url_filter=args.import_filter if args.import_filter else None,
        )
        print(f"[+] {flag_name} import: {result.summary()}")
        imported.extend(result.endpoints)

        if args.import_save:
            importer.save(result.endpoints, args.import_save)

    return imported


# ── DB-only commands ──────────────────────────────────────────────────────────

async def cmd_show_history(args):
    """Print finding history from the database."""
    try:
        from core.storage.scan_database import ScanDatabase
    except ImportError:
        print("[!] ScanDatabase not available")
        return

    async with ScanDatabase(args.db) as db:
        stats = await db.get_stats(program=args.program)
        db.print_stats(stats)
        findings = await db.get_findings(
            program=args.program, limit=50
        )
        db.print_findings(findings)


async def cmd_search(args, query: str):
    """Search past findings."""
    try:
        from core.storage.scan_database import ScanDatabase
    except ImportError:
        print("[!] ScanDatabase not available")
        return

    async with ScanDatabase(args.db) as db:
        findings = await db.search(query)
        print(f"\n[*] Search results for '{query}': {len(findings)} findings\n")
        db.print_findings(findings)


async def cmd_export_h1(args):
    """Export all unreported findings to HackerOne."""
    if not args.h1_token:
        print("[!] --h1-token required for HackerOne export")
        return
    if not args.export_h1:
        print("[!] --export-h1 PROGRAM_HANDLE required")
        return

    try:
        from core.storage.scan_database import ScanDatabase
    except ImportError:
        print("[!] ScanDatabase not available")
        return

    async with ScanDatabase(args.db) as db:
        findings = await db.get_findings(
            program=args.program or args.export_h1,
            status="new",
        )
        print(f"[*] Exporting {len(findings)} new findings to HackerOne/{args.export_h1}...")
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
                print(f"  [!] Export failed ({f.title[:40]}): {e}")
        print(f"\n[+] Exported {success}/{len(findings)} findings to HackerOne")


# ── Recon-only ────────────────────────────────────────────────────────────────

async def run_recon_only(args):
    from urllib.parse import urlparse
    if not args.target:
        print("[!] --target required for recon")
        return

    target_domain = urlparse(args.target).netloc or args.target
    print(f"[*] BLFinder v3.1 Phase 5 — Recon: {target_domain}\n")

    try:
        import aiohttp
        session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False, limit=20),
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
            print(f"[*] Subdomains: {result.live_count} live, {result.api_count} API surface")
            for sub in result.subdomains:
                if sub.is_live:
                    print(f"  [{sub.priority:<8}] {sub.hostname:<40} score={sub.score}")
            os.makedirs(args.output, exist_ok=True)
            with open(f"{args.output}/targets.json", "w") as fh:
                json.dump(
                    [{"hostname": s.hostname, "priority": s.priority,
                      "score": s.score, "api_paths": s.api_paths}
                     for s in result.subdomains if s.is_live],
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


# ── Deep discovery runner ─────────────────────────────────────────────────────

async def run_deep_discovery(args, discovery_cfg, session) -> list[dict]:
    """
    Run the full multi-layer discovery pipeline and return a deduplicated
    list of endpoint dicts suitable for the scanner.

    Layer 1: robots.txt / sitemap.xml  (RobotsParser)
    Layer 2: JS AST endpoint extraction (JSASTParser)
    Layer 2: OpenAPI / Swagger / Postman spec probing (OpenAPIParser)
    Layer 4: Context-seeded wordlist probing (SmartWordlist)
    Layer 4: API version-shadow discovery (VersionPermuter)
    Layer 5: URL normalisation + dedup (normaliser)
    """
    if discovery_cfg is None:
        return []

    print("[*] Deep Discovery — running multi-layer pipeline...")

    discovered_paths: list[str] = []   # paths found so far, fed into wordlist
    all_endpoints: list = []           # DiscoveredEndpoint objects

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
            print(f"  [L1:robots]  {r1.summary()}")
            if r1.errors and args.verbose:
                for err in r1.errors[:3]:
                    print(f"    [!] {err}")
        except ImportError:
            if args.verbose:
                print("  [L1:robots]  not available — skipped")

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
            print(f"  [L2:js_ast]  {r2a.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L2:js_ast]  not available — skipped")

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
            print(f"  [L2:openapi] {r2b.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L2:openapi] not available — skipped")

    # ── Layer 4a: Smart wordlist probing ──────────────────────────────────────
    try:
        from core.discovery.layer4_wordlist.smart_wordlist import SmartWordlist

        # Collect baseline bodies from any existing session if available
        baseline_bodies: list[str] = []

        wl = SmartWordlist(verbose=args.verbose)
        r4a = await wl.run(
            target_url=args.target,
            session=session,
            config=discovery_cfg,
            auth_token=args.token,
            discovered_paths=list(set(discovered_paths)),
            baseline_bodies=baseline_bodies,
        )
        all_endpoints.extend(r4a.endpoints)
        print(f"  [L4:wordlist] {r4a.summary()}")
    except ImportError:
        if args.verbose:
            print("  [L4:wordlist] not available — skipped")

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
            print(f"  [L4:version] {r4b.summary()}")
        except ImportError:
            if args.verbose:
                print("  [L4:version] not available — skipped")

    # ── Layer 5: Normalise + dedup ────────────────────────────────────────────
    try:
        from core.discovery.layer5_dedup.normaliser import dedup_key, batch_normalise
        seen_keys: set[str] = set()
        unique_eps = []
        for ep in all_endpoints:
            k = dedup_key(ep.url, ep.method)
            if k not in seen_keys:
                seen_keys.add(k)
                unique_eps.append(ep)
        dedup_dropped = len(all_endpoints) - len(unique_eps)
        all_endpoints = unique_eps
        if dedup_dropped and args.verbose:
            print(f"  [L5:dedup]   removed {dedup_dropped} duplicate endpoints")
    except ImportError:
        pass

    # Convert DiscoveredEndpoint objects → plain dicts for the scanner
    result_dicts: list[dict] = []
    for ep in all_endpoints:
        result_dicts.append({
            "url":    ep.url,
            "method": ep.method,
            "body":   ep.body   if ep.body   else {},
            "params": ep.params if ep.params else {},
        })

    print(
        f"\n[*] Deep discovery complete: "
        f"{len(result_dicts)} unique endpoints found\n"
    )

    # Optionally save discovered endpoints
    save_path = getattr(discovery_cfg, "save_discovery_path", "") or args.discovery_save
    if save_path and result_dicts:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            with open(save_path, "w") as fh:
                json.dump(result_dicts, fh, indent=2)
            print(f"[+] Discovery results → {save_path}")
        except Exception as e:
            print(f"[!] Could not save discovery results: {e}")

    return result_dicts


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    args = parse_args()

    # ── DB-only commands (no scan needed) ─────────────────────────────────────
    if args.show_history:
        await cmd_show_history(args)
        return 0

    if args.search:
        await cmd_search(args, args.search)
        return 0

    if args.export_h1:
        await cmd_export_h1(args)
        return 0

    if args.recon_only:
        await run_recon_only(args)
        return 0

    # ── Require target for scanning ───────────────────────────────────────────
    if not args.target:
        print("[!] --target is required for scanning")
        print("[!] Use --show-history, --search, or --export-h1 for DB operations")
        return 1

    # ── Load profile ──────────────────────────────────────────────────────────
    profile: dict = {}
    if args.profile:
        profile = load_profile(args.profile)
        if not profile:
            print(f"[!] Continuing without profile")

    merged_settings = merge_profile_with_args(profile, args) if profile else {}

    # ── Import traffic ────────────────────────────────────────────────────────
    imported_endpoints = import_traffic(args)

    # ── Build discovery config (for deep discovery pipeline) ─────────────────
    discovery_cfg = build_discovery_config(args, profile)

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
        rate_limit=merged_settings.get("rate_limit", args.rate),
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        smart_discovery=not args.no_discover,
        fuzz_depth=merged_settings.get("fuzz_depth", args.fuzz_depth),
        output_dir=args.output,
        verbose=args.verbose,
        no_auth_check=True,
        min_confidence=merged_settings.get("min_confidence", args.min_confidence),
        confirmation_attempts=merged_settings.get("confirm_attempts", args.confirm_attempts),
    )

    # ── Apply all phase configs ───────────────────────────────────────────────

    # Phase 3
    config.run_recon              = args.recon or merged_settings.get("run_recon", False)
    config.run_subdomain_map      = config.run_recon
    config.run_js_extract         = args.js_secrets or merged_settings.get("js_secrets", False) or config.run_recon
    config.subdomain_wordlist_size = args.subdomain_size
    config.strict_validation      = args.strict_validation or merged_settings.get("strict_validation", False)

    # Phase 1: Flows
    raw_flow_configs = build_flow_configs(args, profile)
    resolved_flows   = resolve_flow_templates(raw_flow_configs, args)
    auto_flows       = args.auto_flows or profile.get("auto_flows", False)
    config.run_flows       = bool(resolved_flows) or auto_flows
    config.flow_configs    = resolved_flows
    config.auto_detect_flows = auto_flows
    config.product_id      = args.product_id
    config.product_price   = args.product_price
    config.oauth_config    = build_oauth_config(args)
    config.refresh_config  = build_refresh_config(args)
    config.oracle_samples  = args.samples

    # Phase 4
    prof_settings = profile.get("settings", {})
    config.idor_range          = args.idor_range or prof_settings.get("idor_range", 0)
    config.idor_harvest        = args.idor_harvest or prof_settings.get("idor_harvest", False)
    config.idor_cross_endpoint = args.idor_cross_endpoint or prof_settings.get("idor_cross_endpoint", False)
    config.idor_batch_size     = args.idor_batch_size
    config.run_websocket       = args.websocket or prof_settings.get("run_websocket", False)
    config.ws_url              = args.ws_url
    config.ws_race_count       = args.ws_race_count
    config.run_graphql_deep    = args.graphql_deep or prof_settings.get("run_graphql_deep", False)
    config.run_version_scan    = args.version_scan or prof_settings.get("run_version_scan", False)
    config.print_attack_plan   = args.classify

    # Phase 5 — database
    config.db_path     = args.db
    config.program     = args.program
    config.no_repeat   = args.no_repeat
    config.use_db      = bool(args.db) and args.db != "~/.blfinder.db" or args.program or args.no_repeat

    # Deep discovery config attached to scan config
    config.deep_discovery        = args.deep_discovery or merged_settings.get("deep_discovery", False)
    config.discovery_cfg         = discovery_cfg
    config.no_js_ast             = args.no_js_ast
    config.no_robots             = args.no_robots
    config.no_openapi            = args.no_openapi
    config.no_version_permute    = args.no_version_permute

    # ── Load endpoints ────────────────────────────────────────────────────────
    endpoints = load_endpoints(args.endpoints)
    endpoints.extend(imported_endpoints)

    if not endpoints:
        endpoints = [{"url": "/", "method": "GET", "body": {}, "params": {}}]
        if not args.recon:
            print("[*] No endpoints — using discovery")

    # ── Classify-only ─────────────────────────────────────────────────────────
    if args.classify:
        try:
            from core.intelligence.business_classifier import BusinessClassifier
            classifier = BusinessClassifier()
            plan       = classifier.build_plan(endpoints)
            plan.print_report(verbose=args.verbose)
        except ImportError:
            print("[!] Business classifier not available")
        if not args.target:
            return 0

    # ── Initialise database ───────────────────────────────────────────────────
    db = None
    scan_id = None
    if config.use_db:
        try:
            from core.storage.scan_database import ScanDatabase
            db = ScanDatabase(args.db)
            await db.init()
            scan_id = await db.start_scan(
                target=args.target, program=args.program,
                config={"profile": args.profile, "endpoints": len(endpoints)},
            )
            if args.program:
                await db.register_program(args.program)
            print(f"[*] Database: {args.db} (scan #{scan_id})")
        except Exception as e:
            print(f"[!] Database init failed: {e}")
            db = None

    # ── Run deep discovery pipeline (if requested) ────────────────────────────
    if config.deep_discovery and discovery_cfg is not None:
        try:
            import aiohttp
            disc_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(
                    ssl=not args.no_ssl_verify, limit=20
                ),
                timeout=aiohttp.ClientTimeout(total=args.timeout),
            )
            try:
                discovered = await run_deep_discovery(args, discovery_cfg, disc_session)
            finally:
                await disc_session.close()

            # Merge discovered endpoints (deduplicate by url+method)
            existing_keys = {
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
                print(f"[*] Deep discovery added {added} new endpoints")
        except ImportError:
            print("[!] aiohttp required for deep discovery")
        except Exception as e:
            print(f"[!] Deep discovery error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    # ── No-scan mode: discovery only ──────────────────────────────────────────
    if args.no_scan:
        os.makedirs(args.output, exist_ok=True)
        out_path = f"{args.output}/discovered_endpoints.json"
        with open(out_path, "w") as fh:
            json.dump(endpoints, fh, indent=2)
        print(f"[+] {len(endpoints)} endpoints saved → {out_path}")
        return 0

    # ── Run scanner ───────────────────────────────────────────────────────────
    findings = []

    async with BLFScanner(config) as scanner:
        # Apply profile to scanner
        if profile:
            scanner.apply_profile(profile)

        # Setup dashboard
        dashboard = None
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
                asyncio.create_task(dashboard.run())
                print("[*] Dashboard started (q to quit)")
            except ImportError:
                print("[!] Dashboard not available")

        try:
            findings = await scanner.run_all_modules(endpoints)
        finally:
            if dashboard:
                await dashboard.stop()

    # ── Save to database ──────────────────────────────────────────────────────
    if db and findings:
        new_count, dupe_count = await db.save_findings(
            findings, scan_id=scan_id, program=args.program or ""
        )
        await db.finish_scan(scan_id, finding_count=new_count)
        print(f"[*] Database: {new_count} new, {dupe_count} duplicates")

        if args.export_h1 and args.h1_token and new_count > 0:
            await cmd_export_h1(args)

        await db.close()

    # ── Generate reports ──────────────────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)
    cfg_dict = {"target_url": config.target_url}

    if not args.no_color:
        print_terminal_summary(findings, cfg_dict)
    else:
        print(f"\n[+] Scan complete. {len(findings)} findings.")

    if args.html or not (args.json or args.md):
        try:
            # Try the full evidence report first
            from core.reporting import EvidenceReportGenerator
            EvidenceReportGenerator().generate(
                findings, f"{args.output}/report.html", cfg_dict
            )
        except ImportError:
            try:
                # Fallback: evidence_report at its actual path
                from core.reporting.core.reporting.evidence_report import EvidenceReportGenerator
                EvidenceReportGenerator().generate(
                    findings, f"{args.output}/report.html", cfg_dict
                )
            except ImportError:
                generate_html_report(findings, cfg_dict, f"{args.output}/report.html")

    if args.json:
        generate_json_report(findings, cfg_dict, f"{args.output}/report.json")

    if args.md:
        generate_markdown_report(findings, cfg_dict, f"{args.output}/report.md")

    return 1 if any(f.severity.value == "CRITICAL" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
