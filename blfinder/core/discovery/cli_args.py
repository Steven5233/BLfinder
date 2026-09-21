"""
BLFinder v3.1 — core/discovery/cli_args.py
New CLI argument definitions + ScanConfig population for the deep discovery
engine. Import this from blfinder.py to add the new flags cleanly.

Usage in blfinder.py:
─────────────────────
    from core.discovery.cli_args import add_discovery_args, apply_discovery_args

    # Inside parse_args():
    add_discovery_args(p)     # p is the argparse.ArgumentParser

    # Inside main(), after config is built:
    apply_discovery_args(args, config)

That's the complete integration. No other changes to blfinder.py are needed.
"""

from __future__ import annotations

import argparse
from typing import Any






def add_discovery_args(parser: argparse.ArgumentParser) -> None:
    """
    Add all deep discovery flags to an existing ArgumentParser.
    Call this inside parse_args() after the existing argument definitions.
    """
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
        action="store_true",
        dest="use_headless",
        help=(
            "Enable Playwright headless browser crawl.\n"
            "Intercepts all XHR/fetch calls the SPA makes during navigation.\n"
            "Finds endpoints invisible to static analysis (dynamic URL builders).\n"
            "Requires: pip install playwright --break-system-packages\n"
            "          playwright install chromium\n"
            "Note: Chromium requires ~300MB on Termux storage."
        ),
    )

    grp.add_argument(
        "--headless-interact",
        action="store_true",
        dest="headless_interact",
        help=(
            "Click buttons and submit forms during headless crawl.\n"
            "Triggers API calls only reachable via UI interactions\n"
            "(tabs, load-more buttons, dropdown menus, wizards).\n"
            "Use with --use-headless."
        ),
    )

    grp.add_argument(
        "--openapi-path",
        action="append", default=[], dest="openapi_paths",
        metavar="PATH",
        help=(
            "Explicit OpenAPI/Swagger spec path to parse (repeatable).\n"
            "In addition to the 30+ well-known paths probed automatically.\n"
            "Example: --openapi-path /api/v1/openapi.json\n"
            "         --openapi-path /internal/swagger.yaml\n"
            "         --openapi-path /postman_collection.json"
        ),
    )

    grp.add_argument(
        "--proto-path",
        action="append", default=[], dest="proto_paths",
        metavar="FILE",
        help=(
            "Local .proto file for gRPC endpoint extraction (repeatable).\n"
            "Extracts service/method definitions as REST-equivalent endpoints.\n"
            "Example: --proto-path ./protos/user_service.proto"
        ),
    )

    grp.add_argument(
        "--discovery-tags",
        default="", metavar="TAGS",
        dest="discovery_tags",
        help=(
            "Comma-separated business tags to seed the discovery wordlist.\n"
            "Adds tag-specific path segments to the wordlist.\n"
            "Available: payment, order, admin, user, auth, fintech, product,\n"
            "           transfer, report\n"
            "Example: --discovery-tags payment,order,admin\n"
            "Tip: Profiles (--profile ecommerce) set this automatically."
        ),
    )

    grp.add_argument(
        "--no-wordlist",
        action="store_true",
        dest="no_wordlist",
        help=(
            "Disable wordlist-based path discovery.\n"
            "Use only spec/JS/headless sources (fewer requests, no brute-force).\n"
            "Combine with --openapi-path or --import-burp for precise coverage."
        ),
    )

    grp.add_argument(
        "--save-discovery",
        default="", metavar="FILE",
        dest="save_discovery",
        help=(
            "Save all discovered endpoints to a JSON file before scanning.\n"
            "Useful for reviewing what was found or reusing with -e flag.\n"
            "Example: --save-discovery ~/discovered_endpoints.json"
        ),
    )

    grp.add_argument(
        "--no-deep-discovery",
        action="store_true",
        dest="no_deep_discovery",
        help=(
            "Disable the deep discovery engine entirely.\n"
            "Falls back to the original smart_discover() regex crawl.\n"
            "Use when the target is very slow or discovery is causing 429s."
        ),
    )






def apply_discovery_args(args: argparse.Namespace, config: Any) -> None:
    """
    Copy discovery-related argparse values onto the ScanConfig object.
    Call this in main() after building the ScanConfig.

    config: the ScanConfig instance (any object with __setattr__)
    """
    config.discovery_depth   = getattr(args, "discovery_depth",   2)
    config.use_headless       = getattr(args, "use_headless",      False)
    config.headless_interact  = getattr(args, "headless_interact", False)
    config.openapi_paths      = getattr(args, "openapi_paths",     [])
    config.proto_paths        = getattr(args, "proto_paths",       [])
    config.no_wordlist        = getattr(args, "no_wordlist",       False)
    config.save_discovery     = getattr(args, "save_discovery",    "")
    config.no_deep_discovery  = getattr(args, "no_deep_discovery", False)


    raw_tags = getattr(args, "discovery_tags", "")
    if isinstance(raw_tags, str):
        config.discovery_tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
    elif isinstance(raw_tags, list):
        config.discovery_tags = raw_tags
    else:
        config.discovery_tags = []


    if not getattr(config, "smart_discovery", True):
        config.no_deep_discovery = True






def apply_profile_discovery(profile: dict, args: argparse.Namespace, config: Any) -> None:
    """
    Apply profile-level discovery settings to config.
    CLI args take priority; profile only fills in what the CLI left at default.

    Call AFTER apply_discovery_args().
    """
    if not profile:
        return

    settings = profile.get("settings", {})


    if settings.get("discovery_depth") and getattr(args, "discovery_depth", 2) == 2:
        config.discovery_depth = settings["discovery_depth"]


    if settings.get("business_tags") and not config.discovery_tags:
        config.discovery_tags = settings["business_tags"]


    if settings.get("no_wordlist") and not config.no_wordlist:
        config.no_wordlist = True


    if settings.get("use_headless") and not getattr(args, "no_deep_discovery", False):
        config.use_headless = True






INTEGRATION_SNIPPET = '''
# ── Add to parse_args() in blfinder.py ────────────────────────────────────────
from core.discovery.cli_args import add_discovery_args
# ... inside parse_args():
add_discovery_args(p)

# ── Add to main() in blfinder.py, after config is built ───────────────────────
from core.discovery.cli_args import apply_discovery_args, apply_profile_discovery
apply_discovery_args(args, config)
apply_profile_discovery(profile, args, config)   # profile dict from load_profile()

# ── Add to main() in blfinder.py, before BLFScanner context manager ───────────
if not getattr(config, "no_deep_discovery", False):
    from core.discovery.scanner_patch import apply_patch
    apply_patch()   # monkey-patches BLFScanner.run_all_modules()
'''

if __name__ == "__main__":
    print(INTEGRATION_SNIPPET)
