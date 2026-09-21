"""
BLFinder v3.1 — core/discovery/engine.py
Deep Discovery Engine — orchestrator for all 5 layers.

Termux-safe: stdlib + aiohttp only.

Public API
----------
    engine = DeepDiscoveryEngine(session=session, verbose=True)
    queue  = await engine.discover(target_url, session, config)
    eps    = queue.to_endpoint_list()   # list[dict] for BLFScanner

Architecture
------------
Layer 1 — surface recon    (robots/sitemap — always)
Layer 2 — static analysis  (JS AST + OpenAPI — always)
Layer 3 — dynamic crawl    (headless — opt-in via config.use_headless)
Layer 4 — wordlist/permute (smart wordlist + version permuter — always)
Layer 5 — dedup + scoring  (normalise → soft-404 → score → enrich — always)

All layers run concurrently where safe:
  - Layers 1 and 2 run in parallel (both read-only, no dependencies)
  - Layer 4 uses output from Layers 1+2 for context seeding
  - Layer 3 (headless) runs independently, result merged before Layer 5
  - Layer 5 always runs last on the merged pool

Discovery config flags
----------------------
  config.use_headless      → enable Layer 3
  config.no_wordlist       → skip Layer 4 wordlist
  config.wordlist_depth    → 1-5 depth for wordlist
  config.include_versions  → version list for permuter
  config.save_discovery_path → save endpoint JSON to disk

Integration with scanner
------------------------
The existing BLFScanner.run_all_modules() calls this engine and gets back
a list[dict] in the exact format it already expects:
    [{"url": "...", "method": "GET", "body": {}, "params": {}, "_meta": {...}}]

The _meta key carries discovery context (tags, confidence, schema_hint, etc.)
which the scanner uses to prioritise its attack modules but ignores gracefully
if missing.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from .models import (
    DiscoveredEndpoint, DiscoveryConfig, EndpointQueue,
    LayerResult, SOURCE_SEED,
)
from .layer5_dedup.normaliser import normalise_url, dedup_key, extract_id_params
from .layer5_dedup.soft404_filter import Soft404Filter
from .layer5_dedup.scorer import score_and_sort, build_source_count_map
from .layer5_dedup.schema_enricher import SchemaEnricher


try:
    from .layer1_surface.robots_parser import RobotsParser
    _HAS_ROBOTS = True
except ImportError:
    _HAS_ROBOTS = False

try:
    from .layer2_static.js_ast_parser import JSASTParser
    _HAS_JS = True
except ImportError:
    _HAS_JS = False

try:
    from .layer2_static.openapi_parser import OpenAPIParser
    _HAS_OPENAPI = True
except ImportError:
    _HAS_OPENAPI = False

try:
    from .layer4_wordlist.smart_wordlist import SmartWordlist
    _HAS_WORDLIST = True
except ImportError:
    _HAS_WORDLIST = False

try:
    from .layer4_wordlist.version_permuter import VersionPermuter
    _HAS_VERSION = True
except ImportError:
    _HAS_VERSION = False

try:
    from .layer3_dynamic.headless_crawler import HeadlessCrawler
    _HAS_HEADLESS = True
except ImportError:
    _HAS_HEADLESS = False






def _seed_to_discovered(seed_list: list[dict], target_url: str) -> list[DiscoveredEndpoint]:
    """
    Convert user-supplied endpoint dicts (from -e or --import-burp) to
    DiscoveredEndpoints so they flow through the same scoring pipeline.
    """
    from urllib.parse import urljoin
    eps: list[DiscoveredEndpoint] = []
    for ep_dict in seed_list:
        url = ep_dict.get("url", "")
        if not url.startswith("http"):
            url = urljoin(target_url, url)
        method = ep_dict.get("method", "GET").upper()
        _, tmpl = normalise_url(url)
        ep = DiscoveredEndpoint(
            url=url, method=method,
            body=ep_dict.get("body", {}),
            params=ep_dict.get("params", {}),
            source=SOURCE_SEED,
            confidence=0.85,   
            priority=2,
            normalised_template=tmpl,
            id_params=extract_id_params(urlparse(url).path),
            spec_verified=False,
            live_verified=False,
        )
        eps.append(ep)
    return eps






class DeepDiscoveryEngine:
    """
    Orchestrates all discovery layers and returns a scored, deduplicated
    EndpointQueue ready for BLFScanner consumption.

    Usage:
        async with aiohttp.ClientSession() as session:
            engine = DeepDiscoveryEngine(verbose=True)
            queue  = await engine.discover(target, session, config)
            eps    = queue.to_endpoint_list()
    """

    def __init__(self, verbose: bool = False):
        self.verbose       = verbose
        self._layer_timing: dict[str, float] = {}

    async def discover(
        self,
        target_url:    str,
        session:       Any,
        config:        DiscoveryConfig,
        seed_endpoints: Optional[list[dict]] = None,
    ) -> EndpointQueue:
        """
        Run all discovery layers and return a scored EndpointQueue.

        Parameters
        ----------
        target_url:     base URL of the target
        session:        aiohttp.ClientSession (caller owns lifecycle)
        config:         DiscoveryConfig with all tuning knobs
        seed_endpoints: user-supplied endpoints (from -e / --import-burp)
        """
        grand_start = time.time()
        all_endpoints: list[DiscoveredEndpoint] = []

        print(f"[*] Deep Discovery Engine — target: {target_url}")


        if seed_endpoints:
            seeded = _seed_to_discovered(seed_endpoints, target_url)
            all_endpoints.extend(seeded)
            print(f"  [seed] {len(seeded)} user-supplied endpoints")


        layer12_tasks = []
        layer12_names = []

        if _HAS_ROBOTS:
            layer12_tasks.append(
                RobotsParser(verbose=self.verbose).run(
                    target_url, session, config, auth_token=config.auth_token
                )
            )
            layer12_names.append("robots")

        if _HAS_JS:
            layer12_tasks.append(
                JSASTParser(verbose=self.verbose).run(
                    target_url, session, config, auth_token=config.auth_token
                )
            )
            layer12_names.append("js")

        if _HAS_OPENAPI:
            layer12_tasks.append(
                OpenAPIParser(verbose=self.verbose).run(
                    target_url, session, config, auth_token=config.auth_token
                )
            )
            layer12_names.append("openapi")

        if layer12_tasks:
            t0       = time.time()
            results  = await asyncio.gather(*layer12_tasks, return_exceptions=True)
            elapsed  = time.time() - t0
            for name, result in zip(layer12_names, results):
                if isinstance(result, Exception):
                    print(f"  [!] Layer {name} error: {result}")
                    continue
                if isinstance(result, LayerResult):
                    all_endpoints.extend(result.endpoints)
                    self._layer_timing[name] = result.elapsed_s
                    if self.verbose or result.endpoints:
                        print(f"  {result.summary()}")


        if config.use_headless and _HAS_HEADLESS:
            t0 = time.time()
            try:
                crawler = HeadlessCrawler(verbose=self.verbose)
                h_result = await crawler.run(
                    target_url, config, auth_token=config.auth_token
                )
                all_endpoints.extend(h_result.endpoints)
                self._layer_timing["headless"] = time.time() - t0
                if self.verbose or h_result.endpoints:
                    print(f"  {h_result.summary()}")
            except Exception as e:
                print(f"  [!] Headless crawler error: {e}")
        elif config.use_headless and not _HAS_HEADLESS:
            print(
                "  [!] Headless crawl requested but playwright not installed.\n"
                "      Install: pip install playwright --break-system-packages\n"
                "               playwright install chromium"
            )



        discovered_paths = [
            urlparse(ep.url).path
            for ep in all_endpoints
            if ep.url.startswith("http")
        ]
        baseline_bodies: list[str] = []  

        layer4_tasks  = []
        layer4_names  = []

        if not config.no_wordlist and _HAS_WORDLIST:
            layer4_tasks.append(
                SmartWordlist(verbose=self.verbose).run(
                    target_url, session, config,
                    auth_token=config.auth_token,
                    discovered_paths=discovered_paths,
                    baseline_bodies=baseline_bodies,
                )
            )
            layer4_names.append("wordlist")

        if _HAS_VERSION:
            layer4_tasks.append(
                VersionPermuter(verbose=self.verbose).run(
                    target_url, session, config,
                    auth_token=config.auth_token,
                    known_endpoints=[
                        ep.url for ep in all_endpoints if ep.confidence >= 0.70
                    ],
                )
            )
            layer4_names.append("version")

        if layer4_tasks:
            results4 = await asyncio.gather(*layer4_tasks, return_exceptions=True)
            for name, result in zip(layer4_names, results4):
                if isinstance(result, Exception):
                    print(f"  [!] Layer4:{name} error: {result}")
                    continue
                if isinstance(result, LayerResult):
                    all_endpoints.extend(result.endpoints)
                    self._layer_timing[name] = result.elapsed_s
                    if self.verbose or result.endpoints:
                        print(f"  {result.summary()}")


        print(
            f"  [layer5] processing {len(all_endpoints)} raw endpoints..."
        )
        t0 = time.time()


        all_endpoints = _dedup(all_endpoints)
        print(f"  [layer5] after dedup: {len(all_endpoints)} unique endpoints")


        soft404 = Soft404Filter(verbose=self.verbose)
        await soft404.build_profile(target_url, session, config)
        kept, dropped = await soft404.filter_endpoints(
            all_endpoints, session, config
        )
        if dropped:
            print(f"  [layer5] soft-404 filter: dropped {len(dropped)}")
        all_endpoints = kept


        sc_map = build_source_count_map(all_endpoints)


        ca_domains: set[str] = set()
        for domain, profile in soft404._profiles.items():
            if profile.is_catch_all:
                ca_domains.add(domain)


        all_endpoints = score_and_sort(
            all_endpoints,
            source_count_map=sc_map,
            catch_all_domains=ca_domains,
        )


        enricher = SchemaEnricher(verbose=self.verbose)
        all_endpoints = await enricher.enrich(
            all_endpoints, session, config, auth_token=config.auth_token
        )

        self._layer_timing["layer5"] = time.time() - t0


        queue = EndpointQueue()
        for ep in all_endpoints:
            queue.push(ep)


        if config.save_discovery_path:
            self._save(all_endpoints, config.save_discovery_path)


        total_elapsed = time.time() - grand_start
        queue.print_stats()
        self._print_timing(total_elapsed)

        return queue





    def _save(self, endpoints: list[DiscoveredEndpoint], path: str) -> None:
        """Save discovered endpoints to JSON for reuse with --import-save."""
        try:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            data = []
            for ep in endpoints:
                data.append({
                    "url":    ep.url,
                    "method": ep.method,
                    "body":   ep.body,
                    "params": ep.params,
                    "_discovery": {
                        "source":     ep.source,
                        "confidence": round(ep.confidence, 3),
                        "priority":   ep.priority,
                        "tags":       ep.tags,
                        "spec_verified":  ep.spec_verified,
                        "live_verified":  ep.live_verified,
                        "schema_hint":    ep.schema_hint,
                    },
                })
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2)
            print(f"  [+] Discovery saved: {path} ({len(data)} endpoints)")
        except Exception as e:
            print(f"  [!] Failed to save discovery: {e}")

    def _print_timing(self, total: float) -> None:
        if not self.verbose:
            return
        print(f"\n  Discovery timing (total {total:.1f}s):")
        for layer, t in sorted(self._layer_timing.items(), key=lambda x: -x[1]):
            print(f"    {layer:<20} {t:.1f}s")






def _dedup(endpoints: list[DiscoveredEndpoint]) -> list[DiscoveredEndpoint]:
    """
    Deduplicate endpoints by (normalised_template, method).
    When duplicates exist, keep the one with the highest confidence.
    Merge tags and source info from all copies.
    """

    groups: dict[str, list[DiscoveredEndpoint]] = {}
    for ep in endpoints:
        _, tmpl = normalise_url(ep.url)
        ep.normalised_template = tmpl
        key = dedup_key(ep.url, ep.method)
        groups.setdefault(key, []).append(ep)

    result: list[DiscoveredEndpoint] = []
    for key, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue


        best = max(group, key=lambda e: e.confidence)


        all_tags:    set[str]   = set(best.tags)
        all_sources: list[str]  = [best.source]
        for other in group:
            if other is best:
                continue
            all_tags.update(other.tags)
            all_sources.append(other.source)

            if other.spec_verified:
                best.spec_verified = True
            if other.live_verified:
                best.live_verified = True

            if other.schema_hint and not best.schema_hint:
                best.schema_hint = other.schema_hint
            if other.body and not best.body:
                best.body = other.body

            for ip in other.id_params:
                if ip not in best.id_params:
                    best.id_params.append(ip)

        best.tags = list(all_tags)

        if len(all_sources) > 1:
            best.raw_source_evidence = (
                f"[{len(all_sources)} sources: "
                + ", ".join(sorted(set(all_sources)))
                + "] " + best.raw_source_evidence
            )

        result.append(best)

    return result
