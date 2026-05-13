"""
BLFinder v3.1 — core/discovery/layer5_dedup/scorer.py
Priority scoring + confidence adjustment engine.

Termux-safe: stdlib only. Pure functions, no I/O.

Scoring strategy (aligned with README attack prioritisation)
------------------------------------------------------------
Priority 1 (highest — scanned first):
  admin, internal, management, payment, transfer, withdraw

Priority 2:
  auth, order, user, checkout, account, session

Priority 3 (default):
  Everything else that passed FP filters

Priority 4:
  Wordlist-only finds with no spec/live verification

Priority 5 (scanned last):
  Low-confidence paths, debug endpoints with weak signals

Confidence adjustment
----------------------
The base confidence from each layer is adjusted up or down by the
following signals, capped at [0.10, 0.99]:

  +0.15  spec_verified (found in OpenAPI/Swagger spec)
  +0.15  live_verified (actually called during headless crawl)
  +0.10  soft-404 filter passed (from Soft404Filter.check)
  +0.08  body schema available (schema_hint is non-empty)
  +0.05  found by multiple independent sources
  +0.05  has id_params (IDOR attack surface)
  -0.10  wordlist-only source with no corroboration
  -0.15  environment/debug tag (dev, test, qa, staging)
  -0.20  is_catch_all domain (server returns 200 for everything)
"""

from __future__ import annotations

from ..models import DiscoveredEndpoint, SOURCE_WORDLIST


# ─────────────────────────────────────────────────────────────────────────────
# Tag → priority maps
# ─────────────────────────────────────────────────────────────────────────────

_PRIORITY_1_TAGS = frozenset({
    "admin", "payment", "transfer", "withdraw", "internal",
    "management", "billing", "fintech",
})
_PRIORITY_2_TAGS = frozenset({
    "auth", "order", "user", "checkout", "account", "session",
    "product", "subscription",
})
_PRIORITY_4_TAGS = frozenset({
    "debug", "metrics", "actuator", "test", "staging",
    "dev", "qa", "uat",
})

# Source layers ordered by inherent reliability
_SOURCE_RELIABILITY: dict[str, float] = {
    "layer2:openapi":    0.95,
    "layer3:headless":   0.90,
    "layer3:auth_replay": 0.90,
    "layer3:spa":        0.85,
    "layer3:websocket":  0.80,
    "layer2:graphql":    0.85,
    "layer2:js_ast":     0.80,
    "layer2:js_regex":   0.70,
    "layer1:robots":     0.75,
    "layer4:version":    0.70,
    "layer4:method_fuzz": 0.65,
    "layer4:wordlist":   0.60,
    "layer1:dns":        0.60,
    "layer4:param_expand": 0.60,
    "seed":              0.50,
}


def compute_priority(ep: DiscoveredEndpoint) -> int:
    """
    Compute the scan priority (1=highest … 5=lowest) for an endpoint.
    Lower number = scanned sooner = higher attack value.
    """
    tags = set(ep.tags)

    # Priority 1 overrides
    if tags & _PRIORITY_1_TAGS:
        return 1

    # Auth-bypass confirmed by version permuter
    if ep.confidence >= 0.88 and "version" in ep.source:
        return 1

    # Spec-verified POST/PUT/PATCH with a body schema → high attack value
    if ep.spec_verified and ep.method in ("POST", "PUT", "PATCH") and ep.schema_hint:
        return 1

    # Priority 2
    if tags & _PRIORITY_2_TAGS:
        return 2

    # Any endpoint with ID params is high IDOR value
    if ep.id_params and ep.confidence >= 0.75:
        return 2

    # Live-verified (headless saw it being called)
    if ep.live_verified:
        return 2

    # Priority 4 — noise/debug
    if tags & _PRIORITY_4_TAGS and not ep.spec_verified:
        return 4

    # Wordlist-only low-confidence paths
    if ep.source == SOURCE_WORDLIST and ep.confidence < 0.65:
        return 4

    return 3


def adjust_confidence(
    ep:               DiscoveredEndpoint,
    source_count:     int   = 1,    # how many layers independently found this
    soft404_boost:    float = 0.0,  # from Soft404Filter.check()
    is_catch_all_domain: bool = False,
) -> float:
    """
    Adjust an endpoint's confidence score based on corroborating signals.
    Returns clamped float in [0.10, 0.99].
    """
    score = _SOURCE_RELIABILITY.get(ep.source, ep.confidence)

    if ep.spec_verified:
        score += 0.15
    if ep.live_verified:
        score += 0.15

    score += soft404_boost   # +0.10 when soft-404 filter passes on 200

    if ep.schema_hint:
        score += 0.08

    if source_count >= 2:
        score += 0.05

    if ep.id_params:
        score += 0.05

    # Penalties
    if ep.source == SOURCE_WORDLIST and source_count == 1:
        score -= 0.10
    if set(ep.tags) & _PRIORITY_4_TAGS and not ep.spec_verified:
        score -= 0.15
    if is_catch_all_domain and not ep.spec_verified and not ep.live_verified:
        score -= 0.20

    return max(0.10, min(0.99, score))


def score_and_sort(
    endpoints:          list[DiscoveredEndpoint],
    source_count_map:   Optional[dict[str, int]]  = None,
    soft404_boost_map:  Optional[dict[str, float]] = None,
    catch_all_domains:  Optional[set[str]]         = None,
) -> list[DiscoveredEndpoint]:
    """
    Score every endpoint, set .priority and .confidence, sort highest-first.

    source_count_map:  normalised_template → number of sources that found it
    soft404_boost_map: normalised_template → boost from Soft404Filter
    catch_all_domains: set of domain strings with catch-all behaviour
    """
    sc_map  = source_count_map  or {}
    sf_map  = soft404_boost_map or {}
    ca_doms = catch_all_domains or set()

    from urllib.parse import urlparse

    for ep in endpoints:
        key  = ep.normalised_template or ep.url
        dom  = urlparse(ep.url).netloc

        ep.confidence = adjust_confidence(
            ep,
            source_count=sc_map.get(key, 1),
            soft404_boost=sf_map.get(key, 0.0),
            is_catch_all_domain=(dom in ca_doms),
        )
        ep.priority = compute_priority(ep)

    # Sort: priority asc, then confidence desc
    endpoints.sort(key=lambda e: (e.priority, -e.confidence))
    return endpoints


def build_source_count_map(
    all_endpoints: list[DiscoveredEndpoint],
) -> dict[str, int]:
    """
    Count how many independent sources found each normalised endpoint template.
    Used to boost confidence for multiply-corroborated endpoints.
    """
    counts: dict[str, set[str]] = {}
    for ep in all_endpoints:
        key = ep.normalised_template or ep.url
        if key not in counts:
            counts[key] = set()
        counts[key].add(ep.source)
    return {k: len(v) for k, v in counts.items()}


# Allow Optional import without circular issues
from typing import Optional
