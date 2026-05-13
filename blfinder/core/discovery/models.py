"""
BLFinder v3.1 — core/discovery/models.py
Deep Discovery Engine: shared data models.

Termux-safe: stdlib only, no C extensions.
"""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Discovery source labels ───────────────────────────────────────────────────
SOURCE_DNS          = "layer1:dns"
SOURCE_ROBOTS       = "layer1:robots"
SOURCE_SHODAN       = "layer1:shodan"
SOURCE_JS_REGEX     = "layer2:js_regex"
SOURCE_JS_AST       = "layer2:js_ast"
SOURCE_OPENAPI      = "layer2:openapi"
SOURCE_GRAPHQL      = "layer2:graphql"
SOURCE_PROTO        = "layer2:proto"
SOURCE_HEADLESS     = "layer3:headless"
SOURCE_SPA          = "layer3:spa"
SOURCE_AUTH_REPLAY  = "layer3:auth_replay"
SOURCE_WS           = "layer3:websocket"
SOURCE_WORDLIST     = "layer4:wordlist"
SOURCE_VERSION      = "layer4:version"
SOURCE_METHOD_FUZZ  = "layer4:method_fuzz"
SOURCE_PARAM_EXPAND = "layer4:param_expand"
SOURCE_SEED         = "seed"


# ── Core endpoint model ───────────────────────────────────────────────────────
@dataclass
class DiscoveredEndpoint:
    """
    A single endpoint found by any discovery layer.

    Fields are designed so the existing scanner can consume them directly:
    url, method, body, params map 1:1 to the scanner's endpoint dict format.
    Extra fields (confidence, priority, tags, …) drive the scoring/ordering
    step and are stripped before the scanner receives the list.
    """
    url:                str
    method:             str                  = "GET"
    body:               dict                 = field(default_factory=dict)
    params:             dict                 = field(default_factory=dict)
    headers:            dict                 = field(default_factory=dict)
    source:             str                  = SOURCE_SEED

    # Scoring
    confidence:         float                = 0.5   # 0.0–1.0
    priority:           int                  = 3     # 1 (high) – 5 (low)

    # Metadata
    auth_required:      bool                 = True
    schema_hint:        dict                 = field(default_factory=dict)
    id_params:          list[str]            = field(default_factory=list)
    version:            str                  = ""    # "v1", "v2", "internal", …
    tags:               list[str]            = field(default_factory=list)
    raw_source_evidence: str                 = ""    # where it was found
    normalised_template: str                 = ""    # /orders/{id}/items/{id}
    http_methods_allowed: list[str]          = field(default_factory=list)
    discovered_at:      float                = field(default_factory=time.time)

    # FP-reduction signals (populated by layer5 enricher)
    spec_verified:      bool                 = False  # found in an API spec
    live_verified:      bool                 = False  # actually called in headless
    response_hint:      Optional[dict]       = None   # sample response shape

    # Priority heap support: lower number = higher priority
    def __lt__(self, other: "DiscoveredEndpoint") -> bool:
        return self.priority < other.priority

    def to_scanner_dict(self) -> dict:
        """Return the dict format expected by BLFScanner._run_endpoint_checks."""
        return {
            "url":     self.url,
            "method":  self.method,
            "body":    self.body,
            "params":  self.params,
            # Pass extra context the scanner can use for smarter fuzzing
            "_meta": {
                "source":       self.source,
                "confidence":   self.confidence,
                "tags":         self.tags,
                "id_params":    self.id_params,
                "schema_hint":  self.schema_hint,
                "spec_verified": self.spec_verified,
                "live_verified": self.live_verified,
            },
        }


# ── Priority queue of discovered endpoints ────────────────────────────────────
class EndpointQueue:
    """
    Min-heap of DiscoveredEndpoints ordered by priority (1=highest).
    Deduplication is enforced by normalised_template + method.
    """

    def __init__(self):
        self._heap:    list[DiscoveredEndpoint] = []
        self._seen:    set[str]                 = set()   # (template, method)
        self._all:     list[DiscoveredEndpoint] = []

    def push(self, ep: DiscoveredEndpoint) -> bool:
        """
        Add endpoint to queue. Returns True if added, False if duplicate.
        Uses normalised_template for dedup so /orders/123 and /orders/456
        are treated as the same endpoint.
        """
        key = f"{ep.normalised_template or ep.url}|{ep.method.upper()}"
        if key in self._seen:
            return False
        self._seen.add(key)
        heapq.heappush(self._heap, ep)
        self._all.append(ep)
        return True

    def pop(self) -> Optional[DiscoveredEndpoint]:
        if self._heap:
            return heapq.heappop(self._heap)
        return None

    def __len__(self) -> int:
        return len(self._heap)

    def __bool__(self) -> bool:
        return bool(self._heap)

    @property
    def total(self) -> int:
        return len(self._all)

    def to_endpoint_list(self) -> list[dict]:
        """
        Return all endpoints as scanner-compatible dicts, highest priority first.
        This is the output consumed by BLFScanner.run_all_modules().
        """
        sorted_eps = sorted(self._all, key=lambda e: e.priority)
        return [ep.to_scanner_dict() for ep in sorted_eps]

    def stats(self) -> dict:
        by_source: dict[str, int] = {}
        by_tag:    dict[str, int] = {}
        for ep in self._all:
            by_source[ep.source] = by_source.get(ep.source, 0) + 1
            for t in ep.tags:
                by_tag[t] = by_tag.get(t, 0) + 1
        return {
            "total":      len(self._all),
            "by_source":  by_source,
            "by_tag":     by_tag,
            "spec_verified":  sum(1 for e in self._all if e.spec_verified),
            "live_verified":  sum(1 for e in self._all if e.live_verified),
            "high_priority":  sum(1 for e in self._all if e.priority <= 2),
        }

    def print_stats(self):
        s = self.stats()
        print(f"\n[*] Discovery complete: {s['total']} unique endpoints")
        print(f"    Spec-verified : {s['spec_verified']}")
        print(f"    Live-verified : {s['live_verified']}")
        print(f"    High-priority : {s['high_priority']}")
        print(f"    By source:")
        for src, cnt in sorted(s["by_source"].items(), key=lambda x: -x[1]):
            print(f"      {src:<30} {cnt}")


# ── Per-layer result containers ───────────────────────────────────────────────
@dataclass
class LayerResult:
    """Returned by every layer's run() method."""
    layer:      str
    endpoints:  list[DiscoveredEndpoint] = field(default_factory=list)
    errors:     list[str]                = field(default_factory=list)
    elapsed_s:  float                    = 0.0

    def summary(self) -> str:
        return (
            f"[{self.layer}] {len(self.endpoints)} endpoints "
            f"in {self.elapsed_s:.1f}s"
            + (f" ({len(self.errors)} errors)" if self.errors else "")
        )


# ── Discovery config ──────────────────────────────────────────────────────────
@dataclass
class DiscoveryConfig:
    """
    All knobs for the deep discovery pipeline.
    Defaults are chosen to work on Termux with no external deps.
    """
    # Layer 1
    subdomain_wordlist_size: int          = 50
    use_shodan:               bool        = False
    shodan_key:               str         = ""

    # Layer 2
    openapi_paths:            list[str]   = field(default_factory=list)
    proto_paths:              list[str]   = field(default_factory=list)
    follow_js_imports:        bool        = True
    max_js_files:             int         = 30
    graphql_deep:             bool        = False

    # Layer 3 (headless — requires playwright, opt-in)
    use_headless:             bool        = False
    headless_interact:        bool        = False   # click buttons / submit forms
    headless_timeout_s:       int         = 30

    # Layer 4
    wordlist_depth:           int         = 2       # 1=tiny … 5=exhaustive
    include_versions:         list[str]   = field(
        default_factory=lambda: ["v1", "v2", "v3", "internal", "legacy", "beta"]
    )
    business_tags:            list[str]   = field(default_factory=list)
    no_wordlist:              bool        = False

    # General
    auth_token:               str         = ""
    second_token:             str         = ""
    max_depth:                int         = 4       # link-following depth
    timeout_s:                int         = 15
    verbose:                  bool        = False
    save_discovery_path:      str         = ""      # if set, dump JSON here
