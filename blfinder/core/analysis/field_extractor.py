"""
BLFinder v3.0 — core/analysis/field_extractor.py
Volatile Field Extractor & Response Normalizer

Learns which fields in a target's responses are volatile (change every
request) vs stable (meaningful data). Uses statistical sampling across
multiple requests to the same endpoint to build a volatile field map.

This is what allows semantic_diff.py to know WHICH fields to ignore
on a per-target, per-endpoint basis — rather than relying on a static list.
"""

from __future__ import annotations

import json
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FieldProfile:
    """Statistical profile of a single field across multiple observations."""
    name: str
    path: str                          
    observed_values: list = field(default_factory=list)
    unique_count: int = 0
    is_volatile: bool = False          
    is_stable: bool = False            
    is_sequential: bool = False        
    is_temporal: bool = False          
    is_identifier: bool = False        
    value_type: str = "unknown"        
    sample_values: list = field(default_factory=list)  
    volatility_score: float = 0.0     


class VolatileFieldExtractor:
    """
    Extracts and classifies volatile fields from a set of response samples.

    Usage:
        extractor = VolatileFieldExtractor()
        
        # Feed multiple responses from the same endpoint
        for body in response_samples:
            extractor.observe(body, endpoint="/api/users/me")
        
        # Get volatile field names for this endpoint
        volatile = extractor.get_volatile_fields("/api/users/me")
        # → ["timestamp", "request_id", "expires_at", "session_token"]
    """


    TIMESTAMP_PATTERNS = [
        re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', re.I),    
        re.compile(r'^\d{10}$'),                                             
        re.compile(r'^\d{13}$'),                                             
        re.compile(r'\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}'),        
    ]


    IDENTIFIER_PATTERNS = [
        re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),  
        re.compile(r'^[0-9a-f]{32,64}$', re.I),        
        re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),     
        re.compile(r'^[A-Za-z0-9_-]{20,}$'),            
    ]


    VOLATILE_NAME_PATTERNS = [
        re.compile(r'.*_at$', re.I),
        re.compile(r'.*_time$', re.I),
        re.compile(r'.*_date$', re.I),
        re.compile(r'^timestamp$', re.I),
        re.compile(r'^nonce$', re.I),
        re.compile(r'^request_id$', re.I),
        re.compile(r'^trace_id$', re.I),
        re.compile(r'^correlation_id$', re.I),
        re.compile(r'^jti$', re.I),
        re.compile(r'^etag$', re.I),
        re.compile(r'^age$', re.I),
        re.compile(r'^x-request-id$', re.I),
        re.compile(r'^cf-ray$', re.I),
        re.compile(r'^session_id$', re.I),
    ]

    def __init__(self):

        self._profiles: dict[str, dict[str, FieldProfile]] = defaultdict(dict)

        self._global_volatile: set[str] = set()

    def observe(self, body: str, endpoint: str = "_global"):
        """
        Record a single response observation for an endpoint.
        Call this multiple times with different responses from the same endpoint.
        """
        data = self._safe_parse(body)
        if data is None:
            return
        self._walk_and_record(data, endpoint, prefix="")

    def get_volatile_fields(self, endpoint: str = "_global") -> list[str]:
        """
        Return field paths that are volatile for this endpoint.
        Includes both endpoint-specific and global findings.
        """
        profiles = self._profiles.get(endpoint, {})
        volatile = [
            path for path, prof in profiles.items()
            if prof.is_volatile or prof.volatility_score > 0.7
        ]
        return list(set(volatile) | self._global_volatile)

    def get_stable_fields(self, endpoint: str = "_global") -> list[str]:
        """Return field paths that are stable (same across all observations)."""
        profiles = self._profiles.get(endpoint, {})
        return [
            path for path, prof in profiles.items()
            if prof.is_stable and not prof.is_volatile
        ]

    def get_field_profile(self, field_path: str, endpoint: str = "_global") -> FieldProfile | None:
        return self._profiles.get(endpoint, {}).get(field_path)

    def analyze(self, endpoint: str = "_global"):
        """
        Run full volatility analysis for an endpoint after observations are complete.
        Call this once after feeding all response samples.
        """
        profiles = self._profiles.get(endpoint, {})
        for path, prof in profiles.items():
            self._classify_field(prof)
            if prof.is_volatile:

                leaf_name = path.split(".")[-1]
                self._global_volatile.add(leaf_name)

    def is_volatile(self, field_name: str, endpoint: str = "_global") -> bool:
        """Quick check: is this field name volatile?"""

        if any(p.match(field_name) for p in self.VOLATILE_NAME_PATTERNS):
            return True

        if field_name in self._global_volatile:
            return True

        profiles = self._profiles.get(endpoint, {})
        if field_name in profiles:
            return profiles[field_name].is_volatile
        return False

    def normalize_for_compare(self, body: str, endpoint: str = "_global") -> dict:
        """
        Parse a response body and strip all volatile fields.
        Returns a clean dict suitable for stable comparison.
        """
        data = self._safe_parse(body)
        if data is None:
            return {}
        volatile_fields = set(self.get_volatile_fields(endpoint))
        return self._strip_volatile_recursive(data, volatile_fields)



    def _walk_and_record(self, obj: Any, endpoint: str, prefix: str):
        """Recursively walk a JSON object and record field values."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                self._record_value(endpoint, path, key, value)

                if isinstance(value, (dict, list)) and prefix.count(".") < 5:
                    self._walk_and_record(value, endpoint, path)
        elif isinstance(obj, list) and obj:

            if isinstance(obj[0], dict):
                self._walk_and_record(obj[0], endpoint, f"{prefix}[0]")

    def _record_value(self, endpoint: str, path: str, key: str, value: Any):
        """Record a single field observation."""
        if path not in self._profiles[endpoint]:
            self._profiles[endpoint][path] = FieldProfile(name=key, path=path)

        prof = self._profiles[endpoint][path]
        str_val = str(value)
        prof.observed_values.append(str_val)


        if len(prof.observed_values) > 20:
            prof.observed_values = prof.observed_values[-20:]


        if isinstance(value, bool):
            prof.value_type = "boolean"
        elif isinstance(value, int):
            prof.value_type = "integer"
        elif isinstance(value, float):
            prof.value_type = "float"
        elif value is None:
            prof.value_type = "null"
        else:
            prof.value_type = "string"


        if str_val not in prof.sample_values and len(prof.sample_values) < 3:
            prof.sample_values.append(str_val)

    def _classify_field(self, prof: FieldProfile):
        """Classify a field's volatility based on its observation history."""
        if len(prof.observed_values) < 2:
            prof.is_stable = True
            return

        unique_vals = set(prof.observed_values)
        prof.unique_count = len(unique_vals)
        total = len(prof.observed_values)


        prof.volatility_score = len(unique_vals) / total


        if any(p.match(prof.name) for p in self.VOLATILE_NAME_PATTERNS):
            prof.is_volatile = True
            prof.volatility_score = 1.0
            return


        if len(unique_vals) == 1:
            prof.is_stable = True
            prof.volatility_score = 0.0
            return


        if len(unique_vals) == total:
            prof.is_volatile = True


        for val in list(unique_vals)[:5]:
            if any(p.search(val) for p in self.TIMESTAMP_PATTERNS):
                prof.is_temporal = True
                prof.is_volatile = True
                break


        for val in list(unique_vals)[:5]:
            if any(p.match(val) for p in self.IDENTIFIER_PATTERNS):
                prof.is_identifier = True
                prof.is_volatile = True
                break


        if prof.value_type == "integer":
            try:
                int_vals = [int(v) for v in prof.observed_values]
                diffs = [int_vals[i+1] - int_vals[i] for i in range(len(int_vals)-1)]
                if all(d > 0 for d in diffs):
                    prof.is_sequential = True
                    prof.is_volatile = True
            except (ValueError, TypeError):
                pass


        if prof.value_type == "string" and len(unique_vals) > 1:
            avg_len = statistics.mean(len(v) for v in unique_vals)
            if avg_len > 16:

                sample = list(unique_vals)[0]
                entropy = self._string_entropy(sample)
                if entropy > 4.0:  
                    prof.is_identifier = True
                    prof.is_volatile = True

    def _string_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = defaultdict(int)
        for ch in s:
            freq[ch] += 1
        import math
        return -sum(
            (count / len(s)) * math.log2(count / len(s))
            for count in freq.values()
        )

    def _strip_volatile_recursive(self, obj: Any, volatile_fields: set[str]) -> Any:
        """Strip volatile fields recursively."""
        if isinstance(obj, dict):
            return {
                k: self._strip_volatile_recursive(v, volatile_fields)
                for k, v in obj.items()
                if k not in volatile_fields and not any(
                    p.match(k) for p in self.VOLATILE_NAME_PATTERNS
                )
            }
        elif isinstance(obj, list):
            return [self._strip_volatile_recursive(item, volatile_fields) for item in obj]
        return obj

    @staticmethod
    def _safe_parse(body: str) -> Any | None:
        if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
            return None
        try:
            return json.loads(body.strip())
        except (json.JSONDecodeError, ValueError):
            return None


def build_volatile_map(
    responses: list[str],
    endpoint: str = "_global"
) -> VolatileFieldExtractor:
    """
    Convenience function: feed a list of response bodies and get back
    a configured extractor with volatility analysis complete.

    Usage:
        extractor = build_volatile_map(responses, "/api/users/me")
        volatile = extractor.get_volatile_fields("/api/users/me")
    """
    extractor = VolatileFieldExtractor()
    for body in responses:
        extractor.observe(body, endpoint)
    extractor.analyze(endpoint)
    return extractor
