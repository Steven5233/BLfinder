"""
BLFinder v3.0 — core/analysis/semantic_diff.py
JSON-aware Semantic Diff Engine

Replaces naive difflib string comparison with deep structural analysis.
Understands the difference between noise (timestamps, nonces) and
real data changes (user_id, email, role) — eliminating the #1 source
of false positives and false negatives in v2.1.
"""

from __future__ import annotations

import json
import re
import difflib
import hashlib
from dataclasses import dataclass, field
from typing import Any
from .field_extractor import VolatileFieldExtractor
from ..response_heuristics import looks_like_error


@dataclass
class DiffResult:
    """
    Result of a semantic comparison between two API responses.
    All fields are populated even on error — never raises.
    """

    is_different: bool = False          
    structural_change: bool = False     
    value_changes: dict = field(default_factory=dict)   
    new_keys: list[str] = field(default_factory=list)   
    removed_keys: list[str] = field(default_factory=list)  


    volatile_fields_ignored: list[str] = field(default_factory=list)   
    sensitive_changes: list[str] = field(default_factory=list)          
    privileged_changes: list[str] = field(default_factory=list)         


    semantic_similarity: float = 1.0   
    raw_similarity: float = 1.0        
    noise_ratio: float = 0.0           


    size_a: int = 0
    size_b: int = 0
    size_delta: int = 0
    size_delta_pct: float = 0.0


    count_a: int = 0
    count_b: int = 0
    count_delta: int = 0


    parse_error: bool = False          
    fp_signals: list[str] = field(default_factory=list)    
    confidence_boost: int = 0          



_DEFAULT_VOLATILE_PATTERNS = [

    r"^timestamp$", r"^created_at$", r"^updated_at$", r"^expires_at$",
    r"^last_seen$", r"^last_login$", r"^modified_at$", r"^date$",
    r".*_at$", r".*_time$", r".*_date$",

    r"^request_id$", r"^trace_id$", r"^correlation_id$", r"^x-request-id$",
    r"^nonce$", r"^_nonce$", r"^jti$",  

    r"^age$", r"^cache_hit$", r"^x-cache$", r"^etag$", r"^cf-ray$",

    r"^session_expires$", r"^token_expiry$", r"^valid_until$",

    r"^page$", r"^current_page$", r"^offset$",
]


_SENSITIVE_FIELDS = {
    "email", "phone", "mobile", "address", "ssn", "dob", "date_of_birth",
    "credit_card", "card_number", "cvv", "bank_account", "routing_number",
    "password", "password_hash", "secret", "private_key", "api_key",
    "salary", "income", "balance", "credit", "account_number",
    "passport", "national_id", "tax_id", "social_security",
    "first_name", "last_name", "full_name", "name",
    "ip_address", "location", "lat", "lng", "coordinates",
}


_PRIVILEGED_FIELDS = {
    "role", "roles", "permissions", "scopes", "is_admin", "admin",
    "is_staff", "is_superuser", "account_type", "tier", "plan",
    "subscription", "membership", "vip", "verified", "approved",
    "kyc_status", "verification_status", "trust_level",
}


class SemanticDiff:
    """
    Deep structural comparison of two API responses.

    Usage:
        result = SemanticDiff.compare(body_a, body_b)
        if result.is_different and not result.fp_signals:
            # Real difference — report it
    """

    def __init__(self, volatile_patterns: list[str] | None = None):
        self._volatile_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (volatile_patterns or _DEFAULT_VOLATILE_PATTERNS)
        ]
        self._extractor = VolatileFieldExtractor()

    @classmethod
    def compare(
        cls,
        body_a: str,
        body_b: str,
        context: dict | None = None,
        threshold: float = 0.15,
    ) -> DiffResult:
        """
        Main entry point. Compares two response bodies semantically.

        Args:
            body_a: Baseline response body
            body_b: Tampered response body
            context: Optional metadata (endpoint, method, etc.)
            threshold: Minimum meaningful difference ratio (0.0–1.0)

        Returns:
            DiffResult with full analysis
        """
        instance = cls()
        return instance._compare(body_a, body_b, context or {}, threshold)

    def _compare(self, body_a: str, body_b: str, context: dict, threshold: float) -> DiffResult:
        result = DiffResult()
        result.size_a = len(body_a)
        result.size_b = len(body_b)
        result.size_delta = result.size_b - result.size_a
        result.size_delta_pct = (
            abs(result.size_delta) / max(result.size_a, 1)
        )


        result.raw_similarity = difflib.SequenceMatcher(
            None, body_a[:5000], body_b[:5000]
        ).ratio()


        if body_a == body_b:
            result.semantic_similarity = 1.0
            return result


        data_a = self._safe_parse(body_a)
        data_b = self._safe_parse(body_b)

        if data_a is None or data_b is None:
            result.parse_error = True

            return self._string_fallback(result, body_a, body_b, threshold)


        return self._deep_compare(result, data_a, data_b, threshold)

    def _deep_compare(self, result: DiffResult, data_a: Any, data_b: Any, threshold: float) -> DiffResult:
        """Deep JSON structural comparison."""


        if isinstance(data_a, list) and isinstance(data_b, list):
            result.count_a = len(data_a)
            result.count_b = len(data_b)
            result.count_delta = result.count_b - result.count_a

            if result.count_delta != 0:
                result.is_different = True
                result.structural_change = True
                result.confidence_boost += 15
                if abs(result.count_delta) > result.count_a:
                    result.confidence_boost += 20  
            elif result.count_a > 0:

                self._compare_dicts(result, data_a[0], data_b[0], prefix="[0]")

            result.semantic_similarity = self._list_similarity(data_a, data_b)
            return result


        if isinstance(data_a, list) and len(data_a) == 1 and isinstance(data_a[0], dict):
            data_a = data_a[0]
        if isinstance(data_b, list) and len(data_b) == 1 and isinstance(data_b[0], dict):
            data_b = data_b[0]


        data_a = self._unwrap_envelope(data_a)
        data_b = self._unwrap_envelope(data_b)

        if not isinstance(data_a, dict) or not isinstance(data_b, dict):

            result.is_different = True
            result.semantic_similarity = 0.0
            result.confidence_boost += 20
            return result


        keys_a = set(data_a.keys())
        keys_b = set(data_b.keys())

        result.new_keys = [k for k in keys_b - keys_a if not self._is_volatile(k)]
        result.removed_keys = [k for k in keys_a - keys_b if not self._is_volatile(k)]

        if result.new_keys or result.removed_keys:
            result.structural_change = True
            result.is_different = True
            result.confidence_boost += 15


            sensitive_new = [k for k in result.new_keys if k.lower() in _SENSITIVE_FIELDS]
            if sensitive_new:
                result.sensitive_changes.extend(sensitive_new)
                result.confidence_boost += 25


        self._compare_dicts(result, data_a, data_b, prefix="")


        total_keys = max(len(keys_a | keys_b), 1)
        changed_keys = len(result.value_changes) + len(result.new_keys) + len(result.removed_keys)
        volatile_ignored = len(result.volatile_fields_ignored)


        effective_total = max(total_keys - volatile_ignored, 1)
        effective_changed = max(changed_keys, 0)
        result.semantic_similarity = max(0.0, 1.0 - (effective_changed / effective_total))


        total_diff = changed_keys + volatile_ignored
        result.noise_ratio = volatile_ignored / max(total_diff, 1)


        meaningful_diff = result.semantic_similarity < (1.0 - threshold)
        if meaningful_diff or result.structural_change:
            result.is_different = True


        self._add_fp_signals(result)

        return result

    def _compare_dicts(self, result: DiffResult, dict_a: dict, dict_b: dict, prefix: str):
        """Compare shared keys between two dicts, recursing into nested objects."""
        shared_keys = set(dict_a.keys()) & set(dict_b.keys())

        for key in shared_keys:
            val_a = dict_a[key]
            val_b = dict_b[key]
            field_path = f"{prefix}.{key}" if prefix else key

            if self._is_volatile(key):
                result.volatile_fields_ignored.append(field_path)
                continue

            if val_a == val_b:
                continue


            if isinstance(val_a, dict) and isinstance(val_b, dict):
                self._compare_dicts(result, val_a, val_b, prefix=field_path)
                continue


            if isinstance(val_a, list) and isinstance(val_b, list):
                if len(val_a) != len(val_b):
                    result.value_changes[field_path] = [val_a, val_b]
                    result.is_different = True
                elif val_a and isinstance(val_a[0], dict):
                    self._compare_dicts(result, val_a[0], val_b[0], prefix=f"{field_path}[0]")
                else:
                    if val_a != val_b:
                        result.value_changes[field_path] = [val_a, val_b]
                        result.is_different = True
                continue


            result.value_changes[field_path] = [val_a, val_b]
            result.is_different = True


            key_lower = key.lower()
            if key_lower in _SENSITIVE_FIELDS:
                result.sensitive_changes.append(field_path)
                result.confidence_boost += 20
            if key_lower in _PRIVILEGED_FIELDS:
                result.privileged_changes.append(field_path)
                result.confidence_boost += 25

    def _is_volatile(self, field_name: str) -> bool:
        """Return True if this field should be excluded from comparison."""
        return any(p.match(field_name) for p in self._volatile_patterns)

    def _add_fp_signals(self, result: DiffResult):
        """Add false positive warning signals based on the diff analysis."""

        if result.noise_ratio > 0.8 and not result.structural_change:
            result.fp_signals.append(
                f"High noise ratio ({result.noise_ratio:.0%}) — most differences are volatile fields like timestamps"
            )


        if result.size_delta > 0 and not result.value_changes and not result.new_keys:
            result.fp_signals.append(
                "Response is larger but no structured field changes detected — may be formatting difference"
            )


        if result.semantic_similarity > 0.95 and result.raw_similarity < 0.95:
            result.fp_signals.append(
                f"Semantic similarity={result.semantic_similarity:.2f} despite raw diff — "
                "difference likely explained by volatile fields"
            )


        if len(result.value_changes) == 1:
            key = list(result.value_changes.keys())[0]
            old_v, new_v = result.value_changes[key]
            if isinstance(old_v, int) and isinstance(new_v, int):
                if abs(new_v - old_v) == 1:
                    result.fp_signals.append(
                        f"Only field `{key}` changed by exactly 1 — may be a sequence counter, not meaningful"
                    )

    def _string_fallback(self, result: DiffResult, body_a: str, body_b: str, threshold: float) -> DiffResult:
        """Fallback for non-JSON responses."""
        sim = result.raw_similarity
        result.semantic_similarity = sim

        if sim < (1.0 - threshold):
            result.is_different = True
            result.confidence_boost += 10


            success_tokens = ["success", "created", "order_id", "transaction", "confirmed"]
            body_b_lower = body_b.lower()
            has_success = any(t in body_b_lower for t in success_tokens)
            has_failure = looks_like_error(body_b)

            if has_failure and not has_success:
                result.fp_signals.append(
                    "Non-JSON response contains failure tokens — tampered request was likely rejected"
                )
                result.is_different = False  
                result.confidence_boost = 0
        else:
            result.fp_signals.append(
                f"Non-JSON responses are {sim:.0%} similar — difference likely cosmetic"
            )

        return result

    def _unwrap_envelope(self, data: Any) -> Any:
        """
        Unwrap common API envelope patterns:
        {"data": {...}} → {...}
        {"result": {...}} → {...}
        {"response": {...}} → {...}
        """
        if not isinstance(data, dict):
            return data
        envelope_keys = ["data", "result", "response", "payload", "body", "content"]
        for key in envelope_keys:
            if key in data and isinstance(data[key], dict) and len(data) <= 3:
                return data[key]
        return data

    def _list_similarity(self, list_a: list, list_b: list) -> float:
        """Compute similarity between two lists."""
        if not list_a and not list_b:
            return 1.0
        if not list_a or not list_b:
            return 0.0
        len_sim = 1.0 - abs(len(list_a) - len(list_b)) / max(len(list_a), len(list_b))
        return len_sim

    @staticmethod
    def _safe_parse(body: str) -> Any | None:
        """Parse JSON safely, returning None on failure."""
        if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
            return None
        body = body.strip()

        jsonp_match = re.match(r'^\w+\((.*)\);?$', body, re.DOTALL)
        if jsonp_match:
            body = jsonp_match.group(1)
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None


class ResponseFingerprint:
    """
    Creates a stable fingerprint of a response that ignores volatile fields.
    Used for deduplication across scan retries.
    """

    @staticmethod
    def compute(body: str) -> str:
        """Return a stable hash that ignores volatile field values."""
        data = SemanticDiff._safe_parse(body)
        if data is None:

            cleaned = re.sub(
                r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?',
                'TIMESTAMP',
                body
            )
            cleaned = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID', cleaned)
            return hashlib.sha256(cleaned.encode()).hexdigest()[:16]

        cleaned = ResponseFingerprint._strip_volatile(data)
        canonical = json.dumps(cleaned, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @staticmethod
    def _strip_volatile(obj: Any) -> Any:
        """Recursively strip volatile field values, replacing with placeholders."""
        volatile_re = [re.compile(p, re.IGNORECASE) for p in _DEFAULT_VOLATILE_PATTERNS]

        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if any(r.match(k) for r in volatile_re):
                    result[k] = "__VOLATILE__"
                else:
                    result[k] = ResponseFingerprint._strip_volatile(v)
            return result
        elif isinstance(obj, list):
            return [ResponseFingerprint._strip_volatile(item) for item in obj[:10]]
        else:
            return obj
