"""
core/intelligence/field_type_engine.py — BLFinder Attack Targeting Layer

WHAT THIS FIXES
════════════════
Attack modules in scanner.py historically fired a single fixed payload list
at every field matched by name (e.g. any key containing "price"):

    tamper_values = [0, 0.01, -1, -100, 0.00001, "0", "0.00", 1, None, False]

Two problems with that against modern applications:

  1. TYPE MISMATCH → instant 400, zero signal.
     A strictly-typed field (Pydantic/JSON-Schema/protobuf-validated) that
     expects a float will reject `None`, `False`, or a string like "0.00"
     at the validation layer, before any business logic runs. The module
     then correctly sees a non-200 and moves on — but it never actually
     tested the business logic, it tested the framework's type coercion.
     That's a wasted request that looks like "endpoint is safe" when it
     actually means "we sent a plainly malformed request."

  2. WRONG FIELD, RIGHT NAME → attacking the wrong thing.
     Name-substring matching ("id" in key, "amount" in key) catches fields
     that aren't attack-relevant for that module at all — a UUID matched
     by "...id" is not a tamperable integer; a `display_amount` computed
     read-only field is not the same as a mutable `amount` field. Firing
     price-tamper payloads at those just generates noise.

THE FIX
════════
  - infer_field_type()      → classify a field's real type envelope from
                               its observed value (and name, as a hint only
                               — value shape wins over name).
  - is_attack_relevant()    → per-module gate: does this field's type even
                               make sense as a target for this attack class?
  - generate_payloads()     → build a small, TYPE-PRESERVING payload set
                               that stays inside the field's type envelope
                               but breaks the business constraint (goes
                               negative, goes to zero, overflows) instead
                               of breaking the type itself.
  - ValidationPosture cache → one lightweight canary probe per endpoint
                               learns whether the target validates types
                               strictly or permissively. Strict targets get
                               the type-preserving payload set only.
                               Permissive targets (accept anything) additionally
                               get the type-breaking set, and that
                               permissiveness itself becomes a low-severity
                               finding (weak input validation) — signal
                               instead of a silently wasted request.

This module has no network I/O of its own — the calibration probe is a
plain (method, url, mutated_body) tuple the caller sends; this module just
decides what to send and interprets the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Field type envelope
# ─────────────────────────────────────────────────────────────────────────────


class FieldType(str, Enum):
    INTEGER          = "integer"           # 1, 42, -3   (no decimal point)
    FLOAT             = "float"            # 1.0, 9.99
    MONETARY_STRING   = "monetary_string"  # "10.00", "9,999.00" — server expects a string
    BOOLEAN           = "boolean"
    IDENTIFIER        = "identifier"       # UUID / opaque token-shaped string or int PK
    ENUM_LIKE         = "enum_like"        # short fixed-vocabulary string ("active","USD")
    DATE_ISO          = "date_iso"
    STRING_FREE       = "string_free"      # free text, not attack-relevant for numeric classes
    NULL              = "null"
    ARRAY             = "array"
    OBJECT            = "object"
    UNKNOWN           = "unknown"


_UUID_RE   = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ISO_RE    = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?")
_MONEY_RE  = re.compile(r"^-?\d{1,3}(,\d{3})*(\.\d{2})?$|^-?\d+\.\d{2}$")
_ENUM_HINT_KEYS = ("currency", "status", "type", "state", "method", "tier", "plan")


def infer_field_type(key: str, value: Any) -> FieldType:
    """
    Classify a field's real type envelope. Value shape is authoritative;
    the key name is only used to break ties between plausible readings of
    the same value (e.g. a numeric string could be monetary or an
    identifier — the key name disambiguates).
    """
    if value is None:
        return FieldType.NULL
    if isinstance(value, bool):
        return FieldType.BOOLEAN
    if isinstance(value, int):
        # Long opaque-looking integers under an *_id / id key are PKs, not
        # tamperable quantities/prices even though they're numeric.
        if _looks_like_identifier_key(key) and value > 0:
            return FieldType.IDENTIFIER
        return FieldType.INTEGER
    if isinstance(value, float):
        return FieldType.FLOAT
    if isinstance(value, list):
        return FieldType.ARRAY
    if isinstance(value, dict):
        return FieldType.OBJECT
    if isinstance(value, str):
        return _infer_string_subtype(key, value)
    return FieldType.UNKNOWN


def _looks_like_identifier_key(key: str) -> bool:
    k = key.lower()
    return k == "id" or k.endswith("_id") or k.endswith("id") and len(k) <= 4


def _infer_string_subtype(key: str, value: str) -> FieldType:
    v = value.strip()
    if not v:
        return FieldType.STRING_FREE
    if _UUID_RE.match(v):
        return FieldType.IDENTIFIER
    if _ISO_RE.match(v):
        return FieldType.DATE_ISO
    if _MONEY_RE.match(v):
        return FieldType.MONETARY_STRING
    # Pure-digit string under an identifier-shaped key ("order_id": "88213")
    if v.isdigit() and _looks_like_identifier_key(key):
        return FieldType.IDENTIFIER
    # Pure-digit / decimal string not identifier-shaped → treat as monetary/
    # numeric-as-string, which many payment APIs deliberately use to avoid
    # float rounding (Stripe-style minor units are the exception — handled
    # by the caller comparing magnitude, not this classifier).
    if re.match(r"^-?\d+(\.\d+)?$", v):
        return FieldType.MONETARY_STRING
    if any(hint in key.lower() for hint in _ENUM_HINT_KEYS) and len(v) <= 20 and " " not in v:
        return FieldType.ENUM_LIKE
    return FieldType.STRING_FREE


# ─────────────────────────────────────────────────────────────────────────────
# Attack relevance gate — per module class
# ─────────────────────────────────────────────────────────────────────────────

# Which field types are legitimate targets for each attack class. Anything
# outside this set is skipped for that module — this is what stops
# "amount_id" (an identifier that happens to contain "amount") from being
# fed negative-price payloads, and stops a free-text "notes" field from
# being treated as a quantity.
_RELEVANT_TYPES_FOR_MODULE: dict[str, set[FieldType]] = {
    "price_manipulation":  {FieldType.INTEGER, FieldType.FLOAT, FieldType.MONETARY_STRING},
    "negative_quantity":   {FieldType.INTEGER, FieldType.FLOAT},
    "integer_overflow":    {FieldType.INTEGER, FieldType.FLOAT},
    "mass_assignment_bool": {FieldType.BOOLEAN, FieldType.NULL},
    "coupon_stacking":     {FieldType.STRING_FREE, FieldType.ENUM_LIKE, FieldType.IDENTIFIER},
    "time_logic_bypass":   {FieldType.DATE_ISO, FieldType.INTEGER},
}


def is_attack_relevant(module: str, key: str, value: Any) -> bool:
    ftype = infer_field_type(key, value)
    allowed = _RELEVANT_TYPES_FOR_MODULE.get(module)
    if allowed is None:
        return True  # module has no registered gate — don't block it
    return ftype in allowed


# ─────────────────────────────────────────────────────────────────────────────
# Type-preserving payload generation
# ─────────────────────────────────────────────────────────────────────────────


def generate_payloads(ftype: FieldType, original: Any, *, permissive: bool = False) -> list[Any]:
    """
    Return a small, ordered list of payloads for this field's type.

    Order matters: the first entries are the highest-signal, cheapest-to-
    interpret business-logic breaks (e.g. negate, zero). Type-breaking
    payloads (None, bool-for-number, wrong-shape strings) are only
    appended when `permissive=True` — i.e. the endpoint's calibration
    probe already showed it doesn't enforce types, so those payloads have
    a real chance of reaching business logic instead of dying in a 400
    that tells us nothing.
    """
    out: list[Any] = []

    if ftype == FieldType.INTEGER:
        n = int(original) if isinstance(original, (int, float)) else 1
        out += [-n if n != 0 else -1, 0, -1, n - 1 if n > 1 else -1]
        out.append(2_147_483_648)          # int32 overflow
        out.append(9_223_372_036_854_775_808)  # int64 overflow
        if permissive:
            out += [None, False, "0"]

    elif ftype == FieldType.FLOAT:
        n = float(original) if isinstance(original, (int, float)) else 1.0
        out += [round(-n, 2) if n != 0 else -0.01, 0.0, -0.01, 1e-9]
        if permissive:
            out += [None, False, "0.00"]

    elif ftype == FieldType.MONETARY_STRING:
        # Preserve the "it's a string" contract — this is exactly the class
        # of field the old fixed list broke by sending bare ints/None to a
        # server that does `Decimal(request["amount"])` and 500s or 400s
        # on non-string input, telling you nothing.
        try:
            n = float(str(original).replace(",", ""))
        except ValueError:
            n = 1.0
        out += [f"{-n:.2f}" if n != 0 else "-0.01", "0.00", "-0.01", f"{n:.10f}"]
        if permissive:
            out += [None, 0, -1]

    elif ftype == FieldType.BOOLEAN:
        out = [not bool(original)]

    elif ftype == FieldType.ENUM_LIKE:
        # Enum tampering wants known plausible neighbours, not garbage —
        # garbage strings just get schema-rejected. Common neighbours by
        # semantic hint on the value itself.
        v = str(original).lower()
        neighbours = {
            "usd": ["eur", "gbp", "ngn"], "eur": ["usd"], "ngn": ["usd"],
            "pending": ["completed", "approved", "paid"],
            "unverified": ["verified"], "inactive": ["active"],
            "free": ["premium", "pro"], "basic": ["premium", "enterprise"],
        }
        out = neighbours.get(v, [])

    elif ftype == FieldType.IDENTIFIER:
        # Deliberately NOT handled here — identifier tampering is IDOR's
        # job (sequential/adjacent ID walking with cross-user comparison),
        # not the price/quantity module's job. Returning [] enforces that
        # separation instead of letting a same-named module improvise.
        out = []

    return out


def generate_time_payloads(ftype: FieldType, original: Any) -> list[tuple[Any, str]]:
    """
    Type-matched replacement for time_logic_bypass's old fixed pair
    (`"2099-12-31T23:59:59Z"`, `-1`) sent into every time-ish-named field
    regardless of whether that field actually holds an ISO string or a
    unix integer. Sending a full ISO string into a strictly-typed integer
    timestamp field (or vice versa) gets rejected by the schema layer
    before the interesting question — "does the server actually validate
    this timestamp against real-world constraints?" — ever gets tested.

    Returns (value, label) pairs so callers keep their existing evidence
    labelling.
    """
    if ftype == FieldType.DATE_ISO:
        return [
            ("2099-12-31T23:59:59Z", "far-future"),
            ("1970-01-01T00:00:00Z", "epoch-past"),
        ]
    if ftype == FieldType.INTEGER:
        return [
            (4102444800, "far-future-unix"),   # year 2100
            (-1, "unix-negative"),
        ]
    # Field matched a time-ish name but isn't a recognizable date/unix
    # type (e.g. a free-text label) — not this module's business.
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Per-endpoint validation posture — learned once, shared across modules
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ValidationPosture:
    strict: bool = True          # default to conservative (type-preserving only)
    calibrated: bool = False     # has a canary probe actually run yet
    weak_validation_finding_emitted: bool = False


class PostureCache:
    """
    One canary probe per (method, url) is enough to learn whether the
    endpoint enforces types — sharing it across price/quantity/mass-
    assignment modules avoids re-probing the same endpoint 3+ times per
    scan for the same answer.
    """

    def __init__(self) -> None:
        self._cache: dict[str, ValidationPosture] = {}

    def key(self, method: str, url: str) -> str:
        return f"{method.upper()} {url}"

    def get(self, method: str, url: str) -> ValidationPosture:
        return self._cache.setdefault(self.key(method, url), ValidationPosture())

    def record_calibration(self, method: str, url: str, *, canary_rejected: bool) -> None:
        """
        canary_rejected=True  → server 400/422'd an obviously wrong-typed
                                 value → STRICT posture → type-preserving
                                 payloads only.
        canary_rejected=False → server accepted (or silently ignored) a
                                 wrong-typed value → PERMISSIVE posture →
                                 broader payload set is worth trying, and
                                 the permissiveness itself is reportable.
        """
        posture = self.get(method, url)
        posture.strict     = canary_rejected
        posture.calibrated = True


def build_canary_value(ftype: FieldType) -> Any:
    """
    A single, cheap, obviously-wrong-typed value for the calibration probe.
    Picked to be unambiguous: if this is accepted, the endpoint is not
    doing real type validation on this field.
    """
    return {
        FieldType.INTEGER:        "NOT_AN_INTEGER_CANARY",
        FieldType.FLOAT:          "NOT_A_FLOAT_CANARY",
        FieldType.MONETARY_STRING: 123456789,   # int where a formatted string is expected
        FieldType.BOOLEAN:        "NOT_A_BOOL_CANARY",
        FieldType.ENUM_LIKE:      "NOT_A_VALID_ENUM_CANARY",
    }.get(ftype, "TYPE_CANARY")


# ─────────────────────────────────────────────────────────────────────────────
# Non-API path filter — shared across GET-probe modules
# ─────────────────────────────────────────────────────────────────────────────
#
# Several attack modules (BOPLA field expansion, limit/offset manipulation,
# soft-delete bypass, HTTP method override, parameter pollution) fire a
# fixed probe set at every discovered endpoint's URL regardless of whether
# that URL is even an API route. Discovery layers already do their own
# static-asset filtering for crawling purposes, but nothing stopped these
# specific attack modules from independently probing a `.js`/`.css`/image
# URL that slipped through as a "discovered endpoint" (e.g. found via a
# Referer header or a sourcemap reference) — those probes can only ever
# return the same static file byte-for-byte, so every module firing on
# them is pure wasted request volume with zero chance of signal.

_NON_API_EXTENSIONS = frozenset({
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".webp", ".avif",
    ".mp4", ".webm", ".pdf", ".zip", ".gz", ".txt", ".xml.map",
})


def is_non_api_path(url: str) -> bool:
    """True if the URL's path looks like a static asset, not an API route."""
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return any(path.endswith(ext) for ext in _NON_API_EXTENSIONS)


def pollution_probe_value(key: str, original: Any) -> Any:
    """
    Type-matched second value for HTTP parameter pollution's
    `?key=original&key=<probe>` duplication. The old fixed `"999999"`
    duplicate is a coherent probe for a numeric param (does the server
    take first/last/concat on a duplicated ID?) but is a type mismatch
    against a UUID, enum, or opaque-token param — those get compared
    against a structurally different value, which mostly just proves the
    server ignores or rejects malformed input rather than revealing how
    it resolves genuine duplicates.
    """
    ftype = infer_field_type(key, original)
    if ftype == FieldType.IDENTIFIER:
        # Same shape, different value — a real "which one wins" probe.
        if _UUID_RE.match(str(original)):
            return "00000000-0000-0000-0000-000000000000"
        return "999999"
    if ftype in (FieldType.INTEGER,):
        return "999999"
    if ftype == FieldType.ENUM_LIKE:
        return "__polluted__"
    return "999999"  # sane default; still type-mismatched only for free text
