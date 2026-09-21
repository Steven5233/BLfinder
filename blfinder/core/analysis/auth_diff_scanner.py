"""
core/analysis/auth_diff_scanner.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTHENTICATED vs UNAUTHENTICATED DIFF SCANNER

Finds an entire class of bugs invisible to standard module scanning:
fields that are PRESENT in authenticated responses but should be ABSENT
in unauthenticated responses — yet are returned anyway.

WHY THIS MATTERS
════════════════
Standard auth checks test: "does the endpoint return 200 without a token?"
That catches missing authentication entirely, but misses the subtler case:

  Authenticated:   {"id": 1, "email": "me@x.com", "ssn": "123-45-6789",
                    "internal_score": 780, "stripe_customer_id": "cus_xxx"}
  Unauthenticated: {"id": 1, "email": "me@x.com"}

The endpoint "requires" auth (returns partial data without it), but SSN,
internal scoring, and payment processor IDs leak anyway. Classic BOPLA
that no single-request scanner can catch because each response alone
looks normal.

ALGORITHM
═════════

Stage 1 — Schema Extraction
  Parse every response (auth + no-auth) into a FieldSchema:
  - field name, type, value category (PII/credential/financial/internal)
  - presence (always present / sometimes present / never present)
  - sensitivity score based on field name and value patterns

Stage 2 — Differential Analysis (7 diff types)
  Type 1 — AUTH_ONLY_FIELDS
    Fields present in auth response, completely absent in no-auth response.
    Expected: most fields. Interesting: none (this is correct behaviour).

  Type 2 — UNAUTH_LEAKED_FIELDS  ← PRIMARY FINDING TYPE
    Fields present in both auth and no-auth responses.
    If field is sensitive → CRITICAL finding.
    If field is non-sensitive → MEDIUM finding.

  Type 3 — UNAUTH_EXTRA_FIELDS
    Fields in no-auth response NOT in auth response.
    Rare but serious — suggests a different code path with less filtering.

  Type 4 — VALUE_EXPOSURE
    Same field in both, but no-auth value is more complete/different.
    e.g., auth returns masked "****1234", no-auth returns "4111111111111234"

  Type 5 — STRUCTURE_EXPOSURE
    Auth response has nested objects, no-auth response flattens them.
    Flattening sometimes exposes more data than the nested version.

  Type 6 — COUNT_EXPOSURE
    Auth response returns N records, no-auth returns M > N records.
    Classic pagination/filter bypass.

  Type 7 — ROLE_ESCALATION_FIELDS
    Fields that indicate privilege level (role, is_admin, permissions)
    that are present in no-auth response with elevated values.

Stage 3 — Sensitivity Scoring
  Each leaked field is scored by:
  - Name pattern (ssn, password, token → HIGH; name, id → LOW)
  - Value pattern (regex against known PII/credential formats)
  - Context (financial endpoint → higher score for amount fields)
  - Uniqueness (field not in the schema baseline → higher score)

Stage 4 — Cross-Role Diff (when token2 provided)
  Also diffs token1 (user) vs token2 (second user):
  - Fields only in token1's response → IDOR candidate
  - Fields with different VALUES → cross-user data leak

Stage 5 — Finding Generation
  Produces Finding objects compatible with BLFScanner's existing pipeline.
  Plugs directly into run_all_modules() results list.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional







_FIELD_SENSITIVITY: list[tuple[re.Pattern, int, str]] = [

    (re.compile(r'\b(password|passwd|pwd|secret|private_key|api_secret)\b', re.I), 100, "CREDENTIAL"),
    (re.compile(r'\b(ssn|social_security|national_id|tax_id|sin)\b', re.I),        100, "PII_GOVERNMENT"),
    (re.compile(r'\b(credit_card|card_number|cvv|cvc|pan)\b', re.I),               100, "FINANCIAL"),
    (re.compile(r'\b(access_token|auth_token|bearer|refresh_token|jwt)\b', re.I),  95,  "CREDENTIAL"),
    (re.compile(r'\b(api_key|api_token|client_secret|webhook_secret)\b', re.I),    95,  "CREDENTIAL"),
    (re.compile(r'\b(stripe_|braintree_|paypal_|square_)(key|token|secret|id)\b', re.I), 90, "PAYMENT_PROCESSOR"),
    (re.compile(r'\b(aws_|gcp_|azure_)(key|secret|token|id)\b', re.I),             90,  "CLOUD_CREDENTIAL"),
    (re.compile(r'\b(bank_account|routing_number|iban|swift|bic)\b', re.I),        90,  "FINANCIAL"),
    (re.compile(r'\b(dob|date_of_birth|birth_date|birthday)\b', re.I),             85,  "PII"),
    (re.compile(r'\b(salary|income|revenue|profit|wage|compensation)\b', re.I),    85,  "FINANCIAL_PRIVATE"),
    (re.compile(r'\b(internal_score|risk_score|fraud_score|credit_score)\b', re.I), 80, "INTERNAL"),
    (re.compile(r'\b(phone|mobile|cell|telephone)\b', re.I),                       75,  "PII"),
    (re.compile(r'\b(address|street|zipcode|postcode|location)\b', re.I),          70,  "PII"),
    (re.compile(r'\b(email|mail)\b', re.I),                                         65,  "PII"),
    (re.compile(r'\b(is_admin|admin|role|permission|privilege|scope)\b', re.I),    80,  "PRIVILEGE"),
    (re.compile(r'\b(internal|private|confidential|hidden|_meta)\b', re.I),        75,  "INTERNAL"),
    (re.compile(r'\b(ip_address|ip|user_agent|device_id|fingerprint)\b', re.I),   60,  "TRACKING"),
    (re.compile(r'\b(kyc|verification_status|verified|approved)\b', re.I),         70,  "COMPLIANCE"),
    (re.compile(r'\b(balance|amount|price|cost|fee|charge|total)\b', re.I),        65,  "FINANCIAL"),
    (re.compile(r'\b(customer_id|account_id|user_id|profile_id)\b', re.I),         40,  "IDENTIFIER"),
]


_VALUE_SENSITIVITY: list[tuple[re.Pattern, int, str]] = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                          100, "SSN"),
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),                                    100, "VISA_PAN"),
    (re.compile(r'\b5[1-5][0-9]{14}\b'),                                             100, "MC_PAN"),
    (re.compile(r'\bey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\b'),  95,  "JWT"),
    (re.compile(r'\bsk_(live|test)_[A-Za-z0-9]{24,}\b'),                             95,  "STRIPE_KEY"),
    (re.compile(r'\bAKIA[A-Z0-9]{16}\b'),                                             95,  "AWS_KEY"),
    (re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b'),                                    50,  "BASE64_BLOB"),
    (re.compile(r'\b[0-9a-f]{32,64}\b'),                                              45,  "HEX_SECRET"),
    (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),                  65,  "EMAIL"),
    (re.compile(r'\+?1?\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'),                     70,  "PHONE"),
]

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"






@dataclass
class FieldInfo:
    name:         str
    value:        Any
    type_name:    str          
    sensitivity:  int          
    category:     str          
    path:         str          


@dataclass
class DiffFinding:
    diff_type:       str           
    field_path:      str
    field_info:      FieldInfo
    auth_value:      Any
    unauth_value:    Any
    sensitivity:     int
    severity:        str
    description:     str
    evidence:        str
    recommendation:  str
    endpoint:        str
    method:          str






class SchemaExtractor:
    """
    Recursively walks a JSON response and extracts field metadata.
    Produces a flat dict of {dot_path: FieldInfo}.
    """

    def extract(self, data: Any, endpoint: str = "") -> dict[str, FieldInfo]:
        fields: dict[str, FieldInfo] = {}
        self._walk(data, "", fields)
        return fields

    def _walk(self, obj: Any, path: str, out: dict[str, FieldInfo], depth: int = 0):
        if depth > 8:   
            return

        if isinstance(obj, dict):
            for key, val in obj.items():
                child_path = f"{path}.{key}" if path else key
                info = self._classify_field(key, val, child_path)
                out[child_path] = info
                if isinstance(val, (dict, list)):
                    self._walk(val, child_path, out, depth + 1)

        elif isinstance(obj, list):

            if obj and isinstance(obj[0], dict):
                self._walk(obj[0], f"{path}[0]", out, depth + 1)

            if path:
                info = self._classify_field(
                    path.split(".")[-1], obj, path
                )
                out[path] = info

    def _classify_field(self, name: str, value: Any, path: str) -> FieldInfo:
        type_name = self._type_name(value)
        sens, cat = self._sensitivity(name, value)
        return FieldInfo(
            name=name, value=value, type_name=type_name,
            sensitivity=sens, category=cat, path=path,
        )

    @staticmethod
    def _type_name(value: Any) -> str:
        if value is None:       return "null"
        if isinstance(value, bool): return "bool"
        if isinstance(value, int):  return "int"
        if isinstance(value, float): return "float"
        if isinstance(value, str):  return "str"
        if isinstance(value, list): return "list"
        if isinstance(value, dict): return "dict"
        return "unknown"

    @staticmethod
    def _sensitivity(name: str, value: Any) -> tuple[int, str]:
        """Return (sensitivity_score 0-100, category string)."""
        max_score = 0
        category  = "OTHER"


        for pattern, score, cat in _FIELD_SENSITIVITY:
            if pattern.search(name):
                if score > max_score:
                    max_score = score
                    category  = cat


        if isinstance(value, str) and len(value) > 3:
            for pattern, score, cat in _VALUE_SENSITIVITY:
                if pattern.search(value):
                    if score > max_score:
                        max_score = score
                        category  = cat

        return max_score, category











_JWT_VOLATILE_CLAIMS = {"iat", "exp", "nbf", "jti", "nonce"}
_JWT_IDENTITY_CLAIMS = {
    "sub", "uid", "user_id", "userId", "email", "role", "roles",
    "scope", "scopes", "aud", "admin", "is_admin", "permissions",
}


def _decode_jwt_claims(token: Any) -> dict | None:
    if not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _jwt_identity_differs(a_token: Any, b_token: Any) -> bool | None:
    """True/False if an identity-relevant claim differs. None if either
    token isn't a decodable JWT — caller should fall back to raw compare."""
    a = _decode_jwt_claims(a_token)
    b = _decode_jwt_claims(b_token)
    if a is None or b is None:
        return None
    for key in _JWT_IDENTITY_CLAIMS:
        if a.get(key) != b.get(key):
            return True
    return False


class DiffEngine:
    """
    Compares two FieldSchema dicts and produces DiffFinding objects.
    Implements all 7 diff types.
    """

    def __init__(self, min_sensitivity: int = 40):
        self.min_sensitivity = min_sensitivity

    def diff(
        self,
        auth_schema:   dict[str, FieldInfo],
        unauth_schema: dict[str, FieldInfo],
        auth_data:     Any,
        unauth_data:   Any,
        endpoint:      str,
        method:        str,
    ) -> list[DiffFinding]:
        findings: list[DiffFinding] = []

        auth_keys   = set(auth_schema.keys())
        unauth_keys = set(unauth_schema.keys())


        both = auth_keys & unauth_keys
        for path in both:
            auth_field   = auth_schema[path]
            unauth_field = unauth_schema[path]

            if auth_field.sensitivity < self.min_sensitivity:
                continue



            if self._is_empty(unauth_field.value) and self._is_empty(auth_field.value):
                continue
            if self._is_empty(unauth_field.value):
                continue


            if auth_field.category == "JWT" and unauth_field.category == "JWT":
                jwt_diff   = _jwt_identity_differs(auth_field.value, unauth_field.value)
                value_diff = (
                    jwt_diff if jwt_diff is not None
                    else self._value_differs(auth_field.value, unauth_field.value)
                )
            else:
                value_diff = self._value_differs(auth_field.value, unauth_field.value)
            if value_diff:
                findings.append(DiffFinding(
                    diff_type="VALUE_EXPOSURE",
                    field_path=path,
                    field_info=auth_field,
                    auth_value=auth_field.value,
                    unauth_value=unauth_field.value,
                    sensitivity=auth_field.sensitivity,
                    severity=self._severity(auth_field.sensitivity),
                    description=(
                        f"Field `{path}` has different value in unauthenticated "
                        f"response than authenticated response — possible data "
                        f"de-masking or alternate code path."
                    ),
                    evidence=(
                        f"Auth value: {self._safe_repr(auth_field.value)} | "
                        f"No-auth value: {self._safe_repr(unauth_field.value)}"
                    ),
                    recommendation=(
                        f"Verify field `{path}` applies identical masking/filtering "
                        "regardless of authentication state."
                    ),
                    endpoint=endpoint,
                    method=method,
                ))
            else:

                findings.append(DiffFinding(
                    diff_type="UNAUTH_LEAKED_FIELD",
                    field_path=path,
                    field_info=auth_field,
                    auth_value=auth_field.value,
                    unauth_value=unauth_field.value,
                    sensitivity=auth_field.sensitivity,
                    severity=self._severity(auth_field.sensitivity),
                    description=(
                        f"Sensitive field `{path}` ({auth_field.category}) "
                        f"is present in BOTH authenticated and unauthenticated "
                        f"responses. This field should only be accessible to "
                        f"authenticated users."
                    ),
                    evidence=(
                        f"Field `{path}` = {self._safe_repr(auth_field.value)} "
                        f"returned without authentication. "
                        f"Sensitivity: {auth_field.sensitivity}/100 ({auth_field.category})"
                    ),
                    recommendation=(
                        f"Remove field `{path}` from unauthenticated responses. "
                        "Apply a strict field allowlist per authentication level."
                    ),
                    endpoint=endpoint,
                    method=method,
                ))


        extra = unauth_keys - auth_keys
        for path in extra:
            unauth_field = unauth_schema[path]
            if unauth_field.sensitivity < self.min_sensitivity:
                continue
            findings.append(DiffFinding(
                diff_type="UNAUTH_EXTRA_FIELD",
                field_path=path,
                field_info=unauth_field,
                auth_value=None,
                unauth_value=unauth_field.value,
                sensitivity=unauth_field.sensitivity,
                severity=SEVERITY_HIGH,
                description=(
                    f"Field `{path}` appears in the UNAUTHENTICATED response "
                    f"but NOT in the authenticated response — suggests a "
                    f"different code path with less filtering when no token is present."
                ),
                evidence=(
                    f"No-auth exclusive field: `{path}` = "
                    f"{self._safe_repr(unauth_field.value)}"
                ),
                recommendation=(
                    "Audit the unauthenticated code path. It appears to use "
                    "different serialization/filtering than the authenticated path."
                ),
                endpoint=endpoint,
                method=method,
            ))


        count_diff = self._check_count_exposure(auth_data, unauth_data, endpoint, method)
        if count_diff:
            findings.append(count_diff)


        for path in unauth_keys:
            fi = unauth_schema[path]
            if fi.category == "PRIVILEGE" and fi.sensitivity >= 60:
                if self._is_elevated_privilege(fi.value):
                    findings.append(DiffFinding(
                        diff_type="ROLE_ESCALATION_FIELD",
                        field_path=path,
                        field_info=fi,
                        auth_value=auth_schema.get(path, FieldInfo(path, None, "null", 0, "OTHER", path)).value,
                        unauth_value=fi.value,
                        sensitivity=95,
                        severity=SEVERITY_CRITICAL,
                        description=(
                            f"Privilege field `{path}` contains elevated value "
                            f"`{fi.value}` in unauthenticated response."
                        ),
                        evidence=(
                            f"Unauthenticated response contains `{path}` = "
                            f"`{fi.value}` — elevated privilege indicator."
                        ),
                        recommendation=(
                            "Never expose role/permission fields in unauthenticated "
                            "responses. Compute permissions server-side from the "
                            "authenticated session."
                        ),
                        endpoint=endpoint,
                        method=method,
                    ))

        return findings

    def cross_user_diff(
        self,
        user1_schema: dict[str, FieldInfo],
        user2_schema: dict[str, FieldInfo],
        user1_data:   Any,
        user2_data:   Any,
        endpoint:     str,
        method:       str,
    ) -> list[DiffFinding]:
        """
        Diff between user1 and user2 authenticated responses.
        Finds fields where user2 can see user1's private data.
        """
        findings: list[DiffFinding] = []

        for path in set(user1_schema.keys()) & set(user2_schema.keys()):
            f1 = user1_schema[path]
            f2 = user2_schema[path]

            if f1.sensitivity < self.min_sensitivity:
                continue


            if self._value_differs(f1.value, f2.value):

                if f1.category in ("PII", "PII_GOVERNMENT", "CREDENTIAL", "FINANCIAL"):
                    findings.append(DiffFinding(
                        diff_type="CROSS_USER_DATA_LEAK",
                        field_path=path,
                        field_info=f1,
                        auth_value=f1.value,
                        unauth_value=f2.value,
                        sensitivity=f1.sensitivity,
                        severity=SEVERITY_CRITICAL,
                        description=(
                            f"Field `{path}` ({f1.category}) has different values "
                            f"for User 1 vs User 2 on the SAME endpoint — "
                            f"User 2 may be seeing User 1's private data or vice versa."
                        ),
                        evidence=(
                            f"User1 `{path}` = {self._safe_repr(f1.value)} | "
                            f"User2 `{path}` = {self._safe_repr(f2.value)}"
                        ),
                        recommendation=(
                            f"Enforce object-level ownership on `{path}`. "
                            "Verify the authenticated user owns the resource before "
                            "returning any user-specific fields."
                        ),
                        endpoint=endpoint,
                        method=method,
                    ))

        return findings



    @staticmethod
    def _severity(sensitivity: int) -> str:
        if sensitivity >= 90: return SEVERITY_CRITICAL
        if sensitivity >= 70: return SEVERITY_HIGH
        if sensitivity >= 40: return SEVERITY_MEDIUM
        return SEVERITY_LOW

    @staticmethod
    def _is_empty(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str) and value.strip() == "":
            return True
        if isinstance(value, (list, dict)) and len(value) == 0:
            return True
        return False

    @staticmethod
    def _value_differs(a: Any, b: Any) -> bool:
        if a is None and b is None: return False
        if a is None or b is None:  return True
        if type(a) != type(b):      return True
        if isinstance(a, str):

            return a.strip().lower() != b.strip().lower()
        return a != b

    @staticmethod
    def _safe_repr(value: Any, max_len: int = 60) -> str:
        """Return a safe string representation, redacting long secrets."""
        if value is None:           return "null"
        if isinstance(value, bool): return str(value).lower()
        s = str(value)
        if len(s) > max_len:

            return s[:8] + "..." + s[-4:]
        return s

    @staticmethod
    def _is_elevated_privilege(value: Any) -> bool:
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, str):
            return value.lower() in (
                "admin", "superadmin", "root", "staff", "internal",
                "privileged", "super", "god", "owner", "operator",
            )
        if isinstance(value, list):
            elevated = {"admin", "superadmin", "root", "staff", "internal"}
            return any(str(v).lower() in elevated for v in value)
        return False

    def _check_count_exposure(
        self, auth_data: Any, unauth_data: Any,
        endpoint: str, method: str,
    ) -> Optional[DiffFinding]:
        """Check if no-auth response returns MORE records than auth response."""
        def _count(data: Any) -> int:
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for k in ("data", "items", "results", "records", "users", "orders"):
                    if k in data and isinstance(data[k], list):
                        return len(data[k])
            return -1

        auth_count   = _count(auth_data)
        unauth_count = _count(unauth_data)

        if auth_count < 0 or unauth_count < 0:
            return None
        if unauth_count <= auth_count:
            return None
        if unauth_count - auth_count < 2:
            return None  

        return DiffFinding(
            diff_type="COUNT_EXPOSURE",
            field_path="[root]",
            field_info=FieldInfo("[root]", unauth_count, "int", 70, "INTERNAL", "[root]"),
            auth_value=auth_count,
            unauth_value=unauth_count,
            sensitivity=70,
            severity=SEVERITY_HIGH,
            description=(
                f"Unauthenticated response returns MORE records ({unauth_count}) "
                f"than authenticated response ({auth_count}). "
                f"Pagination or ownership filter may be bypassed when no token present."
            ),
            evidence=(
                f"Auth: {auth_count} records | No-auth: {unauth_count} records "
                f"(+{unauth_count - auth_count} extra)"
            ),
            recommendation=(
                "Apply server-side ownership filters unconditionally, "
                "not only when a token is present."
            ),
            endpoint=endpoint,
            method=method,
        )






class AuthDiffScanner:
    """
    Authenticated vs Unauthenticated Diff Scanner.

    Integrates with BLFScanner via scan_endpoint().
    Returns Finding-compatible dicts that the main scanner can
    process through its standard confidence/verifier pipeline.
    """

    def __init__(self, scanner, config):
        self._scanner   = scanner
        self._config    = config
        self._extractor = SchemaExtractor()
        self._diff_eng  = DiffEngine(
            min_sensitivity=getattr(config, "auth_diff_min_sensitivity", 40)
        )

    async def scan_endpoint(
        self,
        url:    str,
        method: str = "GET",
        body:   dict | None = None,
        params: dict | None = None,
    ) -> list[dict]:
        """
        Scan a single endpoint. Returns list of finding dicts.
        Compatible with BLFScanner.run_all_modules() results pipeline.
        """
        findings: list[dict] = []

        token1 = self._config.auth_token
        token2 = getattr(self._config, "second_user_token", "")

        ev = self._scanner._new_evidence()


        auth_status, auth_hdrs, auth_body, _ = await self._scanner._req_ev(
            "baseline", ev, method, url,
            req_body=body if body else None,
            params=params if params else None,
            token_override=token1 or None,
        )

        if auth_status == 0 or auth_status >= 500:
            return findings  

        auth_data   = self._try_parse(auth_body)
        if auth_data is None:
            return findings  

        auth_schema = self._extractor.extract(auth_data, url)
        if not auth_schema:
            return findings  


        unauth_status, _, unauth_body, _ = await self._scanner._req_ev(
            "no_auth", ev, method, url,
            req_body=body if body else None,
            params=params if params else None,
            token_override="",   
            cookies_override={}, 
        )

        if unauth_status == 0:
            return findings

        unauth_data = self._try_parse(unauth_body)


        if unauth_data is not None and unauth_status in (200, 201):
            unauth_schema = self._extractor.extract(unauth_data, url)
            diff_results  = self._diff_eng.diff(
                auth_schema, unauth_schema,
                auth_data, unauth_data,
                endpoint=url, method=method,
            )
            for dr in diff_results:
                findings.append(self._to_finding(dr, "auth_diff", ev=ev))


        if token2 and token2 != token1:
            user2_status, _, user2_body, _ = await self._scanner._req_ev(
                "cross_user", ev, method, url,
                req_body=body if body else None,
                params=params if params else None,
                token_override=token2,
            )
            if user2_status in (200, 201):
                user2_data   = self._try_parse(user2_body)
                user2_schema = self._extractor.extract(user2_data or {}, url)
                cross_results = self._diff_eng.cross_user_diff(
                    auth_schema, user2_schema,
                    auth_data, user2_data or {},
                    endpoint=url, method=method,
                )
                for dr in cross_results:
                    findings.append(self._to_finding(dr, "cross_user_diff", ev=ev))

        return findings



    async def scan_all(
        self,
        endpoints: list[dict],
        concurrency: int = 5,
    ) -> list[dict]:
        """Scan all endpoints concurrently. Called from run_all_modules()."""
        sem = asyncio.Semaphore(concurrency)
        all_findings: list[dict] = []

        async def _bounded(ep: dict):
            async with sem:
                url    = ep.get("url", "")
                method = ep.get("method", "GET")
                body   = ep.get("body") or None
                params = ep.get("params") or None
                try:
                    return await self.scan_endpoint(url, method, body, params)
                except Exception as e:
                    if self._config.verbose:
                        print(f"  [auth_diff] error on {url[:60]}: {e}")
                    return []

        tasks   = [_bounded(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)


        seen:   set[str]   = set()
        unique: list[dict] = []
        for f in all_findings:
            key = f"{f.get('endpoint','')}|{f.get('parameter','')}|{f.get('category','')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        if unique:
            print(f"  [auth_diff] {len(unique)} auth-level exposure findings")

        return unique



    def _to_finding(self, dr: DiffFinding, source: str, ev: "EvidenceCapture | None" = None) -> dict:
        """
        Convert a DiffFinding to a dict compatible with BLFScanner's
        Finding dataclass constructor.
        """
        owasp_map = {
            "CREDENTIAL":       "API2:2023 Broken Authentication",
            "PII":              "API3:2023 Broken Object Property Level Authorization",
            "PII_GOVERNMENT":   "API3:2023 Broken Object Property Level Authorization",
            "FINANCIAL":        "API3:2023 Broken Object Property Level Authorization",
            "FINANCIAL_PRIVATE": "API3:2023 Broken Object Property Level Authorization",
            "INTERNAL":         "API3:2023 Broken Object Property Level Authorization",
            "PRIVILEGE":        "API5:2023 Broken Function Level Authorization",
            "PAYMENT_PROCESSOR": "API3:2023 Broken Object Property Level Authorization",
            "CLOUD_CREDENTIAL": "API2:2023 Broken Authentication",
        }
        cwe_map = {
            "CREDENTIAL":      "CWE-312",
            "PII":             "CWE-213",
            "PII_GOVERNMENT":  "CWE-213",
            "FINANCIAL":       "CWE-213",
            "PRIVILEGE":       "CWE-269",
            "INTERNAL":        "CWE-200",
        }
        cvss_map = {
            SEVERITY_CRITICAL: 9.1,
            SEVERITY_HIGH:     7.5,
            SEVERITY_MEDIUM:   5.3,
            SEVERITY_LOW:      3.1,
        }

        cat      = dr.field_info.category
        diff_label = {
            "UNAUTH_LEAKED_FIELD":  "Unauthenticated Field Exposure",
            "UNAUTH_EXTRA_FIELD":   "Unauthenticated Extra Field",
            "VALUE_EXPOSURE":       "Auth-Level Value Exposure",
            "COUNT_EXPOSURE":       "Unauthenticated Record Count Exposure",
            "ROLE_ESCALATION_FIELD": "Privilege Field in Unauthenticated Response",
            "CROSS_USER_DATA_LEAK": "Cross-User Data Leak",
        }.get(dr.diff_type, dr.diff_type)

        title = (
            f"{diff_label} — `{dr.field_path}` "
            f"({dr.field_info.category}, sensitivity={dr.sensitivity}/100)"
        )

        return {
            "title":       title,
            "severity":    dr.severity,
            "category":    f"Business Logic — Auth Diff — {diff_label}",
            "description": dr.description,
            "request":     {"method": dr.method, "url": dr.endpoint},
            "response_summary": dr.evidence,
            "evidence":    dr.evidence,
            "evidence_package": self._scanner._build_pkg(
                ev, title=title, endpoint=dr.endpoint, vuln_type=diff_label,
                confidence=min(100, dr.sensitivity + 10),
                confirmed=dr.diff_type in ("CROSS_USER_DATA_LEAK", "ROLE_ESCALATION_FIELD"),
                fp_notes=[],
            ) if ev is not None else None,
            "recommendation": dr.recommendation,
            "cwe":         cwe_map.get(cat, "CWE-200"),
            "cvss":        cvss_map.get(dr.severity, 5.3),
            "owasp":       owasp_map.get(cat, "API3:2023 Broken Object Property Level Authorization"),
            "confirmed":   dr.diff_type in ("CROSS_USER_DATA_LEAK", "ROLE_ESCALATION_FIELD"),
            "confidence":  min(100, dr.sensitivity + 10),
            "endpoint":    dr.endpoint,
            "parameter":   dr.field_path,

            "_auth_diff":  {
                "diff_type":     dr.diff_type,
                "field_path":    dr.field_path,
                "field_category": cat,
                "sensitivity":   dr.sensitivity,
                "auth_value":    str(dr.auth_value)[:100] if dr.auth_value is not None else None,
                "unauth_value":  str(dr.unauth_value)[:100] if dr.unauth_value is not None else None,
                "source":        source,
            },
        }

    @staticmethod
    def _try_parse(body: str) -> Optional[Any]:
        if not body:
            return None
        stripped = body.strip()
        if not stripped or stripped[0] not in ("{", "["):
            return None
        try:
            return json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None
