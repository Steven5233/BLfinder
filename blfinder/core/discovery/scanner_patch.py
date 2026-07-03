"""
BLFinder v3.1 — core/discovery/scanner_patch.py
Fixes: coroutine leak, soft-404 over-skipping, missing PoC in reports.

FIX CHANGELOG:
  BUG-6  : Added disable_endpoint_validation() function.  Previously
            --no-validation was stored in config but never acted on because
            no code path in this file or scanner.py read it.  blfinder.py
            now calls disable_endpoint_validation() when the flag is set,
            and this function replaces _validate_endpoint on BLFScanner with
            a no-op that always returns True, bypassing EndpointValidator
            entirely.
"""

from __future__ import annotations
import asyncio
import json



import os as _os
import sys as _sys

# ── Debug logging for silently-swallowed exceptions ────────────────────────
# Set BLFINDER_DEBUG=1 in the environment to see what these except blocks
# were hiding (parse failures, timeouts, malformed responses, etc.) instead
# of endpoints silently disappearing with no trace.
_BLF_DEBUG = bool(_os.environ.get("BLFINDER_DEBUG"))


def _blf_dbg(where: str, err: BaseException) -> None:
    if _BLF_DEBUG:
        print(f"[debug] {where}: {type(err).__name__}: {err}", file=_sys.stderr)

_MIN_BODY = 15

_NEVER_SKIP_STATUSES = frozenset({
    200, 201, 202, 204, 206,
    301, 302, 307, 308,
    400, 401, 403, 405, 410, 422,
})

_API_BODY_PATTERNS = (
    b'"error"', b'"message"', b'"data"', b'"status"',
    b'"code"',  b'"result"',  b'"detail"', b'"errors"',
    b'{"', b'[{',
)


def _is_real_response(status: int, body: str) -> bool:
    if status in _NEVER_SKIP_STATUSES:
        return True
    if status == 0:
        return False
    if 500 <= status < 600:
        return len(body) > _MIN_BODY
    if len(body) < _MIN_BODY:
        return False
    body_bytes = body.encode("utf-8", errors="replace")[:500]
    if any(p in body_bytes for p in _API_BODY_PATTERNS):
        return True
    if status == 404:
        return False
    return len(body) > 100


def _build_poc(finding, token: str) -> dict:
    req    = getattr(finding, "request", {}) or {}
    method = req.get("method", "GET")
    url    = req.get("url",    "") or getattr(finding, "endpoint", "")
    body   = req.get("body")
    title  = getattr(finding, "title",          "")
    desc   = getattr(finding, "description",    "")
    evidence = getattr(finding, "evidence",     "See description")
    rec    = getattr(finding, "recommendation", "")

    # FIX (BUG-8 from scanner_integration review): use a placeholder instead
    # of the raw token in stored PoC output so credentials are not persisted
    # in reports, the database, or HackerOne drafts.  The real token is used
    # only for live requests, never stored in the PoC dict.
    token_display = "<YOUR_BEARER_TOKEN>" if token else ""
    auth_hdr  = f' -H "Authorization: Bearer {token_display}"' if token_display else ""
    body_part = ""
    if body and isinstance(body, dict):
        body_part = f" -d '{json.dumps(body)}'"

    curl = f"curl -sk -X {method}{auth_hdr}{body_part} '{url}'"

    steps = (
        f"1. Send the following HTTP request:\n"
        f"   {curl}\n\n"
        f"2. Observe the response confirms the vulnerability.\n\n"
        f"3. Evidence:\n   {evidence[:400]}"
    )

    python_lines = [
        "import requests",
        "",
        f'url = "{url}"',
    ]
    if token_display:
        python_lines += [
            f'headers = {{"Authorization": "Bearer {token_display}", '
            f'"Content-Type": "application/json"}}',
        ]
    else:
        python_lines += ['headers = {"Content-Type": "application/json"}']

    if body and isinstance(body, dict):
        python_lines += [
            f"body = {json.dumps(body, indent=4)}",
            f'resp = requests.{method.lower()}(url, json=body, headers=headers, verify=False)',
        ]
    else:
        python_lines += [
            f'resp = requests.{method.lower()}(url, headers=headers, verify=False)',
        ]
    python_lines += [
        "print(resp.status_code)",
        "print(resp.text[:500])",
    ]
    python_script = "\n".join(python_lines)

    body_str = ""
    if body and isinstance(body, dict):
        body_str = f"\r\n\r\n{json.dumps(body)}"

    path = "/"
    host = url
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.netloc
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
    except Exception as e:
        _blf_dbg("blfinder/core/discovery/scanner_patch.py#1", e)
        pass

    burp_raw = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
    )
    if token_display:
        burp_raw += f"Authorization: Bearer {token_display}\r\n"
    burp_raw += f"Connection: close{body_str}"

    h1_template = (
        f"## Summary\n{desc}\n\n"
        f"## Steps to Reproduce\n{steps}\n\n"
        f"## Impact\n{desc}\n\n"
        f"## Recommendation\n{rec}"
    )

    return {
        "curl":               curl,
        "python_script":      python_script,
        "burp_raw":           burp_raw,
        "hackerone_template": h1_template,
        "steps":              steps,
        "reproduction":       steps,
        "method":             method,
        "url":                url,
        "headers":            {"Authorization": f"Bearer {token_display}"} if token_display else {},
        "body":               body or {},
        "vulnerability":      title,
        "impact":             desc,
        "affected_endpoint":  url,
        "recommendation":     rec,
    }


def _ensure_poc(finding, config) -> None:
    if getattr(finding, "poc", None):
        return
    token = getattr(config, "auth_token", "") or ""
    finding.poc = _build_poc(finding, token)


def apply_patch() -> bool:
    try:
        from core.scanner import BLFScanner
    except ImportError:
        print("[!] scanner_patch: core.scanner not found — skipped")
        return False

    async def _run_endpoint_checks_fixed(
        self,
        url:    str,
        method: str,
        body:   dict,
        params: dict,
        meta:   dict = None,
    ):
        import core.scanner as _sm
        _HAS_VALIDATION = getattr(_sm, "_HAS_VALIDATION", False)
        _HAS_CLASSIFIER = getattr(_sm, "_HAS_CLASSIFIER", False)
        _HAS_IDOR_ENUM  = getattr(_sm, "_HAS_IDOR_ENUM",  False)

        findings = []

        self._update_dashboard(endpoint=url)
        if self._dashboard_state:
            self._dashboard_state.scanned_endpoints += 1
            while self._dashboard_state.paused:
                await asyncio.sleep(0.5)

        status, headers, base_body, elapsed = await self._request(
            method, url,
            json=body   if body   else None,
            params=params if params else None,
        )

        if not _is_real_response(status, base_body):
            if self.config.verbose:
                print(f"  [SKIP] {url[:70]} — status={status}, body={len(base_body)}B")
            return findings

        self.base_responses[url] = {
            "status":  status,
            "body":    base_body,
            "hash":    self._hash_response(base_body),
            "elapsed": elapsed,
            "headers": headers,
        }
        self._record_baseline_sample(url, base_body)

        if _HAS_IDOR_ENUM and self._idor_enumerator:
            self._idor_enumerator.harvest_ids(base_body)

        confidence_cap = 100
        if _HAS_VALIDATION and self._response_classifier:
            try:
                classified = self._response_classifier.classify(
                    url, status, headers, base_body, elapsed
                )
                self._classified_responses[url] = classified
                self.base_responses[url]["response_class"] = classified.response_class.value
                if classified.suppress_findings:
                    if self.config.verbose:
                        print(f"  [SUPPRESS] {url[:60]} — {classified.classification_note}")
                    return findings
                confidence_cap = classified.confidence_cap
                if self.config.verbose and classified.response_class.value != "REAL_API_JSON":
                    print(
                        f"  [CLASS] {url[:60]} → "
                        f"{classified.response_class.value} (cap={confidence_cap}%)"
                    )
            except Exception as e:
                if self.config.verbose:
                    print(f"  [CLASS error] {url[:60]}: {e}")

        skip_set: set = set(self._profile_skip_modules)
        if _HAS_CLASSIFIER and self._classifier:
            try:
                ep_profile = self._classifier.classify(url, body)
                skip_set.update(ep_profile.skip_modules)
            except Exception as e:
                _blf_dbg("blfinder/core/discovery/scanner_patch.py#2", e)
                pass

        all_checks = [
            ("price_manipulation",
             lambda: self._check_price_manipulation(
                 url, method, body, params, status, base_body)),
            ("negative_quantity",
             lambda: self._check_quantity_negative(
                 url, method, body, params, status, base_body)),
            ("workflow_bypass",
             lambda: self._check_workflow_bypass(
                 url, method, body, params, status, base_body)),
            ("mass_assignment",
             lambda: self._check_mass_assignment(
                 url, method, body, params, status, base_body)),
            ("idor_bola",
             lambda: self._check_idor_bola(
                 url, method, body, params, status, base_body, headers)),
            ("bopla",
             lambda: self._check_bopla(
                 url, method, body, params, status, base_body)),
            ("privilege_escalation",
             lambda: self._check_privilege_escalation(
                 url, method, body, params, status, base_body)),
            ("bfla",
             lambda: self._check_function_level_access(
                 url, method, body, params, status, base_body)),
            ("coupon_stacking",
             lambda: self._check_coupon_stacking(
                 url, method, body, params, status, base_body)),
            ("time_bypass",
             lambda: self._check_time_logic_bypass(
                 url, method, body, params, status, base_body)),
            ("integer_overflow",
             lambda: self._check_integer_overflow(
                 url, method, body, params, status, base_body)),
            ("hidden_parameter",
             lambda: self._check_hidden_parameter_disclosure(
                 url, method, body, params, status, base_body)),
            ("state_machine_abuse",
             lambda: self._check_state_machine_abuse(
                 url, method, body, params, status, base_body)),
            ("race_condition",
             lambda: self._check_race_condition(
                 url, method, body, params, status, base_body)),
            ("jwt_manipulation",
             lambda: self._check_jwt_manipulation(
                 url, method, body, params, status, base_body, headers)),
            ("account_enumeration",
             lambda: self._check_account_enumeration(
                 url, method, body, params, status, base_body)),
            ("limit_offset",
             lambda: self._check_limit_offset_manipulation(
                 url, method, body, params, status, base_body)),
            ("soft_delete_bypass",
             lambda: self._check_soft_delete_bypass(
                 url, method, body, params, status, base_body)),
            ("http_method_override",
             lambda: self._check_http_method_override(
                 url, method, body, params, status, base_body)),
            ("parameter_pollution",
             lambda: self._check_parameter_pollution(
                 url, method, body, params, status, base_body)),
            ("blind_idor",
             lambda: self._check_blind_idor(
                 url, method, body, params, status, base_body)),
        ]

        coros = [fn() for name, fn in all_checks if name not in skip_set]
        results = await asyncio.gather(*coros, return_exceptions=True)

        raw_findings: list = []
        for r in results:
            if isinstance(r, list):
                raw_findings.extend(r)
            elif isinstance(r, Exception) and self.config.verbose:
                print(f"  [!] Module error: {r}")

        for f in raw_findings:
            if confidence_cap < 100:
                f.confidence = min(getattr(f, "confidence", 0), confidence_cap)
            _ensure_poc(f, self.config)
            findings.append(f)
            self._update_dashboard(finding=f)
            if self._findings_queue:
                try:
                    self._findings_queue.put_nowait(f)
                except asyncio.QueueFull:
                    pass

        return findings

    BLFScanner._run_endpoint_checks = _run_endpoint_checks_fixed

    try:
        from core.poc import PoCGenerator
        _orig_generate = PoCGenerator.generate

        def _generate_with_fallback(self_pg, finding):
            result = _orig_generate(self_pg, finding)
            if result:
                return result
            token = getattr(self_pg.config, "auth_token", "") if hasattr(self_pg, "config") else ""
            return _build_poc(finding, token)

        PoCGenerator.generate = _generate_with_fallback
    except ImportError:
        pass

    return True


# ─────────────────────────────────────────────────────────────────────────────
# FIX (BUG-6): disable_endpoint_validation()
# ─────────────────────────────────────────────────────────────────────────────

def disable_endpoint_validation() -> bool:
    """
    Bypass EndpointValidator entirely so that --no-validation scans ALL
    discovered endpoints regardless of response type.

    blfinder.py calls this after apply_patch() when config.no_validation
    is True.  Previously --no-validation was stored in config but never
    acted on — this function is what makes the flag actually work.

    Approach: replace BLFScanner._validate_endpoint with an async no-op
    that always returns True (i.e. "endpoint is valid, do not skip").

    Returns True if the patch was applied, False if core.scanner is absent.
    """
    try:
        from core.scanner import BLFScanner
    except ImportError:
        return False

    # Check whether the scanner exposes a _validate_endpoint hook.
    # If it does, replace it.  If not, replace the EndpointValidator
    # attribute in __aenter__ so it never runs validate().
    if hasattr(BLFScanner, "_validate_endpoint"):
        async def _always_valid(self, endpoint):
            return True

        BLFScanner._validate_endpoint = _always_valid
        return True

    # Fallback: patch __aenter__ to set _endpoint_validator to None after
    # it is initialised, which causes all conditional checks of the form
    # `if self._endpoint_validator:` to skip the validation block.
    _orig_aenter = BLFScanner.__aenter__

    async def _aenter_no_validation(self):
        result = await _orig_aenter(self)
        # Null out the validator so every endpoint passes through
        self._endpoint_validator = None
        return result

    BLFScanner.__aenter__ = _aenter_no_validation
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import warnings

    print("=" * 56)
    print("scanner_patch.py — self-test")
    print("=" * 56)

    print("\n[TEST 1] _is_real_response")
    cases = [
        (200, '{"user_id": 1}',                   True,  "200 JSON"),
        (401, '{"error": "unauthorized"}',         True,  "401 auth required"),
        (403, "Forbidden",                          True,  "403 exists"),
        (400, '{"message": "bad request"}',        True,  "400 validation"),
        (405, "Method Not Allowed",                 True,  "405 method"),
        (422, '{"errors": {"price": "invalid"}}',  True,  "422 validation"),
        (0,   "",                                   False, "0 failed"),
        (200, "",                                   True,  "200 empty — always scan"),
        (200, "ok",                                 True,  "200 tiny — always scan"),
        (404, "<html><body>404</body></html>",      False, "404 HTML"),
        (200, '{"data": [], "total": 0}',           True,  "200 API data key"),
    ]
    all_pass = True
    for status, body, expect, label in cases:
        got = _is_real_response(status, body)
        ok  = got == expect
        if not ok:
            all_pass = False
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            print(f"         expected={expect}, got={got}")

    print("\n[TEST 2] Lambda — no coroutine warnings")

    async def _dummy():
        return []

    skip_set = {"price_manipulation", "race_condition"}
    all_checks = [
        ("price_manipulation", lambda: _dummy()),
        ("negative_quantity",  lambda: _dummy()),
        ("race_condition",     lambda: _dummy()),
        ("idor_bola",          lambda: _dummy()),
    ]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        coros = [fn() for name, fn in all_checks if name not in skip_set]
        async def _run():
            return await asyncio.gather(*coros, return_exceptions=True)
        asyncio.run(_run())
    leaked = [w for w in caught if issubclass(w.category, RuntimeWarning)
              and "coroutine" in str(w.message).lower()]
    if leaked:
        all_pass = False
        print(f"  FAIL — {len(leaked)} warnings")
    else:
        print("  PASS")

    print("\n[TEST 3] _build_poc produces all required keys with token placeholder")

    class FC:
        auth_token = "tok123"

    class FF:
        request        = {"method": "POST", "url": "https://api.x.com/checkout", "body": {"price": 0}}
        endpoint       = "https://api.x.com/checkout"
        title          = "Price Manipulation"
        description    = "Price accepted as 0"
        evidence       = "price=0 returned 200"
        recommendation = "Validate server-side"
        poc            = None

    f = FF()
    _ensure_poc(f, FC())
    required_keys = ["curl", "python_script", "burp_raw", "hackerone_template", "steps"]
    for k in required_keys:
        ok = k in f.poc and bool(f.poc[k])
        if not ok:
            all_pass = False
        print(f"  [{'PASS' if ok else 'FAIL'}] poc['{k}'] present and non-empty")

    # FIX (BUG-8): token placeholder must appear, not raw token
    assert "<YOUR_BEARER_TOKEN>" in f.poc["curl"],          "placeholder in curl"
    assert "<YOUR_BEARER_TOKEN>" in f.poc["python_script"], "placeholder in python"
    assert "<YOUR_BEARER_TOKEN>" in f.poc["burp_raw"],      "placeholder in burp"
    assert "tok123" not in f.poc["curl"],                   "raw token NOT in curl"
    print("  PASS — token placeholder used, raw token not stored")

    print("\n[TEST 4] _ensure_poc does not overwrite existing PoC")

    class FFExisting:
        poc            = {"curl": "existing curl", "steps": "existing steps"}
        request        = {}
        endpoint       = ""
        title          = ""
        description    = ""
        evidence       = ""
        recommendation = ""

    f2 = FFExisting()
    _ensure_poc(f2, FC())
    assert f2.poc["curl"] == "existing curl"
    print("  PASS")

    print("\n[TEST 5] NEVER_SKIP_STATUSES")
    for s in [200, 201, 401, 403, 405, 422]:
        assert s in _NEVER_SKIP_STATUSES, f"{s} missing"
    assert 0   not in _NEVER_SKIP_STATUSES
    assert 404 not in _NEVER_SKIP_STATUSES
    print(f"  PASS — {len(_NEVER_SKIP_STATUSES)} statuses")

    print("\n[TEST 6] disable_endpoint_validation() is callable")
    result = disable_endpoint_validation()
    print(
        f"  result={result} "
        f"({'no core.scanner — expected in isolation' if not result else 'patch applied'})"
    )
    print("  PASS")

    print()
    if all_pass:
        print("=" * 56)
        print("All tests passed.")
        print("=" * 56)
    else:
        print("SOME TESTS FAILED")
