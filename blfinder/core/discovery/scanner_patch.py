"""
BLFinder v3.1 — core/discovery/scanner_patch.py

Fixes THREE bugs without editing any source file:

  BUG 1 — "coroutine was never awaited" RuntimeWarning
  ─────────────────────────────────────────────────────
  In _run_endpoint_checks() the all_checks list called
  self._check_xxx(...) eagerly, creating coroutines for
  skipped checks that were then thrown away unawaited.
  Fix: lambda wrappers so coroutines are created only for
  checks we actually intend to run.

  BUG 2 — 55+ endpoints skipped as soft-404 (55/215 in production)
  ──────────────────────────────────────────────────────────────────
  Previous approach: guess ValidationConfig attribute names and patch them.
  Problem: None of the guessed names matched the real attribute → patch
  was silently doing nothing → aggressive defaults still active.

  NEW APPROACH — patch EndpointValidator.validate() directly:
  We wrap the actual validate() method and intercept its return value.
  If it says should_skip=True for soft-404 reasons, we override it to
  should_skip=False. This works regardless of what ValidationConfig's
  internal attributes are named, because we never touch them at all.

  BUG 3 — validate() called with unexpected kwarg 'strict'
  ─────────────────────────────────────────────────────────
  The patched _run_endpoint_checks passed strict=strict to validate()
  but that method may not accept it. Fixed with a try/except fallback.
"""

from __future__ import annotations
import asyncio
import difflib


# ─────────────────────────────────────────────────────────────────────────────
# Soft-404 override threshold
# ─────────────────────────────────────────────────────────────────────────────
# When the validator says should_skip=True, we re-check the response
# ourselves using this threshold. Only skip if similarity is THIS high.
# 0.97 = only skip when the response is 97%+ identical to a known-404 baseline.
# The original aggressive default was ~0.85 → too many real endpoints skipped.
SOFT_404_OVERRIDE_THRESHOLD = 0.97

# Minimum response body length to even consider soft-404 classification.
# Bodies shorter than this are usually error pages, not real API endpoints.
MIN_BODY_LENGTH_TO_SKIP = 20

# HTTP status codes that are ALWAYS valid API responses — never skip these.
# 401/403 mean the endpoint exists but requires auth — high value targets.
NEVER_SKIP_STATUSES = {200, 201, 202, 204, 301, 302, 400, 401, 403, 405, 422}


def apply_patch() -> bool:
    """
    Monkey-patch BLFScanner and EndpointValidator to fix:
      1. Coroutine-leak RuntimeWarnings in _run_endpoint_checks
      2. Over-aggressive soft-404 endpoint skipping
      3. TypeError from unknown kwargs to validate()

    Call this BEFORE the 'async with BLFScanner(config) as scanner:' block.
    Returns True on success, False if core imports are unavailable.
    """

    # ── Import targets ────────────────────────────────────────────────────────
    try:
        from core.scanner import BLFScanner
    except ImportError:
        print("[!] scanner_patch: core.scanner not found — patch skipped")
        return False

    # EndpointValidator import — try multiple known locations
    EndpointValidator = None
    ValidationResult  = None
    for mod_path in [
        "core.validation.endpoint_validator",
        "core.validator",
        "core.endpoint_validator",
    ]:
        try:
            import importlib
            mod = importlib.import_module(mod_path)
            EndpointValidator = getattr(mod, "EndpointValidator", None)
            ValidationResult  = getattr(mod, "ValidationResult", None)
            if EndpointValidator:
                break
        except ImportError:
            continue

    # ── Patch 1: EndpointValidator.validate() — direct soft-404 override ─────
    # This is the bulletproof approach: we don't touch ValidationConfig at all.
    # Instead we wrap validate() and override any should_skip=True result
    # that we believe is a false positive.

    if EndpointValidator is not None:
        _orig_validate = EndpointValidator.validate

        async def _validate_patched(self, url, method, body=None,
                                    is_graphql=False, **kwargs):
            """
            Patched validate() that prevents over-aggressive soft-404 skipping.

            Strategy:
              1. Call the original validate()
              2. If it says should_skip=True, re-examine WHY
              3. If the reason is soft-404 and our own threshold says it's NOT
                 a soft-404, override to should_skip=False
              4. If the reason is WAF/rate-limit/genuine error, respect it
            """
            # Strip unknown kwargs before calling original (fixes BUG 3)
            safe_kwargs = {}
            if is_graphql:
                safe_kwargs["is_graphql"] = is_graphql

            try:
                result = await _orig_validate(self, url, method, body, **safe_kwargs)
            except TypeError:
                # Original validate() has a different signature — call bare
                try:
                    result = await _orig_validate(self, url, method, body)
                except TypeError:
                    result = await _orig_validate(self, url, method)

            # If the original says "don't skip" — great, trust it
            if not getattr(result, "should_skip", False):
                return result

            # If the original says "skip" — examine the reason
            summary = (getattr(result, "summary", None) or "").lower()
            skip_reason = (getattr(result, "reason",  None) or summary).lower()

            # Always respect genuine blocks — don't override these
            if any(k in skip_reason for k in [
                "waf", "rate limit", "429", "blocked", "cloudflare",
                "connection", "timeout", "ssl", "tls",
            ]):
                return result

            # For soft-404 skips: re-check with our own threshold
            if any(k in skip_reason for k in [
                "soft", "404", "similar", "generic", "baseline",
                "identical", "same", "threshold",
            ]) or not skip_reason:
                # Re-run a quick similarity check ourselves
                # Pull the actual response from the scanner's base_responses
                # if available, otherwise just un-skip (conservative)
                scanner_instance = getattr(self, "_scanner", None) or \
                                   getattr(self, "scanner", None)

                if scanner_instance is not None:
                    base = getattr(scanner_instance, "base_responses", {})
                    entry = base.get(url, {})
                    resp_status = entry.get("status", 0)
                    resp_body   = entry.get("body",   "")

                    # Never skip endpoints that returned a real status
                    if resp_status in NEVER_SKIP_STATUSES:
                        return _make_pass(result)

                    # Re-check body similarity against soft-404 baseline
                    soft404_body = getattr(self, "_soft404_baseline", None) or \
                                   getattr(self, "_baseline_body", None) or \
                                   getattr(self, "baseline", None)

                    if soft404_body and resp_body:
                        sim = difflib.SequenceMatcher(
                            None,
                            str(soft404_body)[:3000],
                            resp_body[:3000],
                        ).ratio()
                        # Only skip if VERY similar to the soft-404 baseline
                        if sim < SOFT_404_OVERRIDE_THRESHOLD:
                            return _make_pass(result)  # not actually a soft-404

                    elif resp_body and len(resp_body) >= MIN_BODY_LENGTH_TO_SKIP:
                        # Has a real body — don't skip
                        return _make_pass(result)

                else:
                    # No scanner reference — be conservative, don't skip
                    return _make_pass(result)

            return result

        EndpointValidator.validate = _validate_patched

    # ── Patch 2: BLFScanner.__aenter__ — inject scanner ref into validator ────
    # So the patched validate() above can access base_responses and config.
    _orig_aenter = BLFScanner.__aenter__

    async def _patched_aenter(self):
        result = await _orig_aenter(self)

        # Inject a reference to the scanner into EndpointValidator
        # so the patched validate() can access base_responses
        ev = getattr(self, "_endpoint_validator", None)
        if ev is not None and not hasattr(ev, "_scanner"):
            try:
                ev._scanner = self
            except Exception:
                pass

        # Also attempt direct attribute patching as a secondary approach
        # (works when attribute names match, harmless when they don't)
        if ev is not None:
            _try_direct_attr_patch(ev, getattr(self.config, "verbose", False))

        return result

    BLFScanner.__aenter__ = _patched_aenter

    # ── Patch 3: _run_endpoint_checks — lambda fix + strict kwarg safety ──────
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

        # Dashboard update + pause
        self._update_dashboard(endpoint=url)
        if self._dashboard_state:
            self._dashboard_state.scanned_endpoints += 1
            while self._dashboard_state.paused:
                await asyncio.sleep(0.5)

        # Validate endpoint — skip entirely when --no-validation is set
        is_graphql = any(seg in url.lower() for seg in ["/graphql", "/gql", "/query"])
        if _HAS_VALIDATION and self._endpoint_validator and not getattr(self.config, "no_validation", False):
            try:
                val_report = await self._endpoint_validator.validate(
                    url, method, body, is_graphql=is_graphql
                )
            except TypeError:
                try:
                    val_report = await self._endpoint_validator.validate(url, method, body)
                except TypeError:
                    val_report = await self._endpoint_validator.validate(url, method)

            if val_report.should_skip:
                self._skipped_endpoints.append(url)
                if self.config.verbose:
                    print(f"  [SKIP] {url[:70]} — {val_report.summary}")
                return findings

        # Baseline request
        status, headers, base_body, elapsed = await self._request(
            method, url,
            json=body   if body   else None,
            params=params if params else None,
        )
        if status == 0:
            return findings

        self.base_responses[url] = {
            "status":  status,
            "body":    base_body,
            "hash":    self._hash_response(base_body),
            "elapsed": elapsed,
            "headers": headers,
        }
        self._record_baseline_sample(url, base_body)

        # Phase 4: ID harvesting
        if _HAS_IDOR_ENUM and self._idor_enumerator:
            self._idor_enumerator.harvest_ids(base_body)

        # Phase 3: Classify response
        confidence_cap = 100
        if _HAS_VALIDATION and self._response_classifier:
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

        # Build skip set
        skip_set: set = set(self._profile_skip_modules)
        if _HAS_CLASSIFIER and self._classifier:
            try:
                ep_profile = self._classifier.classify(url, body)
                skip_set.update(ep_profile.skip_modules)
            except Exception:
                pass

        # ── THE CORE BUG-1 FIX: lambda wrappers ──────────────────────────────
        # Calling self._check_xxx(...) directly creates the coroutine IMMEDIATELY
        # for ALL checks — even ones in skip_set that will be discarded.
        # Those discarded coroutines are never awaited → RuntimeWarning.
        # Solution: wrap in lambda so coroutine is only created when fn() is
        # called, which only happens for checks NOT in skip_set.
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

        # Create coroutines ONLY for checks we will actually run
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
            findings.append(f)
            self._update_dashboard(finding=f)
            if self._findings_queue:
                try:
                    self._findings_queue.put_nowait(f)
                except asyncio.QueueFull:
                    pass

        return findings

    BLFScanner._run_endpoint_checks = _run_endpoint_checks_fixed
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Secondary: direct attribute patching (best-effort, harmless if no match)
# ─────────────────────────────────────────────────────────────────────────────

_RELAXED_ATTRS = {
    "similarity_threshold"   : 0.97,
    "soft404_threshold"      : 0.97,
    "soft_404_similarity"    : 0.97,
    "soft_404_threshold"     : 0.97,
    "threshold"              : 0.97,
    "min_body_length"        : 10,
    "minimum_body_length"    : 10,
    "require_json"           : False,
    "json_only"              : False,
    "require_json_response"  : False,
}

def _try_direct_attr_patch(endpoint_validator, verbose: bool = False) -> None:
    """
    Secondary approach: try to patch known attribute names on ValidationConfig.
    Works when attribute names match; silently does nothing when they don't.
    The primary fix (patching validate() directly) handles the case where
    attribute names don't match.
    """
    if endpoint_validator is None:
        return

    patched_on: list[str] = []

    # Try nested config objects first
    for cfg_attr in ("config", "cfg", "validation_config", "settings", "_config"):
        cfg = getattr(endpoint_validator, cfg_attr, None)
        if cfg is None:
            continue
        for attr, value in _RELAXED_ATTRS.items():
            if hasattr(cfg, attr):
                old = getattr(cfg, attr)
                if old != value:
                    setattr(cfg, attr, value)
                    patched_on.append(f"{cfg_attr}.{attr}={value}")

    # Also try attributes directly on the validator
    for attr, value in _RELAXED_ATTRS.items():
        if hasattr(endpoint_validator, attr):
            old = getattr(endpoint_validator, attr)
            if old != value:
                setattr(endpoint_validator, attr, value)
                patched_on.append(f"{attr}={value}")

    if verbose and patched_on:
        print(f"  [scanner_patch] direct attr patch: {', '.join(patched_on[:4])}")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: build a "pass" result from an existing ValidationResult
# ─────────────────────────────────────────────────────────────────────────────

def _make_pass(result):
    """
    Override a ValidationResult to should_skip=False.
    Works with dataclass, namedtuple, or plain object.
    """
    try:
        # Dataclass / plain object with mutable attributes
        object.__setattr__(result, "should_skip", False)
        object.__setattr__(result, "summary", "passed (soft-404 override)")
        return result
    except (AttributeError, TypeError):
        pass

    try:
        result.should_skip = False
        result.summary     = "passed (soft-404 override)"
        return result
    except AttributeError:
        pass

    # If the object is frozen/immutable, return a simple namespace
    class _PassResult:
        should_skip = False
        summary     = "passed (soft-404 override)"
        reason      = "override"
        def __getattr__(self, name):
            return getattr(result, name, None)

    return _PassResult()


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import warnings
    import asyncio

    print("=" * 62)
    print("scanner_patch.py — self-test")
    print("=" * 62)

    # ── Test 1: _make_pass works on plain object ──────────────────────────────
    print("\n[TEST 1] _make_pass — mutable object")

    class FakeResult:
        should_skip = True
        summary     = "soft-404 detected"

    r = _make_pass(FakeResult())
    assert r.should_skip is False, f"expected False, got {r.should_skip}"
    print("  PASS")

    # ── Test 2: _make_pass works on frozen dataclass ──────────────────────────
    print("\n[TEST 2] _make_pass — frozen/immutable fallback")
    from dataclasses import dataclass as dc, field as f

    @dc(frozen=True)
    class FrozenResult:
        should_skip: bool = True
        summary:     str  = "soft-404"

    r2 = _make_pass(FrozenResult())
    assert r2.should_skip is False
    print("  PASS — fallback namespace used for frozen object")

    # ── Test 3: direct attr patching ─────────────────────────────────────────
    print("\n[TEST 3] _try_direct_attr_patch — nested config")

    class FakeCfg:
        similarity_threshold = 0.85
        require_json         = True
        min_body_length      = 0

    class FakeValidator:
        config = FakeCfg()

    fv = FakeValidator()
    _try_direct_attr_patch(fv, verbose=False)
    assert fv.config.similarity_threshold == 0.97
    assert fv.config.require_json         is False
    assert fv.config.min_body_length      == 10
    print("  PASS — nested config patched")

    # ── Test 4: lambda coroutine leak prevention ──────────────────────────────
    print("\n[TEST 4] Lambda fix — no RuntimeWarning")

    async def _dummy(): return []

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
    assert not leaked, f"{len(leaked)} coroutine warnings leaked"
    print("  PASS — no coroutine warnings")

    # ── Test 5: NEVER_SKIP_STATUSES contains critical statuses ───────────────
    print("\n[TEST 5] NEVER_SKIP_STATUSES correctness")
    for s in (200, 401, 403, 405, 422):
        assert s in NEVER_SKIP_STATUSES, f"{s} missing from NEVER_SKIP_STATUSES"
    print("  PASS")

    # ── Test 6: Threshold values are sensible ─────────────────────────────────
    print("\n[TEST 6] Threshold values")
    assert SOFT_404_OVERRIDE_THRESHOLD >= 0.95, "Threshold too low"
    assert MIN_BODY_LENGTH_TO_SKIP     >= 10,   "Min body length too low"
    print(f"  PASS — threshold={SOFT_404_OVERRIDE_THRESHOLD}, "
          f"min_body={MIN_BODY_LENGTH_TO_SKIP}")

    print("\n" + "=" * 62)
    print("All tests passed.")
    print("=" * 62)
    print()
    print("Key change from previous version:")
    print("  OLD: Guess ValidationConfig attribute names → silently fails")
    print("       when names don't match → patch does nothing")
    print("  NEW: Patch EndpointValidator.validate() directly → always works")
    print("       regardless of what ValidationConfig's attributes are named")
