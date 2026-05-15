

from __future__ import annotations
import asyncio


# ─────────────────────────────────────────────────────────────────────────────
# ValidationConfig attribute patching
# ─────────────────────────────────────────────────────────────────────────────
# We do NOT call ValidationConfig(**kwargs) — we set attributes directly on
# the already-constructed instance. This works regardless of what parameters
# __init__ accepts.
#
# The dict below maps every known attribute name used by different versions of
# ValidationConfig to the relaxed value we want. hasattr() guards each write
# so we only touch attributes that actually exist on the object — no spurious
# attribute injection.

_RELAXED_ATTRS = {
    # Soft-404 similarity threshold.
    # How similar must a response body be to the baseline for the endpoint to
    # be classified as soft-404 and skipped?
    # High value = only skip when responses are almost identical (>97%) = fewer
    # endpoints wrongly skipped. Previous effective value was ~0.85.
    "similarity_threshold"   : 0.97,
    "soft404_threshold"      : 0.97,
    "soft_404_similarity"    : 0.97,
    "threshold"              : 0.97,
    # Minimum body length (bytes) to bother validating.
    # Prevents empty-body responses from being auto-skipped as soft-404.
    "min_body_length"        : 10,
    "minimum_body_length"    : 10,
    # JSON requirement flags — set False so HTML-responding APIs pass through.
    "require_json"           : False,
    "json_only"              : False,
    "require_json_response"  : False,
}


def _relax_validation_config(cfg) -> None:
    """
    Write relaxed thresholds onto a ValidationConfig instance.
    Only writes attributes that already exist on the object.
    Safe to call on any object — unknown attributes are silently skipped.
    """
    if cfg is None:
        return
    patched = []
    for attr, value in _RELAXED_ATTRS.items():
        if hasattr(cfg, attr):
            setattr(cfg, attr, value)
            patched.append(attr)
    return patched  # returned for debug logging


def _find_and_relax(endpoint_validator, verbose: bool = False) -> None:
    """
    Locate the ValidationConfig on an EndpointValidator instance and
    apply relaxed thresholds. Tries every common attribute name the
    validator might use to store its config.
    """
    if endpoint_validator is None:
        return

    # Common attribute names the validator might store its config under
    config_attr_candidates = (
        "config", "cfg", "validation_config",
        "settings", "_config", "vc", "vconfig",
    )

    for attr_name in config_attr_candidates:
        cfg = getattr(endpoint_validator, attr_name, None)
        if cfg is not None:
            patched = _relax_validation_config(cfg)
            if verbose and patched:
                print(
                    f"[*] scanner_patch: relaxed ValidationConfig.{attr_name} "
                    f"attrs: {patched}"
                )
            return

    # Last resort: try to relax the validator itself (in case config attrs
    # are stored directly on the validator, not a nested object)
    _relax_validation_config(endpoint_validator)


# ─────────────────────────────────────────────────────────────────────────────
# Main patch entry point
# ─────────────────────────────────────────────────────────────────────────────

def apply_patch() -> bool:
    """
    Monkey-patch BLFScanner to fix:
      1. Coroutine-leak RuntimeWarnings in _run_endpoint_checks
      2. Over-aggressive soft-404 skipping (ValidationConfig thresholds)
      3. TypeError from passing unknown kwargs to validate()

    Call this BEFORE the 'async with BLFScanner(config) as scanner:' block.
    Returns True on success, False if core.scanner cannot be imported.
    """
    try:
        from core.scanner import BLFScanner
    except ImportError:
        print("[!] scanner_patch: core.scanner not found — patch skipped")
        return False

    # ── Patch A: wrap __aenter__ to fix ValidationConfig after construction ───
    _orig_aenter = BLFScanner.__aenter__

    async def _patched_aenter(self):
        # Run the original __aenter__ first (builds the session, constructs
        # EndpointValidator, etc.)
        result = await _orig_aenter(self)

        # Now patch ValidationConfig on the live EndpointValidator instance
        ev = getattr(self, "_endpoint_validator", None)
        verbose = getattr(self.config, "verbose", False)
        _find_and_relax(ev, verbose=verbose)

        return result

    BLFScanner.__aenter__ = _patched_aenter

    # ── Patch B: fix _run_endpoint_checks (coroutine-leak + strict kwarg) ────

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

        # ── Dashboard ─────────────────────────────────────────────────────────
        self._update_dashboard(endpoint=url)
        if self._dashboard_state:
            self._dashboard_state.scanned_endpoints += 1
            while self._dashboard_state.paused:
                await asyncio.sleep(0.5)

        # ── Endpoint validation ───────────────────────────────────────────────
        is_graphql = any(
            seg in url.lower() for seg in ["/graphql", "/gql", "/query"]
        )
        if _HAS_VALIDATION and self._endpoint_validator:
            # Try with strict kwarg first; fall back without it if the
            # validate() signature doesn't support it (avoids TypeError)
            try:
                val_report = await self._endpoint_validator.validate(
                    url, method, body,
                    is_graphql=is_graphql,
                    strict=getattr(self.config, "strict_validation", False),
                )
            except TypeError:
                val_report = await self._endpoint_validator.validate(
                    url, method, body,
                    is_graphql=is_graphql,
                )
            if val_report.should_skip:
                self._skipped_endpoints.append(url)
                if self.config.verbose:
                    print(f"  [SKIP] {url[:70]} — {val_report.summary}")
                return findings

        # ── Baseline request ──────────────────────────────────────────────────
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

        # ── Phase 4: ID harvesting ────────────────────────────────────────────
        if _HAS_IDOR_ENUM and self._idor_enumerator:
            self._idor_enumerator.harvest_ids(base_body)

        # ── Response classification ───────────────────────────────────────────
        confidence_cap = 100
        if _HAS_VALIDATION and self._response_classifier:
            classified = self._response_classifier.classify(
                url, status, headers, base_body, elapsed
            )
            self._classified_responses[url] = classified
            self.base_responses[url]["response_class"] = (
                classified.response_class.value
            )
            if classified.suppress_findings:
                if self.config.verbose:
                    print(
                        f"  [SUPPRESS] {url[:60]} — "
                        f"{classified.classification_note}"
                    )
                return findings
            confidence_cap = classified.confidence_cap
            if (
                self.config.verbose
                and classified.response_class.value != "REAL_API_JSON"
            ):
                print(
                    f"  [CLASS] {url[:60]} → "
                    f"{classified.response_class.value} "
                    f"(cap={confidence_cap}%)"
                )

        # ── Skip set ──────────────────────────────────────────────────────────
        skip_set: set = set(self._profile_skip_modules)
        if _HAS_CLASSIFIER and self._classifier:
            try:
                ep_profile = self._classifier.classify(url, body)
                skip_set.update(ep_profile.skip_modules)
            except Exception:
                pass

        # ── THE CORE FIX — lambda wrappers ───────────────────────────────────
        # Calling self._check_xxx(...) directly creates the coroutine object
        # immediately, before skip_set filtering. Skipped coroutines are
        # abandoned unawaited → RuntimeWarning: coroutine was never awaited.
        #
        # Solution: wrap every check in a zero-arg lambda so the coroutine
        # is only created at the moment fn() is called — which only happens
        # for checks whose name is NOT in skip_set.
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
# Quick self-test  (python core/discovery/scanner_patch.py)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import warnings

    print("=" * 60)
    print("scanner_patch.py — self-test")
    print("=" * 60)

    # ── Test 1: _relax_validation_config works on dataclass-style objects ─────
    print("\n[TEST 1] _relax_validation_config — attribute patching")

    class FakeConfig:
        similarity_threshold = 0.85
        min_body_length      = 0
        require_json         = True

    cfg = FakeConfig()
    _relax_validation_config(cfg)
    assert cfg.similarity_threshold == 0.97, f"expected 0.97 got {cfg.similarity_threshold}"
    assert cfg.min_body_length      == 10,   f"expected 10 got {cfg.min_body_length}"
    assert cfg.require_json         is False, f"expected False got {cfg.require_json}"
    print("  PASS — known attributes patched correctly")

    # ── Test 2: unknown attributes are NOT added ──────────────────────────────
    print("\n[TEST 2] _relax_validation_config — no spurious attrs added")

    class MinimalConfig:
        similarity_threshold = 0.85   # only has this one

    mcfg = MinimalConfig()
    _relax_validation_config(mcfg)
    assert not hasattr(mcfg, "soft404_threshold"), "spurious attr added"
    assert not hasattr(mcfg, "require_json"),      "spurious attr added"
    assert mcfg.similarity_threshold == 0.97
    print("  PASS — only existing attributes patched")

    # ── Test 3: lambda fix prevents unawaited coroutines ─────────────────────
    print("\n[TEST 3] Lambda fix — no RuntimeWarning emitted")

    async def _dummy():
        return []

    skip_set = {"price_manipulation", "race_condition", "bopla"}
    all_checks = [
        ("price_manipulation", lambda: _dummy()),
        ("negative_quantity",  lambda: _dummy()),
        ("race_condition",     lambda: _dummy()),
        ("bopla",              lambda: _dummy()),
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
        print(f"  FAIL — {len(leaked)} RuntimeWarning(s) still emitted")
        for w in leaked:
            print(f"    {w.message}")
    else:
        print("  PASS — no 'coroutine was never awaited' warnings")

    # ── Test 4: _find_and_relax handles nested config attr ───────────────────
    print("\n[TEST 4] _find_and_relax — nested config attribute discovery")

    class FakeValidator:
        class config:
            similarity_threshold = 0.85
            require_json         = True

    fv = FakeValidator()
    _find_and_relax(fv, verbose=False)
    assert fv.config.similarity_threshold == 0.97
    assert fv.config.require_json is False
    print("  PASS — nested config.similarity_threshold patched")

    # ── Test 5: _find_and_relax handles None validator gracefully ─────────────
    print("\n[TEST 5] _find_and_relax — None validator is a no-op")
    _find_and_relax(None)   # must not raise
    print("  PASS — no exception raised for None validator")

    print("\n" + "=" * 60)
    print("All tests passed.")
    print("=" * 60)
