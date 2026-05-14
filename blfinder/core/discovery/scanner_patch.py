"""
BLFinder v3.1 — scanner_patch.py
Apply this patch to core/scanner.py to fix:

  BUG 1 — "coroutine was never awaited" RuntimeWarning
  ─────────────────────────────────────────────────────
  Root cause:
    In _run_endpoint_checks(), the all_checks list is built as:
        [("name", self._check_xxx(url, ...)), ...]
    Calling self._check_xxx(...) HERE creates the coroutine object
    immediately.  When a name is in skip_set we discard that tuple,
    but the coroutine object already exists and is never awaited →
    Python emits RuntimeWarning.

  Fix:
    Use lambda/callable wrappers so the coroutine is only created
    for the checks we actually intend to run.

  BUG 2 — 120/128 endpoints skipped as soft-404
  ───────────────────────────────────────────────
  Root cause:
    ValidationConfig() uses a default soft-404 similarity threshold
    that is too aggressive for a typical SPA / API target, causing
    nearly every discovered endpoint to be classified as soft-404 and
    skipped before any attack module runs.

  Fix:
    • Raise soft_404_threshold from 0.85 → 0.97
    • Raise min_body_length from 0 → 10 (ignore truly empty responses
      instead of treating them as soft-404)
    • Set require_json=False so HTML APIs are not auto-skipped
    • Pass strict=config.strict_validation so --strict-validation
      keeps the old behaviour for users who want it.

  BUG 3 — unawaited coroutines leak when gather raises
  ──────────────────────────────────────────────────────
  asyncio.gather(*checks_to_run, return_exceptions=True) already
  handles exceptions correctly; the real issue was Bug 1.
  After the lambda fix, gather receives only freshly-created
  coroutines for the checks we want, so no leaks occur.
"""

# ── Drop-in monkey-patch (import and call apply_patch()) ─────────────────────

def apply_patch():
    """
    Monkey-patch BLFScanner with the corrected _run_endpoint_checks.
    Call this from blfinder.py BEFORE the 'async with BLFScanner' block.
    """
    from core.scanner import BLFScanner
    from core.validation.endpoint_validator import ValidationConfig

    # ── Patch 1: ValidationConfig defaults ───────────────────────────────────
    # Override the class-level defaults so every ValidationConfig()
    # instantiation uses the less-aggressive thresholds.
    try:
        ValidationConfig.__init__.__defaults__   # verify it is a normal function
        # Patch via a subclass swap — safest approach without touching source
        _orig_init = ValidationConfig.__init__

        def _patched_init(self, **kwargs):
            # Provide sane defaults; caller kwargs still win
            kwargs.setdefault("soft_404_threshold", 0.97)
            kwargs.setdefault("min_body_length",    10)
            kwargs.setdefault("require_json",        False)
            _orig_init(self, **kwargs)

        ValidationConfig.__init__ = _patched_init
    except Exception:
        pass   # If the class structure changed, skip — scanner still works

    # ── Patch 2: _run_endpoint_checks ────────────────────────────────────────
    import asyncio

    async def _run_endpoint_checks_fixed(
        self,
        url:    str,
        method: str,
        body:   dict,
        params: dict,
        meta:   dict = None,
    ):
        from core.scanner import _HAS_VALIDATION, _HAS_CLASSIFIER  # noqa: F401

        findings = []

        # Phase 5: Dashboard update + pause support
        self._update_dashboard(endpoint=url)
        if self._dashboard_state:
            self._dashboard_state.scanned_endpoints += 1
            while self._dashboard_state.paused:
                await asyncio.sleep(0.5)

        # Phase 3: Validate endpoint
        is_graphql = any(
            seg in url.lower() for seg in ["/graphql", "/gql", "/query"]
        )
        if _HAS_VALIDATION and self._endpoint_validator:
            # Use strict only when the user explicitly asked for it
            strict = getattr(self.config, "strict_validation", False)
            val_report = await self._endpoint_validator.validate(
                url, method, body,
                is_graphql=is_graphql,
                strict=strict,
            )
            if val_report.should_skip:
                self._skipped_endpoints.append(url)
                if self.config.verbose:
                    print(f"  [SKIP] {url[:70]} — {val_report.summary}")
                return findings

        # Baseline request
        status, headers, base_body, elapsed = await self._request(
            method, url,
            json=body if body else None,
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

        # Phase 4: Harvest IDs
        try:
            if self._idor_enumerator:
                self._idor_enumerator.harvest_ids(base_body)
        except Exception:
            pass

        # Phase 3: Classify response
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

        # Build skip set from profile + business classifier
        skip_set: set = set(self._profile_skip_modules)
        try:
            if _HAS_CLASSIFIER and self._classifier:
                ep_profile = self._classifier.classify(url, body)
                skip_set.update(ep_profile.skip_modules)
        except Exception:
            pass

        # ── BUG-1 FIX: use callables so coroutines are created only for
        #               checks we actually intend to run. ──────────────────
        all_checks = [
            ("price_manipulation",
             lambda: self._check_price_manipulation(url, method, body, params, status, base_body)),
            ("negative_quantity",
             lambda: self._check_quantity_negative(url, method, body, params, status, base_body)),
            ("workflow_bypass",
             lambda: self._check_workflow_bypass(url, method, body, params, status, base_body)),
            ("mass_assignment",
             lambda: self._check_mass_assignment(url, method, body, params, status, base_body)),
            ("idor_bola",
             lambda: self._check_idor_bola(url, method, body, params, status, base_body, headers)),
            ("bopla",
             lambda: self._check_bopla(url, method, body, params, status, base_body)),
            ("privilege_escalation",
             lambda: self._check_privilege_escalation(url, method, body, params, status, base_body)),
            ("bfla",
             lambda: self._check_function_level_access(url, method, body, params, status, base_body)),
            ("coupon_stacking",
             lambda: self._check_coupon_stacking(url, method, body, params, status, base_body)),
            ("time_bypass",
             lambda: self._check_time_logic_bypass(url, method, body, params, status, base_body)),
            ("integer_overflow",
             lambda: self._check_integer_overflow(url, method, body, params, status, base_body)),
            ("hidden_parameter",
             lambda: self._check_hidden_parameter_disclosure(url, method, body, params, status, base_body)),
            ("state_machine_abuse",
             lambda: self._check_state_machine_abuse(url, method, body, params, status, base_body)),
            ("race_condition",
             lambda: self._check_race_condition(url, method, body, params, status, base_body)),
            ("jwt_manipulation",
             lambda: self._check_jwt_manipulation(url, method, body, params, status, base_body, headers)),
            ("account_enumeration",
             lambda: self._check_account_enumeration(url, method, body, params, status, base_body)),
            ("limit_offset",
             lambda: self._check_limit_offset_manipulation(url, method, body, params, status, base_body)),
            ("soft_delete_bypass",
             lambda: self._check_soft_delete_bypass(url, method, body, params, status, base_body)),
            ("http_method_override",
             lambda: self._check_http_method_override(url, method, body, params, status, base_body)),
            ("parameter_pollution",
             lambda: self._check_parameter_pollution(url, method, body, params, status, base_body)),
            ("blind_idor",
             lambda: self._check_blind_idor(url, method, body, params, status, base_body)),
        ]

        # Only call (and await) coroutines for checks not in skip_set
        coros = [fn() for name, fn in all_checks if name not in skip_set]
        results = await asyncio.gather(*coros, return_exceptions=True)

        raw_findings = []
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

    # Apply the fixed method
    BLFScanner._run_endpoint_checks = _run_endpoint_checks_fixed
    return True
