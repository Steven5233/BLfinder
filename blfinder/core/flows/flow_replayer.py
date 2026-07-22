"""
BLFinder v3.0 — core/flows/flow_replayer.py
Multi-Step Business Flow Executor

Executes multi-step request sequences where each step can extract values
from the response and inject them into subsequent steps via templating.

This is the key capability that v2.1 was missing: testing business logic
that only manifests across multiple requests — e.g. add-to-cart →
apply-coupon → checkout → payment. Testing checkout in isolation misses
flaws that only appear in the complete sequence.

Attack capabilities per flow:
  - Price manipulation at any step
  - Coupon stacking / replay across the full flow
  - Workflow step skipping (jump to step N from step 1)
  - Race condition on the final state-changing step
  - State machine abuse (force order status mid-flow)
  - Parameter injection into extracted values
  - Replay attacks (repeat a completed flow without re-auth)
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class FlowStep:
    """
    A single step in a multi-step business flow.

    Supports template variables: {{variable_name}} in url, body, params.
    Variables are populated from previous step extractions.
    """
    id: str                                    # Unique step identifier
    method: str                                # HTTP method
    url: str                                   # URL — may contain {{variables}}
    body: dict = field(default_factory=dict)   # Request body — may contain {{variables}}
    params: dict = field(default_factory=dict) # Query params — may contain {{variables}}
    headers: dict = field(default_factory=dict)

    # Value extraction: key → JSONPath-like expression
    # e.g. {"cart_id": "$.cart.id", "total": "$.order.total"}
    extract: dict = field(default_factory=dict)

    # If True, run all attack modules against this step
    attack_here: bool = False

    # If True, skip this step (used for workflow bypass attacks)
    skip: bool = False

    # Expected status codes — deviation is flagged
    expected_status: list[int] = field(default_factory=lambda: [200, 201])

    # Optional delay before this step (seconds)
    delay: float = 0.0

    # If True, this step must succeed for the flow to continue
    required: bool = True


@dataclass
class FlowStepResult:
    """Result of executing a single flow step."""
    step_id: str
    method: str
    url: str
    status: int
    body: str
    elapsed: float
    extracted: dict = field(default_factory=dict)   # Values extracted from response
    success: bool = False
    error: str = ""
    request_body: dict = field(default_factory=dict)
    request_params: dict = field(default_factory=dict)


@dataclass
class FlowResult:
    """Result of executing a complete multi-step flow."""
    flow_name: str
    success: bool = False
    steps: list[FlowStepResult] = field(default_factory=list)
    context: dict = field(default_factory=dict)   # All extracted values
    total_elapsed: float = 0.0
    error: str = ""
    attack_findings: list = field(default_factory=list)  # list[Finding]


@dataclass
class FlowAttackResult:
    """Result of a single attack attempt within a flow."""
    attack_type: str
    step_id: str
    tampered_field: str
    original_value: Any
    tampered_value: Any
    success: bool = False
    status: int = 0
    response_body: str = ""
    evidence: str = ""
    confirmed: bool = False


# ── Flow Replayer ─────────────────────────────────────────────────────────────

class FlowReplayer:
    """
    Executes multi-step business flows and attacks them at each step.

    Usage:
        replayer = FlowReplayer(scanner_instance)

        # Load a flow template
        flow = FlowTemplates.ecommerce_checkout()

        # Execute normally first (baseline)
        baseline = await replayer.execute(flow, base_url="https://api.target.com")

        # Then attack
        findings = await replayer.attack(flow, base_url="https://api.target.com")
    """

    def __init__(self, scanner):
        self._scanner  = scanner
        self._config   = scanner.config
        self._request  = scanner._request

    # ── Public API ────────────────────────────────────────────────────────────

    async def execute(
        self,
        steps: list[FlowStep],
        base_url: str = "",
        context: dict | None = None,
        stop_on_failure: bool = True,
    ) -> FlowResult:
        """
        Execute a flow from start to finish, extracting values at each step.

        Args:
            steps:            Ordered list of FlowStep objects
            base_url:         Base URL prepended to relative step URLs
            context:          Pre-populated template variables
            stop_on_failure:  If True, stop the flow when a required step fails

        Returns:
            FlowResult with all step results and extracted context
        """
        flow_name = steps[0].id.split("_")[0] if steps else "unnamed"
        result = FlowResult(flow_name=flow_name)
        ctx = dict(context or {})
        start = time.time()

        for step in steps:
            if step.skip:
                continue
            if step.delay > 0:
                await asyncio.sleep(step.delay)

            step_result = await self._execute_step(step, base_url, ctx)
            result.steps.append(step_result)

            # Merge extracted values into context
            ctx.update(step_result.extracted)

            # Check if step succeeded
            if not step_result.success and step.required:
                result.error = (
                    f"Required step '{step.id}' failed "
                    f"(HTTP {step_result.status}): {step_result.error}"
                )
                if stop_on_failure:
                    break

        result.context = ctx
        result.total_elapsed = time.time() - start
        result.success = (
            not result.error and
            all(
                s.success for s in result.steps
                if any(step.required and step.id == s.step_id for step in steps)
            )
        )
        return result

    async def attack(
        self,
        steps: list[FlowStep],
        base_url: str = "",
        context: dict | None = None,
    ) -> list:
        """
        Execute the flow and attack every step marked with attack_here=True.
        Returns a list of Finding objects.
        """
        # First, run a clean baseline to populate context
        baseline = await self.execute(steps, base_url, context, stop_on_failure=False)
        ctx = dict(baseline.context)

        all_findings = []

        for step in steps:
            if not step.attack_here:
                continue

            # Resolve the step's URL and body with current context
            resolved_url  = self._resolve_template(step.url,  ctx, base_url)
            resolved_body = self._resolve_body(step.body, ctx)

            step_findings = await self._attack_step(
                step=step,
                url=resolved_url,
                body=resolved_body,
                params=self._resolve_body(step.params, ctx),
                context=ctx,
                baseline_result=self._find_baseline_step(baseline, step.id),
            )
            all_findings.extend(step_findings)

        return all_findings

    async def attack_workflow_bypass(
        self,
        steps: list[FlowStep],
        base_url: str = "",
        context: dict | None = None,
    ) -> list:
        """
        Attempt to reach each step directly without completing prior steps.
        Tests whether the server enforces sequential step completion.
        """
        findings = []
        ctx = dict(context or {})

        # Execute only the first step to get a valid session
        if steps:
            first_result = await self._execute_step(steps[0], base_url, ctx)
            ctx.update(first_result.extracted)

        # Try to jump directly to each subsequent step
        for i, step in enumerate(steps[1:], start=1):
            if step.skip:
                continue

            resolved_url  = self._resolve_template(step.url,  ctx, base_url)
            resolved_body = self._resolve_body(step.body, ctx)

            status, _, resp_body, elapsed = await self._request(
                step.method, resolved_url,
                json=resolved_body if resolved_body else None,
                params=self._resolve_body(step.params, ctx) or None,
            )

            # Success on a step we shouldn't have access to = workflow bypass
            if status in step.expected_status:
                # FP guard: try with a completely invalid body to verify server isn't just 200ing everything
                canary_status, _, _, _ = await self._request(
                    step.method, resolved_url,
                    json={"__canary_invalid__": True},
                )
                if canary_status in step.expected_status:
                    continue  # Server returns 200 for anything — skip

                findings.append(self._make_finding(
                    title=f"Workflow Bypass — jumped directly to step '{step.id}' (step {i+1})",
                    severity="HIGH",
                    category="Business Logic — Workflow Bypass",
                    description=(
                        f"Accessed step '{step.id}' directly without completing "
                        f"{i} prior step(s). Server returned HTTP {status}."
                    ),
                    request={"method": step.method, "url": resolved_url, "body": resolved_body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=(
                        f"Jumped to step {i+1} ('{step.id}') without steps 1–{i}. "
                        f"HTTP {status}. Canary → {canary_status}."
                    ),
                    recommendation=(
                        "Enforce sequential step validation using signed server-side session state. "
                        "Each step must verify prior steps completed successfully."
                    ),
                    cwe="CWE-284",
                    owasp="API5:2023 Broken Function Level Authorization",
                ))

        return findings

    async def attack_race_condition(
        self,
        target_step: FlowStep,
        base_url: str = "",
        context: dict | None = None,
        concurrency: int = 15,
    ) -> list:
        """
        Fire N near-simultaneous copies of a flow step. Reuses the scanner's
        shared burst primitives (see scanner.py) instead of a bare
        asyncio.gather, which fixes two problems the original version had:

          1. The main aiohttp session caps concurrent connections per host
             at 5 (limit_per_host=5) — a "15 concurrent" burst was actually
             serialized into batches of 5, so tight race windows were
             routinely missed. The burst session has no such cap.
          2. Success was judged purely on HTTP status. Now every successful
             response is run through the distinct-identifier / numeric-delta
             oracle so a repeated-but-idempotent 200 isn't mistaken for a
             real double-processing bug.
        """
        ctx = dict(context or {})
        resolved_url  = self._resolve_template(target_step.url, ctx, base_url)
        resolved_body = self._resolve_body(target_step.body, ctx)

        waves = [5, 15, 30] if concurrency >= 15 else [concurrency]
        analysis = None
        winning_wave = 0
        for wave in waves:
            responses = await self._scanner._execute_race_burst(
                target_step.method, resolved_url,
                body=resolved_body if resolved_body else None,
                concurrency=wave,
            )
            analysis = self._scanner._analyze_race_burst(responses)
            if analysis["success_count"] > 1:
                winning_wave = wave
                break

        if not analysis or analysis["success_count"] <= 1:
            return []

        success_count = analysis["success_count"]
        total         = analysis["total"]
        distinct_ids  = analysis["distinct_ids"]

        if len(distinct_ids) > 1:
            oracle_note = (
                f" {len(distinct_ids)} distinct resource identifiers were created "
                "across the successful responses, confirming separate mutations "
                "(not one transaction echoed back)."
            )
            confirmed = True
        elif len(distinct_ids) == 1:
            oracle_note = (
                " All successes shared one identifier — may be correctly "
                "deduplicated via an idempotency key; verify manually."
            )
            confirmed = False
        else:
            oracle_note = " No identifier field found to independently confirm the double-processing; verify manually."
            confirmed = False

        return [self._make_finding(
            title=(
                f"Race Condition — '{target_step.id}' accepted {success_count}/{total} "
                f"concurrent requests (window at concurrency={winning_wave})"
            ),
            severity="CRITICAL",
            category="Business Logic — Race Condition",
            description=(
                f"{success_count} of {total} simultaneous, connection-warmed requests "
                f"to step '{target_step.id}' returned success. Single-use operations may be "
                f"exploitable for double-spending or duplicate redemption.{oracle_note}"
            ),
            request={
                "method": target_step.method, "url": resolved_url,
                "body": resolved_body, "note": f"{total} concurrent requests, connection-warmed",
            },
            response_summary=f"{success_count}/{total} successes",
            evidence=f"Concurrent success rate: {success_count}/{total} at concurrency={winning_wave}.{oracle_note}",
            recommendation=(
                "Use DB-level locks (SELECT FOR UPDATE), Redis SETNX, "
                "or idempotency keys to prevent race conditions."
            ),
            cwe="CWE-362",
            owasp="API4:2023 Unrestricted Resource Consumption",
            confirmed=confirmed,
        )]

    async def attack_state_transitions(
        self,
        steps: list[FlowStep],
        base_url: str = "",
        context: dict | None = None,
    ) -> list:
        """
        Full pairwise state-transition fuzzer — the actual "state machine
        abuse" class of bug, not just linear skip-ahead.

        `attack_workflow_bypass` only ever asks "can step N be reached
        without steps 1..N-1?". Real state-machine bugs are graph problems:
        can a COMPLETED order be cancelled again, can a REFUNDED order be
        shipped, can a step be replayed after the flow already moved past
        it? This method executes the flow once (snapshotting context after
        every step), then from EVERY position tries EVERY other step —
        including going backward and repeating a step that should only be
        reachable once — and flags any transition that succeeds but isn't
        the one legitimate next step.
        """
        findings = []
        if len(steps) < 2:
            return findings

        ctx: dict = dict(context or {})
        snapshots: dict[int, dict] = {}
        for idx, step in enumerate(steps):
            if step.skip:
                snapshots[idx] = dict(ctx)
                continue
            result = await self._execute_step(step, base_url, ctx)
            ctx.update(result.extracted)
            snapshots[idx] = dict(ctx)

        for i, snap_ctx in snapshots.items():
            for j, target_step in enumerate(steps):
                if j == i + 1 or target_step.skip:
                    continue  # i+1 is the one legitimate next transition

                resolved_url  = self._resolve_template(target_step.url, snap_ctx, base_url)
                resolved_body = self._resolve_body(target_step.body, snap_ctx)

                status, _, resp_body, _ = await self._request(
                    target_step.method, resolved_url,
                    json=resolved_body if resolved_body else None,
                    params=self._resolve_body(target_step.params, snap_ctx) or None,
                )
                if status not in target_step.expected_status:
                    continue

                # FP guard: server that 200s everything isn't meaningful
                canary_status, _, _, _ = await self._request(
                    target_step.method, resolved_url,
                    json={"__canary_invalid__": True},
                )
                if canary_status in target_step.expected_status:
                    continue

                direction = "backward/replay" if j <= i else "forward-skip"
                findings.append(self._make_finding(
                    title=(
                        f"State Machine Abuse — step '{target_step.id}' reachable "
                        f"({direction}) from the state after '{steps[i].id}'"
                    ),
                    severity="HIGH",
                    category="Business Logic — State Machine Abuse",
                    description=(
                        f"After completing step '{steps[i].id}' (position {i}), the "
                        f"server still allowed invoking step '{target_step.id}' "
                        f"(position {j}) — a {direction} transition the intended "
                        f"flow does not permit at that point. Server returned HTTP {status}."
                    ),
                    request={"method": target_step.method, "url": resolved_url, "body": resolved_body},
                    response_summary=f"HTTP {status} — {resp_body[:300]}",
                    evidence=(
                        f"State after '{steps[i].id}' → invoked '{target_step.id}' "
                        f"({direction}). HTTP {status}. Canary control → {canary_status}."
                    ),
                    recommendation=(
                        "Model the workflow as an explicit server-side state machine "
                        "and reject any transition not defined for the current state — "
                        "including backward transitions and repeat invocations of "
                        "single-use/terminal actions."
                    ),
                    cwe="CWE-841",
                    owasp="API5:2023 Broken Function Level Authorization",
                ))

        return findings

    async def attack_cross_instance_confusion(
        self,
        steps: list[FlowStep],
        base_url: str = "",
        context: dict | None = None,
        second_token: str | None = None,
    ) -> list:
        """
        Runs the flow twice — a second independent instance, optionally
        under a different account if `second_token` is provided — and at
        each step swaps the values extracted so far between the two
        instances before continuing. This catches servers that don't
        verify a referenced object (cart, order, coupon, session state)
        actually belongs to the identity/flow that's currently executing —
        i.e. object-level authorization bugs that only manifest *inside*
        a multi-step workflow, not on any single endpoint in isolation.
        """
        findings = []
        if len(steps) < 2:
            return findings

        ctx_a: dict = dict(context or {})
        ctx_b: dict = dict(context or {})

        for idx, step in enumerate(steps):
            if step.skip:
                continue

            result_a = await self._execute_step(step, base_url, ctx_a)
            ctx_a.update(result_a.extracted)
            result_b = await self._execute_step(step, base_url, ctx_b, token_override=second_token)
            ctx_b.update(result_b.extracted)

            if not step.extract or idx + 1 >= len(steps):
                continue

            mixed_ctx = dict(ctx_a)
            swapped_fields = []
            for key in step.extract:
                if key in ctx_b and ctx_b[key] != ctx_a.get(key):
                    mixed_ctx[key] = ctx_b[key]
                    swapped_fields.append(key)
            if not swapped_fields:
                continue

            next_step = steps[idx + 1]
            resolved_url  = self._resolve_template(next_step.url, mixed_ctx, base_url)
            resolved_body = self._resolve_body(next_step.body, mixed_ctx)

            status, _, resp_body, _ = await self._request(
                next_step.method, resolved_url,
                json=resolved_body if resolved_body else None,
                params=self._resolve_body(next_step.params, mixed_ctx) or None,
            )
            if status not in next_step.expected_status:
                continue
            canary_status, _, _, _ = await self._request(
                next_step.method, resolved_url,
                json={"__canary_invalid__": True},
            )
            if canary_status in next_step.expected_status:
                continue

            account_note = " (different account)" if second_token else ""
            findings.append(self._make_finding(
                title=(
                    f"Cross-Object State Confusion — '{next_step.id}' accepted "
                    f"identifiers from a separate flow instance{account_note}"
                ),
                severity="CRITICAL",
                category="Business Logic — Cross-Object State Confusion",
                description=(
                    f"At step '{step.id}', identifier field(s) {swapped_fields} from a "
                    f"SEPARATE, independently-run flow instance{account_note} were "
                    f"substituted into this flow's context. Step '{next_step.id}' still "
                    f"succeeded (HTTP {status}) — the server did not verify these "
                    "identifiers belonged to the flow currently executing."
                ),
                request={"method": next_step.method, "url": resolved_url, "body": resolved_body},
                response_summary=f"HTTP {status} — {resp_body[:300]}",
                evidence=(
                    f"Swapped field(s) {swapped_fields} from instance B into instance A at "
                    f"step '{step.id}', continued to '{next_step.id}' → HTTP {status}. "
                    f"Canary control → {canary_status}."
                ),
                recommendation=(
                    "Bind every extracted identifier (cart id, order id, coupon id, "
                    "session token, etc.) to the account/session that created it, and "
                    "re-validate that binding on every subsequent step of the flow — "
                    "not only at the point of creation."
                ),
                cwe="CWE-639",
                owasp="API1:2023 Broken Object Level Authorization",
            ))

        return findings

    # ── Step Execution ────────────────────────────────────────────────────────

    async def _execute_step(
        self,
        step: FlowStep,
        base_url: str,
        context: dict,
        token_override: str | None = None,
    ) -> FlowStepResult:
        """Execute a single step and extract values from the response."""
        url    = self._resolve_template(step.url, context, base_url)
        body   = self._resolve_body(step.body, context)
        params = self._resolve_body(step.params, context)

        result = FlowStepResult(
            step_id=step.id,
            method=step.method,
            url=url,
            status=0,
            body="",
            elapsed=0.0,
            request_body=body,
            request_params=params,
        )

        try:
            status, headers, resp_body, elapsed = await self._request(
                step.method, url,
                json=body if body else None,
                params=params if params else None,
                headers=step.headers if step.headers else None,
                token_override=token_override,
            )
            result.status  = status
            result.body    = resp_body
            result.elapsed = elapsed
            result.success = status in step.expected_status

            if not result.success:
                result.error = f"Expected {step.expected_status}, got {status}"

            # Extract values for use in subsequent steps
            if step.extract and resp_body:
                result.extracted = self._extract_values(resp_body, step.extract)

        except Exception as e:
            result.error = str(e)

        return result

    # ── Attack Modules ────────────────────────────────────────────────────────

    async def _attack_step(
        self,
        step: FlowStep,
        url: str,
        body: dict,
        params: dict,
        context: dict,
        baseline_result: FlowStepResult | None,
    ) -> list:
        """Run all relevant attack modules against a single step."""
        findings = []

        base_body   = baseline_result.body   if baseline_result else ""
        base_status = baseline_result.status if baseline_result else 0

        checks = [
            self._attack_price_fields(step, url, body, params, base_status, base_body),
            self._attack_quantity_fields(step, url, body, params, base_status, base_body),
            self._attack_coupon_fields(step, url, body, params, base_status, base_body),
            self._attack_state_fields(step, url, body, params, base_status, base_body),
            self._attack_mass_assignment(step, url, body, params, base_status, base_body),
        ]

        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _attack_price_fields(self, step, url, body, params, base_status, base_body) -> list:
        findings = []
        price_keys = [
            "price", "amount", "total", "cost", "fee", "charge",
            "unit_price", "subtotal", "payment_amount", "order_total",
            "grand_total", "final_price", "shipping_cost",
        ]
        tamper_values = [0, 0.01, -1, -100, "0", "0.00"]

        for key in self._find_keys_recursive(body, price_keys):
            original = self._get_nested(body, key)
            for tampered in tamper_values:
                test_body = self._set_nested(copy.deepcopy(body), key, tampered)
                status, _, resp_body, _ = await self._request(
                    step.method, url, json=test_body,
                    params=params if params else None,
                )
                if (
                    status in step.expected_status
                    and self._scanner._response_indicates_success(resp_body, status)
                    and not self._is_waf_block(resp_body)
                ):
                    findings.append(self._make_finding(
                        title=f"[Flow:{step.id}] Price Manipulation — `{key}` = {tampered}",
                        severity="CRITICAL",
                        category="Business Logic — Price Manipulation",
                        description=(
                            f"In flow step '{step.id}', field `{key}` "
                            f"(original: {original}) accepted tampered value {tampered}."
                        ),
                        request={"method": step.method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"Flow step '{step.id}': {key}={original} → {tampered} → HTTP {status}",
                        recommendation="Compute all prices server-side. Never trust client-submitted values.",
                        cwe="CWE-20",
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    ))
                    break
        return findings

    async def _attack_quantity_fields(self, step, url, body, params, base_status, base_body) -> list:
        findings = []
        qty_keys = ["quantity", "qty", "count", "units", "items", "amount", "number"]

        for key in self._find_keys_recursive(body, qty_keys):
            original = self._get_nested(body, key)
            for tampered in [-1, -100, 0, -0.5]:
                test_body = self._set_nested(copy.deepcopy(body), key, tampered)
                status, _, resp_body, _ = await self._request(
                    step.method, url, json=test_body,
                    params=params if params else None,
                )
                # FP guard: verify server rejects invalid string values
                canary_body = self._set_nested(copy.deepcopy(body), key, "INVALID_QTY")
                cs, _, _, _ = await self._request(step.method, url, json=canary_body)
                if cs in step.expected_status:
                    continue  # Server accepts anything — skip

                if (
                    status in step.expected_status
                    and self._scanner._response_indicates_success(resp_body, status)
                ):
                    findings.append(self._make_finding(
                        title=f"[Flow:{step.id}] Negative Quantity — `{key}` = {tampered}",
                        severity="CRITICAL",
                        category="Business Logic — Negative Value",
                        description=(
                            f"In flow step '{step.id}', `{key}` = {tampered} "
                            f"(original: {original}) was accepted."
                        ),
                        request={"method": step.method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status} — {resp_body[:300]}",
                        evidence=f"Flow '{step.id}': qty={tampered} → HTTP {status} (canary rejected → {cs})",
                        recommendation="Enforce qty >= 1 server-side. Reject negative and zero values.",
                        cwe="CWE-20",
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                    ))
                    break
        return findings

    async def _attack_coupon_fields(self, step, url, body, params, base_status, base_body) -> list:
        findings = []
        coupon_keys = ["coupon", "coupon_code", "promo_code", "discount_code", "voucher", "promo"]

        for key in self._find_keys_recursive(body, coupon_keys):
            original = self._get_nested(body, key)
            if not isinstance(original, str):
                continue

            # Test: array type confusion
            for test_val, label in [
                ([original, original], "duplicate array"),
                ([original],           "single-item array"),
            ]:
                test_body = self._set_nested(copy.deepcopy(body), key, test_val)
                status, _, resp_body, _ = await self._request(
                    step.method, url, json=test_body,
                    params=params if params else None,
                )
                if (
                    status in step.expected_status
                    and self._scanner._response_indicates_success(resp_body, status)
                ):
                    # Check if discount actually increased
                    base_discount = self._scanner._extract_discount(base_body)
                    new_discount  = self._scanner._extract_discount(resp_body)
                    confirmed = bool(
                        new_discount and base_discount and
                        new_discount > base_discount * 1.4
                    )
                    findings.append(self._make_finding(
                        title=f"[Flow:{step.id}] Coupon Abuse — {label} for `{key}`",
                        severity="CRITICAL" if confirmed else "HIGH",
                        category="Business Logic — Coupon Abuse",
                        description=(
                            f"In flow step '{step.id}', coupon `{key}` as {label} was accepted. "
                            f"{'Discount increased: ' + str(base_discount) + '→' + str(new_discount) if confirmed else 'Possible stacking.'}"
                        ),
                        request={"method": step.method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}",
                        evidence=f"Flow '{step.id}': coupon as {label} → discount {base_discount}→{new_discount}",
                        recommendation="Normalize coupon inputs. Enforce one-coupon-per-order server-side.",
                        cwe="CWE-20",
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confirmed=confirmed,
                    ))
        return findings

    async def _attack_state_fields(self, step, url, body, params, base_status, base_body) -> list:
        findings = []
        state_map = {
            "status":              ["completed", "approved", "paid", "shipped"],
            "order_status":        ["completed", "delivered", "paid"],
            "payment_status":      ["paid", "completed", "cleared"],
            "verification_status": ["verified", "approved"],
            "state":               ["completed", "approved", "active"],
        }
        for key, targets in state_map.items():
            if key not in body:
                continue
            for target_state in targets:
                if body.get(key) == target_state:
                    continue
                test_body = {**body, key: target_state}
                status, _, resp_body, _ = await self._request(
                    step.method, url, json=test_body,
                    params=params if params else None,
                )
                if status not in step.expected_status:
                    continue
                data = self._scanner._try_parse_json(resp_body)
                if isinstance(data, dict) and data.get(key) == target_state:
                    findings.append(self._make_finding(
                        title=f"[Flow:{step.id}] State Machine Abuse — `{key}` forced to `{target_state}`",
                        severity="CRITICAL",
                        category="Business Logic — State Machine Abuse",
                        description=(
                            f"In flow step '{step.id}', forcing `{key}` to '{target_state}' "
                            "was accepted and reflected. Workflow conditions bypassed."
                        ),
                        request={"method": step.method, "url": url, "body": test_body},
                        response_summary=f"HTTP {status}, {key}={target_state}",
                        evidence=f"Flow '{step.id}': forced {key}={target_state} → confirmed in response",
                        recommendation="Compute state transitions server-side. Never trust client state values.",
                        cwe="CWE-284",
                        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
                        confirmed=True,
                    ))
                    break
        return findings

    async def _attack_mass_assignment(self, step, url, body, params, base_status, base_body) -> list:
        findings = []
        privileged_keys = [
            "is_admin", "admin", "role", "is_premium", "premium",
            "verified", "approved", "kyc_verified", "tax_exempt",
            "price_override", "fee_waiver", "discount_override",
        ]
        for key in privileged_keys:
            test_body = {**body, key: True}
            status, _, resp_body, _ = await self._request(
                step.method, url, json=test_body,
                params=params if params else None,
            )
            if status not in step.expected_status:
                continue
            resp_data = self._scanner._try_parse_json(resp_body)
            if not isinstance(resp_data, dict):
                continue
            reflected = resp_data.get(key)
            if reflected in (True, "true", 1, "admin", "premium", "verified"):
                base_data = self._scanner._try_parse_json(base_body)
                if isinstance(base_data, dict) and base_data.get(key) == reflected:
                    continue  # Already set — no injection
                findings.append(self._make_finding(
                    title=f"[Flow:{step.id}] Mass Assignment — `{key}` reflected as `{reflected}`",
                    severity="CRITICAL",
                    category="Business Logic — Mass Assignment",
                    description=(
                        f"In flow step '{step.id}', injecting `{key}: true` "
                        f"was accepted and reflected as `{reflected}`."
                    ),
                    request={"method": step.method, "url": url, "body": test_body},
                    response_summary=f"HTTP {status}, {key}={reflected}",
                    evidence=f"Flow '{step.id}': injected {key}=True → response {key}={reflected}",
                    recommendation="Use an explicit field allowlist. Never pass raw bodies to ORM methods.",
                    cwe="CWE-915",
                    owasp="API3:2023 Broken Object Property Level Authorization",
                    confirmed=True,
                ))
        return findings

    # ── Template Resolution ───────────────────────────────────────────────────

    def _resolve_template(self, template: str, context: dict, base_url: str = "") -> str:
        """Replace {{variable}} placeholders with values from context."""
        def replacer(match):
            key = match.group(1).strip()
            return str(context.get(key, match.group(0)))

        resolved = re.sub(r'\{\{(\w+)\}\}', replacer, template)

        if resolved.startswith("/") and base_url:
            return urljoin(base_url.rstrip("/") + "/", resolved.lstrip("/"))
        if not resolved.startswith("http") and base_url:
            return urljoin(base_url, resolved)
        return resolved

    def _resolve_body(self, body: Any, context: dict) -> Any:
        """Recursively resolve template variables in a request body."""
        if isinstance(body, str):
            return self._resolve_template(body, context)
        if isinstance(body, dict):
            return {k: self._resolve_body(v, context) for k, v in body.items()}
        if isinstance(body, list):
            return [self._resolve_body(item, context) for item in body]
        return body

    # ── Value Extraction ──────────────────────────────────────────────────────

    def _extract_values(self, body: str, extract_map: dict) -> dict:
        """
        Extract values from a JSON response using simple dot-notation paths.
        e.g. {"cart_id": "$.cart.id"} extracts response["cart"]["id"]
        """
        extracted = {}
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return extracted

        for var_name, path in extract_map.items():
            # Strip leading $. if present
            clean_path = path.lstrip("$").lstrip(".")
            value = self._get_by_path(data, clean_path)
            if value is not None:
                extracted[var_name] = value

        return extracted

    def _get_by_path(self, data: Any, path: str) -> Any:
        """Navigate a dot-notation path through a nested dict/list."""
        if not path:
            return data
        parts = path.split(".", 1)
        key   = parts[0]
        rest  = parts[1] if len(parts) > 1 else ""

        if isinstance(data, dict) and key in data:
            return self._get_by_path(data[key], rest)
        if isinstance(data, list):
            try:
                idx = int(key)
                return self._get_by_path(data[idx], rest)
            except (ValueError, IndexError):
                pass
        return None

    # ── Nested body helpers ───────────────────────────────────────────────────

    def _find_keys_recursive(self, obj: Any, target_keys: list[str], prefix: str = "") -> list[str]:
        """Find all keys in a nested dict that match any of the target_keys."""
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if any(tk in k.lower() for tk in target_keys):
                    found.append(path)
                found.extend(self._find_keys_recursive(v, target_keys, path))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                found.extend(self._find_keys_recursive(item, target_keys, f"{prefix}[{i}]"))
        return found

    def _get_nested(self, obj: Any, path: str) -> Any:
        """Get a value from a nested dict using a dot-notation path."""
        return self._get_by_path(obj, path)

    def _set_nested(self, obj: Any, path: str, value: Any) -> Any:
        """Set a value in a nested dict using a dot-notation path."""
        parts = path.split(".", 1)
        key   = parts[0]

        # Handle list index notation: [0]
        list_match = re.match(r'^(\w+)\[(\d+)\]$', key)
        if list_match:
            field_name = list_match.group(1)
            idx        = int(list_match.group(2))
            if isinstance(obj, dict) and field_name in obj and isinstance(obj[field_name], list):
                if len(parts) > 1:
                    obj[field_name][idx] = self._set_nested(obj[field_name][idx], parts[1], value)
                else:
                    obj[field_name][idx] = value
            return obj

        if isinstance(obj, dict):
            if len(parts) == 1:
                obj[key] = value
            elif key in obj:
                obj[key] = self._set_nested(obj[key], parts[1], value)
        return obj

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_baseline_step(
        self, baseline: FlowResult, step_id: str
    ) -> FlowStepResult | None:
        return next((s for s in baseline.steps if s.step_id == step_id), None)

    def _is_waf_block(self, body: str) -> bool:
        waf = [
            "access denied", "request blocked", "security violation",
            "cloudflare", "imperva", "akamai security", "sucuri",
        ]
        body_lower = body.lower()
        return any(w in body_lower for w in waf)

    def _make_finding(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        request: dict,
        response_summary: str,
        evidence: str,
        recommendation: str,
        cwe: str = "",
        owasp: str = "",
        confirmed: bool = False,
    ):
        """Create a Finding using the models from the existing models.py."""
        from ..models import Finding, Severity
        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
            "INFO":     Severity.INFO,
        }
        return Finding(
            title=title,
            severity=sev_map.get(severity.upper(), Severity.MEDIUM),
            category=category,
            description=description,
            request=request,
            response_summary=response_summary,
            evidence=evidence,
            recommendation=recommendation,
            cwe=cwe,
            owasp=owasp,
            confirmed=confirmed,
            confidence=75 if confirmed else 55,
        )
