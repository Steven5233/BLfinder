"""
BLFinder v3.1 — core/verifier.py

Re-tests each finding before reporting it.
Reduces false positives by:
  1. Re-running the exact tampered request N times
  2. Checking consistency of the result
  3. Confirming the anomaly vs baseline on each retry
  4. Flagging findings that only trigger intermittently

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHANGES FROM v2.1  (all bugs that caused 3 findings → 0 verified)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FIX 1 — confirmed=True findings no longer re-verified from scratch
  OLD: Every finding, even one already cross-user confirmed during the
       scan, was re-run through full _still_anomalous() checks. A small
       API response change (timestamp, token, UUID) would fail the body
       similarity check and the finding would be dropped.
  NEW: If finding.confirmed is already True when verify_all() receives
       it, we only check that the endpoint is still alive (returns a
       non-error status). We do NOT re-run the anomaly check because the
       cross-user confirmation during the scan is stronger evidence than
       a body-similarity check ever could be.

FIX 2 — similarity threshold lowered from implicit ~0.95 to 0.45
  OLD: The generic branch and the IDOR branch both used a similarity
       threshold derived from self.config.similarity_threshold, which
       defaults to 0.85, meaning (1.0 - 0.85) = 0.15. This required the
       re-test response to differ from the baseline by at least 15% —
       a very small tolerance. Real APIs include timestamps, nonces,
       session tokens, and request IDs that change every response. An
       IDOR re-test returning the same PII with a different timestamp
       could easily fail this check.
  NEW: RETEST_SIMILARITY_THRESHOLD = 0.45. Re-test and original attack
       response must be ≥ 45% similar — handles timestamp/UUID churn
       while still catching soft-404 injections (which score ~0.10).

FIX 3 — status class comparison instead of exact status match
  OLD: IDOR/access-control branch required base_status in (401,403,404)
       and status == 200 exactly. APIs that return 200 normally and 200
       for the IDOR target (the common case for blind IDOR and same-user-
       context IDOR) would fall into the second branch and be subject to
       the strict similarity threshold.
  NEW: A dedicated _status_class() helper groups statuses into 2xx/3xx/
       4xx/5xx. Status checks use class comparison so 200 vs 201 is
       treated as equivalent, and the IDOR branch correctly handles the
       200→200 case that occurs when both baseline and attacked endpoint
       return 200 with different bodies.

FIX 4 — majority voting fixed from floor division to round()
  OLD: successes >= max(1, attempts // 2)
       With attempts=2: max(1, 1) = 1 → need 1/2 — this looks correct
       but attempts // 2 with attempts=3 gives 1 (floor), so 1/3 passes.
       With attempts=1: max(1, 0) = 1 → need 1/1 — correct.
       The real bug: with attempts=2, if successes=0 the finding falls
       into the "successes > 0" branch, gets confidence -= 25, and is
       then compared to min_confidence. With default min_confidence=40
       and a finding at confidence=55, it drops to 30 and gets returned
       as None. So findings at medium confidence with 0/2 successes were
       being silently dropped.
  NEW: Use round() for majority threshold. Add explicit handling so
       0-success findings are always None (not silently dropped via
       confidence floor). Confirmed findings skip the majority vote.

FIX 5 — retry sleep removed for confirmed findings, reduced for others
  OLD: await asyncio.sleep(0.5) between every retry, unconditionally.
       With attempts=2 this adds 1s of dead time per finding. With 3
       findings that's 3 extra seconds minimum. More importantly, the
       0.5s sleep was INSIDE the attempt loop, so it ran even on the
       last attempt — wasting time after the decision is already made.
  NEW: Sleep only between attempts (not after the last one) and skip
       entirely for confirmed findings since they exit early.

FIX 6 — _still_anomalous() body comparison uses attack response, not baseline
  OLD: The generic branch compared the RETRY body against the BASELINE
       body. This is wrong for manipulation findings (price, mass
       assignment, state machine): the anomaly is that the retry body
       looks like the ATTACK response, not that it differs from baseline.
       A finding where the attack and baseline bodies are accidentally
       similar (e.g. the field was already at the tampered value) would
       always fail.
  NEW: _still_anomalous() now receives the original attack_body (stored
       at finding-creation time in finding.response_summary) and compares
       the retry against that when category logic requires it. Falls back
       to baseline comparison when attack_body is unavailable.
"""

from __future__ import annotations

import asyncio
import difflib
import json
from .models import Finding, ScanConfig

try:
    from .analysis.semantic_diff import SemanticDiff
    _HAS_SEMANTIC_DIFF = True
except ImportError:
    _HAS_SEMANTIC_DIFF = False










RETEST_SIMILARITY_THRESHOLD = 0.45




IDOR_DIFFER_THRESHOLD = 0.85



PASS_FRACTION = 0.5



HARD_FAIL_STATUSES = {0, 404, 410, 500, 502, 503, 504}


FAILURE_TOKENS = frozenset([
    "error", "invalid", "rejected", "denied", "forbidden",
    "not found", "unauthorized", "bad request", "exception",
])


SUCCESS_TOKENS = frozenset([
    "success", "created", "updated", "confirmed", "processed",
    "completed", "accepted", "order_id", "transaction_id",
    "payment_id", "token",
])


def _status_class(status: int) -> str:
    """Map an HTTP status to its class string: '2xx', '3xx', '4xx', '5xx', 'err'."""
    if status == 0:
        return "err"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "err"


def _similarity(a: str, b: str, limit: int = 3000) -> float:
    """
    Similarity between two response bodies, used across the verifier's
    majority-vote and re-test gates that decide whether a finding
    survives to the final report.

    Was: raw difflib.SequenceMatcher.ratio() on truncated strings. That
    treats a response purely as an opaque byte sequence — two JSON
    objects with identical data but different key order, or differing
    only in a timestamp/nonce field, can score as "different" even
    though nothing meaningful changed, while a response that changed one
    security-relevant field deep in a large payload can score as
    "similar" purely because most of the surrounding bytes matched. Since
    this function runs *after* every other detection module, in the code
    path with the final say on whether a finding is reported at all,
    that's exactly the place false-positive/false-negative risk from
    naive string comparison matters most.

    Now: delegates to SemanticDiff, which parses both bodies as JSON,
    excludes known-volatile fields (timestamps, nonces, request IDs)
    before scoring, and only falls back to raw string comparison when a
    body genuinely isn't JSON. Falls back to the original difflib
    behavior if semantic_diff isn't importable, so a broken/missing
    module degrades gracefully instead of breaking verification.
    """
    if not a or not b:
        return 0.0
    a, b = a[:limit], b[:limit]
    if _HAS_SEMANTIC_DIFF:
        try:
            return SemanticDiff.compare(a, b).semantic_similarity
        except Exception:
            pass  
    return difflib.SequenceMatcher(None, a, b).ratio()


def _is_success_body(body: str, status: int) -> bool:
    """Return True when a response body looks like a successful operation."""
    if status not in (200, 201, 202, 204):
        return False
    if not body or body.startswith(("TIMEOUT", "ERROR:", "CONNECTION_ERROR:")):
        return False
    bl = body.lower()
    if any(t in bl for t in FAILURE_TOKENS):
        return False
    return True






class FindingVerifier:

    def __init__(self, scanner, config: ScanConfig):
        self.scanner = scanner   
        self.config  = config



    async def verify_all(
        self,
        findings:       list[Finding],
        base_responses: dict,
    ) -> list[Finding]:
        """
        Re-verify every finding concurrently.
        Returns only those whose anomaly holds up on re-test.
        """
        if not findings:
            return []

        tasks = [self._verify_one(f, base_responses) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        verified: list[Finding] = []
        for f, result in zip(findings, results):
            if isinstance(result, Finding):
                verified.append(result)
            elif isinstance(result, Exception):
                if self.config.verbose:
                    print(f"  [!] Verifier exception for '{f.title[:55]}': {result}")



                verified.append(f)

        dropped = len(findings) - len(verified)
        if dropped:
            print(
                f"  [*] Verifier: {len(verified)} passed, {dropped} dropped"
            )

        return verified



    async def _verify_one(
        self,
        finding:        Finding,
        base_responses: dict,
    ) -> Finding | None:
        """
        Re-run the finding's attack request up to confirmation_attempts times.

        Returns:
          Finding  — anomaly reproduced (or already confirmed, just alive-checked)
          None     — finding did not reproduce and should be dropped
        """
        req    = finding.request or {}
        method = req.get("method", "GET")
        url    = req.get("url", "") or getattr(finding, "endpoint", "") or ""
        body   = req.get("body")
        hdrs   = req.get("headers")

        if not url:

            return finding


        baseline    = base_responses.get(url, {})
        base_body   = baseline.get("body",   "")
        base_status = baseline.get("status", 0)





        if getattr(finding, "confirmed", False):
            return await self._liveness_check(finding, method, url, body, hdrs)




        attack_body = self._extract_attack_body(finding)

        attempts  = max(1, self.config.confirmation_attempts)
        successes = 0
        last_body = ""

        for attempt in range(attempts):
            kwargs: dict = {}
            if body:
                kwargs["json"] = body
            if hdrs:
                kwargs["headers"] = hdrs

            try:
                status, _, resp_body, _ = await self.scanner._request(
                    method, url, **kwargs
                )
            except Exception as e:
                if self.config.verbose:
                    print(
                        f"  [!] Verifier _request error "
                        f"({url[:55]}): {e}"
                    )

                if attempt < attempts - 1:
                    await asyncio.sleep(0.3)
                continue

            last_body = resp_body

            if self._still_anomalous(
                status, resp_body,
                base_status, base_body,
                attack_body, finding,
            ):
                successes += 1


            if attempt < attempts - 1:
                await asyncio.sleep(0.3)


        required = max(1, round(attempts * PASS_FRACTION))
        return self._apply_verdict(finding, successes, attempts, required)



    async def _liveness_check(
        self,
        finding: Finding,
        method:  str,
        url:     str,
        body,
        hdrs,
    ) -> Finding | None:
        """
        For already-confirmed findings: just verify the endpoint is still
        reachable and not returning a hard-fail status. Does not re-run the
        full anomaly check — the cross-user confirmation is sufficient proof.
        """
        kwargs: dict = {}
        if body:
            kwargs["json"] = body
        if hdrs:
            kwargs["headers"] = hdrs

        try:
            status, _, _, _ = await self.scanner._request(method, url, **kwargs)
        except Exception:

            return finding

        if status in HARD_FAIL_STATUSES:
            if self.config.verbose:
                print(
                    f"  [-] Confirmed finding gone ({status}), dropping: "
                    f"{finding.title[:55]}"
                )
            return None


        if getattr(finding, "confidence", 0) < 100:
            finding.confidence = min(100, finding.confidence + 5)
        if hasattr(finding, "confidence_reasons"):
            finding.confidence_reasons.append(
                "Liveness re-check passed (already cross-user confirmed)"
            )
        return finding



    def _apply_verdict(
        self,
        finding:   Finding,
        successes: int,
        attempts:  int,
        required:  int,
    ) -> Finding | None:
        """
        Apply the majority-vote verdict and update the finding accordingly.
        """
        if successes >= required:

            finding.confirmed = True
            finding.confidence = min(100, finding.confidence + 15)
            if hasattr(finding, "confidence_reasons"):
                finding.confidence_reasons.append(
                    f"Re-verified: {successes}/{attempts} attempts reproduced anomaly"
                )
            return finding

        if successes > 0:

            finding.confirmed = False
            finding.confidence = max(0, finding.confidence - 20)
            if hasattr(finding, "confidence_reasons"):
                finding.confidence_reasons.append(
                    f"Intermittent: {successes}/{attempts} retries reproduced"
                )
            if hasattr(finding, "false_positive_checks"):
                finding.false_positive_checks.append(
                    "Intermittent reproduction — may be timing-dependent or rate-limited"
                )
            if self.config.verbose:
                print(
                    f"  [~] Intermittent ({successes}/{attempts}): "
                    f"{finding.title[:55]}"
                )

            if finding.confidence >= self.config.min_confidence:
                return finding
            return None


        if self.config.verbose:
            print(
                f"  [-] Did not reproduce (0/{attempts}): "
                f"{finding.title[:55]}"
            )
        return None



    def _still_anomalous(
        self,
        status:       int,
        body:         str,
        base_status:  int,
        base_body:    str,
        attack_body:  str,
        finding:      Finding,
    ) -> bool:
        """
        Check whether a re-test response still shows the original anomaly.
        Uses category-specific logic; falls back to a generic check.

        Parameters
        ──────────
        status / body       : re-test HTTP status and body
        base_status / base_body : original baseline (normal request)
        attack_body         : original attack response body (for similarity)
        finding             : the Finding being re-verified
        """

        if status in HARD_FAIL_STATUSES:
            return False

        cat = (finding.category or "").lower()


        if any(k in cat for k in [
            "idor", "bola", "privilege", "bfla",
            "authentication", "function level", "missing auth",
        ]):
            return self._check_access_control(
                status, body, base_status, base_body, attack_body
            )


        if any(k in cat for k in [
            "price", "quantity", "mass", "state", "coupon",
            "workflow", "time", "integer", "discount",
        ]):
            return self._check_manipulation(status, body, attack_body)


        if "race" in cat:
            return _status_class(status) == "2xx"


        if any(k in cat for k in [
            "disclosure", "bopla", "hidden", "enumeration",
            "property", "soft delete", "limit",
        ]):
            return self._check_disclosure(status, body, base_body)


        if "jwt" in cat:
            return _status_class(status) == "2xx" and _is_success_body(body, status)


        if "graphql" in cat:
            return (
                status == 200
                and '"data"' in body
                and "errors" not in body.lower()
                and not body.strip().startswith("<")
            )


        return self._check_generic(status, body, base_body, attack_body)



    def _check_access_control(
        self,
        status:      int,
        body:        str,
        base_status: int,
        base_body:   str,
        attack_body: str,
    ) -> bool:
        """
        Access control anomaly = getting a successful response where the
        baseline was blocked, OR getting meaningfully different data.
        """
        sc      = _status_class(status)
        base_sc = _status_class(base_status)


        if base_sc in ("4xx",) and base_status in (401, 403, 404) and sc == "2xx":
            return True



        if sc == "2xx" and base_sc == "2xx":
            sim_to_baseline = _similarity(base_body, body)

            if attack_body:
                sim_to_attack = _similarity(attack_body, body)
                return (
                    sim_to_baseline < IDOR_DIFFER_THRESHOLD
                    and sim_to_attack >= RETEST_SIMILARITY_THRESHOLD
                )
            return sim_to_baseline < IDOR_DIFFER_THRESHOLD


        if sc == "2xx":
            return _is_success_body(body, status)

        return False

    def _check_manipulation(
        self,
        status:      int,
        body:        str,
        attack_body: str,
    ) -> bool:
        """
        Manipulation anomaly = server accepted the tampered request.
        Compare retry body to original attack body — they should look similar
        (both successful responses to the same tampered payload).
        """
        if _status_class(status) not in ("2xx",):
            return False
        if not _is_success_body(body, status):
            return False

        if attack_body:
            return _similarity(attack_body, body) >= RETEST_SIMILARITY_THRESHOLD

        bl = body.lower()
        return any(t in bl for t in SUCCESS_TOKENS)

    def _check_disclosure(
        self,
        status:    int,
        body:      str,
        base_body: str,
    ) -> bool:
        """
        Disclosure anomaly = re-test still returns more data than the baseline.
        """
        if _status_class(status) != "2xx":
            return False
        if not body:
            return False

        if len(body) > len(base_body) * 1.15:
            return True

        try:
            base_data = json.loads(base_body) if base_body else {}
            new_data  = json.loads(body)
            if isinstance(base_data, dict) and isinstance(new_data, dict):
                new_keys = set(new_data.keys()) - set(base_data.keys())
                return len(new_keys) > 0
        except (json.JSONDecodeError, ValueError):
            pass
        return _similarity(base_body, body) < 0.85

    def _check_generic(
        self,
        status:      int,
        body:        str,
        base_body:   str,
        attack_body: str,
    ) -> bool:
        """
        Generic fallback: re-test is anomalous if it's a 2xx response and
        the body resembles the original attack response more than the baseline.
        """
        if _status_class(status) not in ("2xx",):
            return False
        if not body:
            return False

        if attack_body:
            sim_to_attack   = _similarity(attack_body, body)
            sim_to_baseline = _similarity(base_body,   body)

            return (
                sim_to_attack >= RETEST_SIMILARITY_THRESHOLD
                and sim_to_attack > sim_to_baseline + 0.10
            )


        if base_body:
            return _similarity(base_body, body) < 0.95

        return _is_success_body(body, status)



    @staticmethod
    def _extract_attack_body(finding: Finding) -> str:
        """
        Attempt to recover the original attack response body.

        response_summary is stored as "HTTP 200 — {body[:300]}" by the
        scanner modules. We strip the prefix to get the body fragment.
        Falls back to evidence string if response_summary is absent.
        """
        summary = getattr(finding, "response_summary", "") or ""
        if summary:

            if " — " in summary:
                return summary.split(" — ", 1)[1]
            if "HTTP " in summary and "\n" in summary:
                return summary.split("\n", 1)[1]
            return summary


        return getattr(finding, "evidence", "") or ""
