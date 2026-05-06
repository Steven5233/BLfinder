"""
BLFinder v2.1 — Finding Verifier

Re-tests each finding before reporting it.
Reduces false positives by:
  1. Re-running the exact tampered request N times
  2. Checking consistency of the result
  3. Confirming the anomaly vs baseline on each retry
  4. Flagging findings that only trigger intermittently
"""

import asyncio
import difflib
import json
from .models import Finding, ScanConfig


class FindingVerifier:

    def __init__(self, scanner, config: ScanConfig):
        self.scanner = scanner  # Reference to BLFScanner for _request()
        self.config = config

    async def verify_all(self, findings: list[Finding], base_responses: dict) -> list[Finding]:
        """
        Re-verify each finding. Returns only those that hold up.
        """
        verified = []
        tasks = [self._verify_one(f, base_responses) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for f, result in zip(findings, results):
            if isinstance(result, Finding):
                verified.append(result)
            elif isinstance(result, Exception) and self.config.verbose:
                print(f"  [!] Verifier error for '{f.title}': {result}")
        return verified

    async def _verify_one(self, finding: Finding, base_responses: dict) -> Finding | None:
        """
        Re-run the finding's request up to confirmation_attempts times.
        Returns None if the finding does not reproduce.
        """
        req = finding.request
        method = req.get("method", "GET")
        url = req.get("url", "")
        body = req.get("body")
        headers = req.get("headers")

        if not url:
            return finding  # Can't verify without URL

        baseline = base_responses.get(url, {})
        base_body = baseline.get("body", "")
        base_status = baseline.get("status", 0)

        attempts = self.config.confirmation_attempts
        successes = 0
        last_body = ""

        for attempt in range(attempts):
            kwargs = {}
            if body:
                kwargs["json"] = body
            if headers:
                kwargs["headers"] = headers

            status, _, resp_body, _ = await self.scanner._request(method, url, **kwargs)
            last_body = resp_body

            # Check if the anomaly still holds
            if self._still_anomalous(status, resp_body, base_status, base_body, finding):
                successes += 1

            # Small gap between retries
            await asyncio.sleep(0.5)

        # Require majority of attempts to succeed
        if successes >= max(1, attempts // 2):
            finding.confirmed = True
            finding.confidence = min(100, finding.confidence + 15)
            finding.confidence_reasons.append(
                f"Re-verified: {successes}/{attempts} confirmation attempts succeeded"
            )
            return finding
        else:
            if self.config.verbose:
                print(f"  [-] Finding did not reproduce ({successes}/{attempts}): {finding.title[:60]}")
            # Still report but with reduced confidence and unconfirmed
            if successes > 0:
                finding.confirmed = False
                finding.confidence = max(0, finding.confidence - 25)
                finding.confidence_reasons.append(
                    f"Intermittent: only {successes}/{attempts} retries reproduced"
                )
                finding.false_positive_checks.append(
                    "Intermittent reproduction — may be timing-dependent or already patched"
                )
                return finding if finding.confidence >= self.config.min_confidence else None
            return None

    def _still_anomalous(self, status: int, body: str, base_status: int,
                          base_body: str, finding: Finding) -> bool:
        """
        Check whether the retry still shows the same anomaly.
        Uses category-specific logic.
        """
        cat = finding.category.lower()

        # For access control findings: anomaly = getting 200 when base was 401/403
        if any(k in cat for k in ["idor", "bola", "privilege", "bfla", "authentication"]):
            if base_status in (401, 403, 404) and status == 200:
                return True
            if base_status == 200 and status == 200:
                sim = difflib.SequenceMatcher(None, base_body[:2000], body[:2000]).ratio()
                return sim < (1.0 - self.config.similarity_threshold)
            return False

        # For injection/manipulation findings: anomaly = 200 + success body
        if any(k in cat for k in ["price", "quantity", "mass", "state", "coupon"]):
            if status not in (200, 201):
                return False
            failure_tokens = ["error", "invalid", "rejected", "denied", "forbidden"]
            return not any(t in body.lower() for t in failure_tokens)

        # For race conditions: always re-test (handled separately)
        if "race" in cat:
            return status in (200, 201)

        # Generic: status is 200 and response differs from baseline
        if status in (200, 201) and base_body:
            sim = difflib.SequenceMatcher(None, base_body[:2000], body[:2000]).ratio()
            return sim < 0.95
        return status in (200, 201)
