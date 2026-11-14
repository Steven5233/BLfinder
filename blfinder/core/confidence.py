"""
BLFinder v2.1 — Confidence Scoring & False Positive Reduction

Every finding goes through this before being reported.
Score 0–100. Below config.min_confidence → dropped.
"""

import json
import re
import difflib
from .models import Finding, Severity

try:
    from .analysis.semantic_diff import SemanticDiff
    _HAS_SEMANTIC_DIFF = True
except ImportError:
    _HAS_SEMANTIC_DIFF = False


class ConfidenceEngine:
    """
    Calculates a confidence score for each finding and attaches
    false-positive check results.
    """

    def score(self, finding: Finding, baseline_body: str, tampered_body: str,
              base_status: int, tampered_status: int) -> Finding:
        score = 0
        reasons = []
        fp_checks = []


        if tampered_status in (200, 201) and base_status in (200, 201):
            score += 10
            reasons.append("Both baseline and tampered returned 2xx")
        elif tampered_status in (200, 201) and base_status in (401, 403, 404):
            score += 35
            reasons.append(f"Baseline {base_status} → tampered {tampered_status}: access gained")
        elif tampered_status == base_status:
            score += 5
            reasons.append("Same status code (weaker signal)")


        success_tokens = [
            "success", "created", "updated", "confirmed", "accepted",
            "processed", "completed", "transaction_id", "order_id",
            "payment_id", "token", "\"id\":", "\"status\": \"ok\"",
        ]
        failure_tokens = [
            "error", "invalid", "unauthorized", "forbidden", "rejected",
            "denied", "not found", "bad request", "validation failed",
            "exception", "stack trace",
        ]
        tampered_lower = tampered_body.lower()
        base_lower = baseline_body.lower()

        success_hits = sum(1 for t in success_tokens if t in tampered_lower)
        failure_hits = sum(1 for t in failure_tokens if t in tampered_lower)

        if success_hits >= 3 and failure_hits == 0:
            score += 25
            reasons.append(f"Strong success signals ({success_hits} tokens, 0 failure tokens)")
        elif success_hits >= 1 and failure_hits == 0:
            score += 12
            reasons.append(f"Mild success signals ({success_hits} tokens)")
        elif failure_hits > success_hits:
            score -= 20
            fp_checks.append(f"Failure tokens ({failure_hits}) exceed success tokens ({success_hits}) — likely error response")

        if tampered_status in (400, 401, 403, 404, 422):
            score -= 15
            fp_checks.append(f"Tampered request returned {tampered_status} — likely rejected")







        if _HAS_SEMANTIC_DIFF:
            try:
                diff = SemanticDiff.compare(baseline_body[:4000], tampered_body[:4000])
            except Exception:
                diff = None
        else:
            diff = None

        if diff is not None:
            similarity = diff.semantic_similarity

            if similarity > 0.98 and not diff.structural_change:
                score -= 15
                fp_checks.append(
                    f"Responses semantically identical (similarity={similarity:.2f}) — "
                    "likely same data returned regardless of tamper"
                )
            elif similarity < 0.5 and tampered_status == 200:
                score += 20
                reasons.append(f"Significantly different response (similarity={similarity:.2f})")
            elif 0.5 <= similarity <= 0.95:
                score += 10
                reasons.append(f"Moderate response difference (similarity={similarity:.2f})")

            if diff.privileged_changes:
                score += 25
                reasons.append(
                    f"Privileged field(s) changed in response: {diff.privileged_changes[:3]}"
                )
            if diff.sensitive_changes:
                score += 20
                reasons.append(
                    f"Sensitive field(s) changed in response: {diff.sensitive_changes[:3]}"
                )
            if diff.structural_change and diff.new_keys:
                score += 15
                reasons.append(
                    f"New fields appeared in tampered response: {diff.new_keys[:5]}"
                )

            score += min(diff.confidence_boost, 30)
            if diff.confidence_boost > 0:
                reasons.append(
                    f"SemanticDiff confidence boost: +{min(diff.confidence_boost, 30)}"
                )

            for sig in diff.fp_signals:
                score -= 8
                fp_checks.append(f"SemanticDiff FP signal: {sig}")

            if diff.noise_ratio > 0.8 and not diff.structural_change:
                score -= 10
                fp_checks.append(
                    f"Response diff is {diff.noise_ratio:.0%} volatile fields "
                    "(timestamps/nonces) — real signal is weak"
                )
        else:
            similarity = difflib.SequenceMatcher(
                None, baseline_body[:2000], tampered_body[:2000]
            ).ratio()
            if similarity > 0.98:
                score -= 15
                fp_checks.append(f"Responses nearly identical (similarity={similarity:.2f})")
            elif similarity < 0.5 and tampered_status == 200:
                score += 20
                reasons.append(f"Significantly different response (similarity={similarity:.2f})")
            elif 0.5 <= similarity <= 0.95:
                score += 10
                reasons.append(f"Moderate response difference (similarity={similarity:.2f})")


        base_data = _safe_json(baseline_body)
        new_data = _safe_json(tampered_body)

        if isinstance(new_data, dict) and isinstance(base_data, dict):
            new_keys = set(new_data.keys()) - set(base_data.keys())
            if new_keys:
                score += 15
                reasons.append(f"New JSON keys in tampered response: {list(new_keys)[:5]}")


            sensitive = ["password", "secret", "token", "apikey", "api_key",
                         "ssn", "cvv", "private", "internal", "admin", "hash", "salt"]
            sens_found = [k for k in new_data if any(s in k.lower().replace("-", "_") for s in sensitive)]
            if sens_found:
                score += 20
                reasons.append(f"Sensitive fields in response: {sens_found[:3]}")

        elif isinstance(new_data, list) and isinstance(base_data, list):
            if len(new_data) > len(base_data) * 2:
                score += 20
                reasons.append(f"Response list grew from {len(base_data)} to {len(new_data)} items")


        if finding.confirmed:
            score += 25
            reasons.append("Finding independently confirmed (multi-user or re-verified)")



        if finding.severity == Severity.CRITICAL and score < 50:
            score = min(score, 49)  
            fp_checks.append("Critical severity requires stronger evidence — capped confidence")


        generic_responses = [
            '{"status": "ok"}',
            '{"success": true}',
            '{"message": "ok"}',
        ]
        if any(tampered_body.strip() == g for g in generic_responses):
            score -= 10
            fp_checks.append("Generic success response — may not indicate real business logic flaw")


        waf_signals = [
            "access denied", "request blocked", "security violation",
            "cloudflare", "akamai", "imperva", "sucuri", "mod_security",
        ]
        if any(w in tampered_lower for w in waf_signals):
            score -= 30
            fp_checks.append("WAF/security block detected in response — likely blocked, not vulnerable")


        score = max(0, min(100, score))
        finding.confidence = score
        finding.confidence_reasons = reasons
        finding.false_positive_checks = fp_checks
        return finding


def _safe_json(body: str):
    try:
        return json.loads(body)
    except Exception:
        return None


def severity_from_confidence(finding: Finding) -> Finding:
    """
    Downgrade severity if confidence is low.
    Prevents over-reporting unverified findings.
    """
    c = finding.confidence
    if c < 30 and finding.severity == Severity.CRITICAL:
        finding.severity = Severity.MEDIUM
        finding.confidence_reasons.append("Downgraded CRITICAL→MEDIUM due to low confidence")
    elif c < 20 and finding.severity == Severity.HIGH:
        finding.severity = Severity.LOW
        finding.confidence_reasons.append("Downgraded HIGH→LOW due to very low confidence")
    return finding
