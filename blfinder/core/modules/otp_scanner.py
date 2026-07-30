"""
BLFinder — core/modules/otp_scanner.py
OTP Rate-Limit & Lockout Bypass Scanner

Missing or bypassable rate limiting on an OTP verification endpoint is one
of the most consistently in-scope, consistently paid bug classes across
bug bounty programs — but it's also easy to test sloppily (fire N requests,
see none get blocked, call it done) or to overstep into an actual
account-takeover attempt. This module is scoped deliberately narrowly:

  It measures whether the OTP *verification* endpoint enforces a lockout
  after repeated wrong guesses, and if it does, whether that lockout can be
  bypassed — it does NOT attempt to brute-force the real OTP value itself.
  Attempt counts are bounded (hard-capped regardless of what's requested)
  and every guess is a random code, never a sweep of the full keyspace.

  This intentionally only targets the *verification* endpoint the operator
  points it at. It never touches an OTP *send/resend* endpoint on its own
  initiative, because repeatedly triggering OTP delivery can cost the
  target real money (SMS) or trip carrier abuse flags — that's a distinct,
  separately-scoped test the operator would run by hand if in scope.

Three independent tests, run in sequence:

  Test 1 — Sequential lockout-threshold detection
      Sends random wrong-length-correct OTP guesses one at a time (small
      delay between each, default 100ms) and watches for the first sign of
      a block: HTTP 429/403/423, a `Retry-After` header, or a response body
      phrase like "too many attempts" / "locked" / "try again later". If no
      such signal appears within the (capped) sample budget, that's strong
      evidence of missing rate limiting, and the module estimates real-world
      brute-force feasibility using the *actually measured* request rate
      against this specific target — not a generic assumption.

  Test 2 — Concurrent burst race-condition check
      Fires a burst of simultaneous requests (true asyncio.gather
      concurrency, not sequential) and counts how many are processed
      without a block signal. If more requests get through concurrently
      than the sequential test's lockout threshold would predict, the
      counter likely has a check-then-act race condition — a common bug
      where the attempt counter is read, checked, and incremented in
      separate steps that aren't atomic under concurrent load.

  Test 3 — Client-IP header spoofing bypass check
      Only runs if Test 1 found a real lockout. Re-attempts a handful of
      guesses while rotating `X-Forwarded-For` / `X-Real-IP` / `X-Client-IP`
      to a fresh random IP on every request. If the block signal stops
      appearing, the rate limit is keyed off a client-supplied header
      instead of the authenticated session/account — trivially bypassable.

A built-in safety valve: if any guess's response ever matches the
operator-supplied `success_marker` (indicating we accidentally landed on a
real, currently-valid OTP), the scan stops immediately and reports that
fact instead of continuing — this tool tests rate-limiting robustness, it
does not try to ride a lucky guess into an authenticated session.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field as dc_field

from ..models import Finding, Severity, ProofOfConcept

_HARD_MAX_SAMPLES = 500        # absolute ceiling regardless of what's requested
_HARD_MAX_CONCURRENCY = 50
_DEFAULT_SEQUENTIAL_DELAY = 0.1  # seconds between sequential guesses

_BLOCK_STATUS_CODES = {429, 403, 423}
_BLOCK_BODY_PHRASES = (
    "too many attempts", "too many requests", "rate limit", "rate-limit",
    "try again later", "temporarily locked", "account locked",
    "account is locked", "please wait", "blocked", "suspended",
    "too many failed attempts", "exceeded the maximum",
)


@dataclass
class OTPScanResult:
    otp_url: str
    digits: int
    attempts_made: int = 0
    lockout_attempt_index: int | None = None   # None = never observed
    measured_rate_per_sec: float = 0.0
    concurrency_attempts: int = 0
    concurrency_processed: int = 0
    header_bypass_succeeded: bool = False
    accidental_match: bool = False
    accidental_match_code: str = ""
    raw_log: list[dict] = dc_field(default_factory=list)


class OTPRateLimitScanner:
    """
    Usage:
        otp = OTPRateLimitScanner(scanner)
        result, findings = await otp.scan(
            otp_url="https://api.target.com/auth/verify-otp",
            method="POST",
            digits=6,
            field="otp",
            extra_body={"user_id": "123"},
            in_query=False,
            samples=20,
            concurrency=10,
            success_marker="\"verified\":true",
        )
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request

    # ── Public API ───────────────────────────────────────────────────────────

    async def scan(
        self,
        otp_url: str,
        method: str,
        digits: int,
        field: str = "otp",
        extra_body: dict | None = None,
        in_query: bool = False,
        samples: int = 20,
        concurrency: int = 10,
        success_marker: str = "",
        sequential_delay: float = _DEFAULT_SEQUENTIAL_DELAY,
        verbose: bool = False,
    ) -> tuple[OTPScanResult, list[Finding]]:
        digits = max(1, min(digits, 12))
        samples = max(1, min(samples, _HARD_MAX_SAMPLES))
        concurrency = max(1, min(concurrency, _HARD_MAX_CONCURRENCY))
        extra_body = extra_body or {}

        result = OTPScanResult(otp_url=otp_url, digits=digits)
        findings: list[Finding] = []

        # ── Test 1: sequential lockout-threshold detection ──────────────────
        used_codes: set[str] = set()
        elapsed_samples: list[float] = []

        for i in range(samples):
            code = self._random_code(digits, used_codes)
            status, headers, body, elapsed = await self._send_guess(
                otp_url, method, field, code, extra_body, in_query,
            )
            result.attempts_made += 1
            elapsed_samples.append(elapsed)
            result.raw_log.append({"i": i + 1, "code": code, "status": status, "elapsed": elapsed})

            if verbose:
                print(f"  [otp] attempt {i + 1}/{samples}: {code} -> {status} ({elapsed:.2f}s)")

            if success_marker and success_marker in (body or ""):
                result.accidental_match = True
                result.accidental_match_code = code
                findings.append(self._build_accidental_match_finding(otp_url, code, i + 1))
                return result, findings  # stop immediately — do not continue probing

            if self._looks_blocked(status, headers, body):
                result.lockout_attempt_index = i + 1
                if verbose:
                    print(f"  [otp] lockout signal observed at attempt {i + 1}")
                break

            if sequential_delay > 0:
                await asyncio.sleep(sequential_delay)

        if elapsed_samples:
            avg_elapsed = sum(elapsed_samples) / len(elapsed_samples)
            per_request_wall_time = avg_elapsed + sequential_delay
            result.measured_rate_per_sec = 1.0 / per_request_wall_time if per_request_wall_time > 0 else 0.0

        if result.lockout_attempt_index is None:
            findings.append(self._build_no_rate_limit_finding(result))

        # ── Test 2: concurrent burst race-condition check ───────────────────
        if not result.accidental_match:
            processed = await self._concurrency_burst_test(
                otp_url, method, field, digits, extra_body, in_query,
                concurrency, used_codes, success_marker, result, verbose,
            )
            result.concurrency_attempts = concurrency
            result.concurrency_processed = processed
            if (
                result.lockout_attempt_index is not None
                and processed > result.lockout_attempt_index
            ):
                findings.append(self._build_race_condition_finding(result))

        # ── Test 3: client-IP header spoofing bypass (only if a real lockout exists) ──
        if result.lockout_attempt_index is not None and not result.accidental_match:
            bypassed = await self._header_spoof_bypass_test(
                otp_url, method, field, digits, extra_body, in_query,
                used_codes, success_marker, result, verbose,
            )
            result.header_bypass_succeeded = bypassed
            if bypassed:
                findings.append(self._build_header_bypass_finding(result))

        return result, findings

    # ── Test 2 implementation ───────────────────────────────────────────────

    async def _concurrency_burst_test(
        self, otp_url, method, field, digits, extra_body, in_query,
        concurrency, used_codes, success_marker, result, verbose,
    ) -> int:
        codes = [self._random_code(digits, used_codes) for _ in range(concurrency)]

        async def one(code):
            try:
                status, headers, body, elapsed = await self._send_guess(
                    otp_url, method, field, code, extra_body, in_query,
                )
                return code, status, headers, body
            except Exception as e:
                if verbose:
                    print(f"  [otp] concurrency request error: {e}")
                return code, 0, {}, ""

        responses = await asyncio.gather(*(one(c) for c in codes))
        processed = 0
        for code, status, headers, body in responses:
            if success_marker and success_marker in (body or ""):
                result.accidental_match = True
                result.accidental_match_code = code
                continue
            if not self._looks_blocked(status, headers, body) and status != 0:
                processed += 1
        if verbose:
            print(f"  [otp] concurrency burst: {processed}/{concurrency} processed without a block signal")
        return processed

    # ── Test 3 implementation ───────────────────────────────────────────────

    async def _header_spoof_bypass_test(
        self, otp_url, method, field, digits, extra_body, in_query,
        used_codes, success_marker, result, verbose, attempts: int = 5,
    ) -> bool:
        for _ in range(attempts):
            code = self._random_code(digits, used_codes)
            fake_ip = self._random_ip()
            spoof_headers = {
                "X-Forwarded-For": fake_ip,
                "X-Real-IP": fake_ip,
                "X-Client-IP": fake_ip,
            }
            try:
                status, headers, body, elapsed = await self._request(
                    method, otp_url, headers=spoof_headers,
                    **self._payload_kwargs(field, code, extra_body, in_query),
                )
            except Exception as e:
                if verbose:
                    print(f"  [otp] header-spoof request error: {e}")
                continue
            if success_marker and success_marker in (body or ""):
                result.accidental_match = True
                result.accidental_match_code = code
                return False
            if not self._looks_blocked(status, headers, body) and status != 0:
                if verbose:
                    print(f"  [otp] header spoof with {fake_ip} was NOT blocked (status {status})")
                return True
        return False

    # ── Request helpers ──────────────────────────────────────────────────────

    def _payload_kwargs(self, field, code, extra_body, in_query) -> dict:
        if in_query:
            params = dict(extra_body)
            params[field] = code
            return {"params": params}
        body = dict(extra_body)
        body[field] = code
        return {"json": body}

    async def _send_guess(self, otp_url, method, field, code, extra_body, in_query):
        return await self._request(method, otp_url, **self._payload_kwargs(field, code, extra_body, in_query))

    def _looks_blocked(self, status: int, headers: dict, body: str) -> bool:
        if status in _BLOCK_STATUS_CODES:
            return True
        for k in (headers or {}):
            if k.lower() == "retry-after":
                return True
        lower = (body or "").lower()
        return any(p in lower for p in _BLOCK_BODY_PHRASES)

    def _random_code(self, digits: int, used: set[str]) -> str:
        space = 10 ** digits
        for _ in range(50):  # bounded retries to avoid infinite loop on tiny keyspaces
            n = random.randint(0, space - 1)
            code = str(n).zfill(digits)
            if code not in used:
                used.add(code)
                return code
        return str(random.randint(0, space - 1)).zfill(digits)

    def _random_ip(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    # ── Finding builders ─────────────────────────────────────────────────────

    def _build_no_rate_limit_finding(self, result: OTPScanResult) -> Finding:
        space = 10 ** result.digits
        rate = result.measured_rate_per_sec or 1.0
        worst_case_seconds = space / rate
        avg_case_seconds = worst_case_seconds / 2
        worst_case_human = self._human_duration(worst_case_seconds)
        avg_case_human = self._human_duration(avg_case_seconds)

        description = (
            f"`{result.attempts_made}` sequential wrong-OTP guesses were sent to "
            f"`{result.otp_url}` with no lockout signal (no 429/403/423, no "
            f"`Retry-After` header, no rate-limit-indicating response text) at any "
            f"point. At the measured request rate this specific endpoint actually "
            f"sustained (~{rate:.1f} req/s), exhausting the full "
            f"{result.digits}-digit keyspace ({space:,} codes) would take approximately "
            f"{worst_case_human} in the worst case, and {avg_case_human} on average "
            f"(expected number of attempts to hit the correct code by chance is half "
            f"the keyspace). A {result.digits}-digit OTP with no rate limiting is "
            f"brute-forceable within a practically achievable timeframe from a single "
            f"client, with no need for any bypass technique at all."
        )

        finding = Finding(
            title=f"Missing Rate Limiting on {result.digits}-Digit OTP Verification",
            severity=Severity.CRITICAL,
            category="OTP Rate Limiting",
            description=description,
            request={"method": "POST", "url": result.otp_url},
            response_summary=f"{result.attempts_made} attempts sent, no block signal observed",
            evidence=(
                f"Attempts: {result.attempts_made}, measured rate: {rate:.2f} req/s, "
                f"keyspace: {space:,}, estimated worst-case brute-force time: {worst_case_human}"
            ),
            recommendation=(
                "Enforce a hard lockout after a small number of failed attempts "
                "(e.g. 5) per OTP session/challenge, tied to the server-side "
                "session or account — not to a client-supplied header. Add "
                "exponential backoff and a maximum attempt count that permanently "
                "invalidates the current OTP and requires a fresh one to be issued. "
                "Consider increasing OTP length/entropy as defense-in-depth, but "
                "note that length alone does not fix a missing rate limit."
            ),
            cwe="CWE-307",
            cvss=9.1,
            owasp="OWASP Top 10 A07:2021 Identification and Authentication Failures",
            confirmed=True,
            confidence=85,
            confidence_reasons=[
                f"No block signal across {result.attempts_made} sequential attempts",
                "Estimate uses this endpoint's own measured response rate, not a generic assumption",
            ],
            false_positive_checks=[
                f"Only {result.attempts_made} of {space:,} total codes were tried — "
                "a lockout with a very high threshold (beyond the sample budget) "
                "cannot be ruled out; increase --otp-samples to raise confidence",
            ],
            endpoint=result.otp_url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary=f"No lockout observed after {result.attempts_made} wrong OTP guesses",
            curl_command=(
                f'for i in $(seq 1 30); do\n'
                f'  code=$(printf "%0{result.digits}d" $((RANDOM % {space})))\n'
                f'  curl -sk -X POST "{result.otp_url}" -H "Content-Type: application/json" \\\n'
                f'    -d "{{\\"otp\\": \\"$code\\"}}" -o /dev/null -w "%{{http_code}} "\n'
                f'done'
            ),
            python_script=(
                "import requests, random\n\n"
                f'url = "{result.otp_url}"\n'
                f"for _ in range(30):\n"
                f'    code = str(random.randint(0, {space - 1})).zfill({result.digits})\n'
                f'    r = requests.post(url, json={{"otp": code}})\n'
                f"    print(code, r.status_code)\n"
            ),
            burp_request="",
            expected_result="Every attempt returns the same 'invalid OTP' response with no blocking.",
            steps=["Repeat the request above and confirm no lockout/backoff ever triggers."],
        )
        return finding

    def _build_race_condition_finding(self, result: OTPScanResult) -> Finding:
        description = (
            f"A sequential test found a lockout signal after {result.lockout_attempt_index} "
            f"attempt(s), but firing {result.concurrency_attempts} requests "
            f"simultaneously (true concurrent burst, not sequential) resulted in "
            f"{result.concurrency_processed} of them being processed without a "
            f"block signal — more than the sequential threshold predicts. This "
            f"suggests the attempt counter is read, checked, and incremented in "
            f"separate, non-atomic steps, allowing concurrent requests to race past "
            f"the intended limit before the counter catches up."
        )
        finding = Finding(
            title="OTP Rate Limit Counter Race Condition (TOCTOU)",
            severity=Severity.HIGH,
            category="OTP Rate Limiting",
            description=description,
            request={"method": "POST", "url": result.otp_url},
            response_summary=(
                f"{result.concurrency_processed}/{result.concurrency_attempts} concurrent "
                f"attempts processed vs. sequential threshold of {result.lockout_attempt_index}"
            ),
            evidence=(
                f"Sequential lockout threshold: {result.lockout_attempt_index}; "
                f"concurrent burst processed: {result.concurrency_processed}/{result.concurrency_attempts}"
            ),
            recommendation=(
                "Use an atomic increment-and-check operation (e.g. a single "
                "Redis `INCR` + expiry, or a DB row lock / atomic UPDATE ... "
                "RETURNING) for the attempt counter, rather than a "
                "read-then-write pattern that different concurrent requests can "
                "interleave through."
            ),
            cwe="CWE-362",
            cvss=7.5,
            owasp="OWASP Top 10 A07:2021 Identification and Authentication Failures",
            confirmed=False,
            confidence=60,
            confidence_reasons=[
                "Concurrent processed count exceeded the sequential lockout threshold",
            ],
            false_positive_checks=[
                "Result is best-effort against a single burst; re-verify with a "
                "fresh OTP session before reporting, since lockout windows that "
                "reset on a timer can produce a similar-looking result",
            ],
            endpoint=result.otp_url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary="Concurrent burst processed more attempts than the sequential lockout allows",
            curl_command=(
                f'seq 1 {result.concurrency_attempts} | xargs -P {result.concurrency_attempts} -I{{}} '
                f'curl -sk -X POST "{result.otp_url}" -H "Content-Type: application/json" '
                f'-d "{{\\"otp\\": \\"000000\\"}}" -o /dev/null -w "%{{http_code}}\\n"'
            ),
            python_script=(
                "import asyncio, aiohttp, random\n\n"
                f'url = "{result.otp_url}"\n'
                f"async def one(session, code):\n"
                f"    async with session.post(url, json={{'otp': code}}) as r:\n"
                f"        return r.status\n\n"
                f"async def main():\n"
                f"    async with aiohttp.ClientSession() as session:\n"
                f"        codes = [str(random.randint(0, {10 ** result.digits - 1})).zfill({result.digits}) "
                f"for _ in range({result.concurrency_attempts})]\n"
                f"        results = await asyncio.gather(*(one(session, c) for c in codes))\n"
                f"        print(results)\n\n"
                f"asyncio.run(main())\n"
            ),
            burp_request="",
            expected_result="More requests are processed than the sequential lockout threshold predicts.",
            steps=["Send a fresh burst of concurrent requests against a new OTP session and compare counts."],
        )
        return finding

    def _build_header_bypass_finding(self, result: OTPScanResult) -> Finding:
        description = (
            f"After a lockout was confirmed at attempt {result.lockout_attempt_index}, "
            f"retrying with a randomized `X-Forwarded-For`/`X-Real-IP`/`X-Client-IP` "
            f"header on each request caused the block signal to disappear — "
            f"requests were processed again as if no lockout were in effect. This "
            f"indicates the rate limiter keys its counter off a client-supplied "
            f"header rather than the authenticated session or account, making the "
            f"lockout trivially bypassable by rotating a spoofed IP header on every "
            f"request."
        )
        finding = Finding(
            title="OTP Rate Limit Bypass via Spoofed Client-IP Header",
            severity=Severity.CRITICAL,
            category="OTP Rate Limiting",
            description=description,
            request={"method": "POST", "url": result.otp_url},
            response_summary="Lockout signal disappeared once X-Forwarded-For/X-Real-IP/X-Client-IP was randomized",
            evidence=f"Lockout observed at attempt {result.lockout_attempt_index}; bypassed by header rotation",
            recommendation=(
                "Never trust client-supplied IP headers for rate-limiting/lockout "
                "keys unless they are stripped and re-set by a trusted, "
                "application-controlled reverse proxy that the client cannot "
                "reach directly. Key the lockout counter off the authenticated "
                "session/account/OTP-challenge ID instead."
            ),
            cwe="CWE-290",
            cvss=9.1,
            owasp="OWASP Top 10 A07:2021 Identification and Authentication Failures",
            confirmed=True,
            confidence=88,
            confidence_reasons=[
                "Block signal reproducibly disappeared when rotating spoofed client-IP headers",
            ],
            endpoint=result.otp_url,
            parameter="",
        )
        finding.poc = ProofOfConcept(
            summary="Spoofed X-Forwarded-For bypasses the OTP lockout",
            curl_command=(
                f'curl -sk -X POST "{result.otp_url}" \\\n'
                f'  -H "X-Forwarded-For: $RANDOM.$RANDOM.$RANDOM.$RANDOM" \\\n'
                f'  -H "Content-Type: application/json" -d \'{{"otp": "000000"}}\' -i'
            ),
            python_script=(
                "import requests, random\n\n"
                f'url = "{result.otp_url}"\n'
                "fake_ip = '.'.join(str(random.randint(1,254)) for _ in range(4))\n"
                "headers = {'X-Forwarded-For': fake_ip, 'X-Real-IP': fake_ip}\n"
                'r = requests.post(url, headers=headers, json={"otp": "000000"})\n'
                "print(r.status_code)\n"
            ),
            burp_request="",
            expected_result="Request is processed (not blocked) despite the account/session being locked out.",
            steps=["Trigger the lockout normally, then retry with a fresh spoofed IP header per request."],
        )
        return finding

    def _build_accidental_match_finding(self, otp_url: str, code: str, attempt_index: int) -> Finding:
        finding = Finding(
            title="Random OTP Guess Matched a Currently-Valid Code",
            severity=Severity.INFO,
            category="OTP Rate Limiting",
            description=(
                f"A random {len(code)}-digit guess (`{code}`) matched the "
                f"operator-supplied success marker on attempt {attempt_index}. The "
                f"scan was stopped immediately rather than proceeding, since "
                f"continuing would mean actively exploiting a real authentication "
                f"bypass rather than testing rate-limiting robustness. This is "
                f"either an extraordinary coincidence, a test/demo account with a "
                f"predictable or static code, or a very small effective keyspace — "
                f"investigate manually before drawing conclusions."
            ),
            request={"method": "POST", "url": otp_url},
            response_summary="Success marker matched",
            evidence=f"Matched on attempt {attempt_index} with code {code}",
            recommendation=(
                "If this is a test/demo account, exclude it from testing. If it "
                "occurred on a real account, investigate whether the OTP "
                "generation is predictable or the effective keyspace is much "
                "smaller than the stated digit count suggests."
            ),
            cwe="CWE-330",
            cvss=0.0,
            owasp="OWASP Top 10 A07:2021 Identification and Authentication Failures",
            confirmed=False,
            confidence=20,
            endpoint=otp_url,
            parameter="",
        )
        return finding

    def _human_duration(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f} minutes"
        hours = minutes / 60
        if hours < 24:
            return f"{hours:.1f} hours"
        days = hours / 24
        if days < 365:
            return f"{days:.1f} days"
        years = days / 365
        return f"{years:.1f} years"
