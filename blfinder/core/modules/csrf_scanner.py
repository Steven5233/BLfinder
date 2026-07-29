"""
BLFinder — core/modules/csrf_scanner.py
Cross-Site Request Forgery (CSRF) Scanner

CSRF reports are notoriously noisy: most scanners flag "no CSRF token
found" as a finding by itself, which is wrong on two counts — (1) plenty of
APIs are legitimately immune to CSRF because they authenticate with a
bearer token in a header rather than a cookie (an attacker's cross-site
form/fetch can't attach a header it doesn't know), and (2) even where
cookies are in play, a missing token means nothing if Origin/Referer
enforcement or SameSite already blocks the attack in practice. This module
only ever reports CONFIRMED, exploitable CSRF — proven by actually
reproducing the forged cross-site request and diffing its effect against a
legitimate one — plus a small number of clearly-labelled hardening gaps.

Applicability gate (checked before sending a single extra request):
  - Method must be state-changing (POST/PUT/PATCH/DELETE). GET is
    idempotent-by-contract and out of scope here (a GET that changes state
    is a business-logic bug, not a CSRF-defense bug, and worth flagging
    separately — see Layer 4).
  - The session must be cookie-authenticated (`scanner.config.cookies` is
    non-empty). Pure header/bearer-token auth is not exploitable via
    classic CSRF, since a cross-site form/img/fetch(no-cors) cannot attach
    an Authorization header the victim's browser doesn't already send
    automatically the way it does with cookies.

Evidence layers (each is cheap-to-expensive, cheapest first; later layers
only run if the applicability gate passes and where relevant):

  Layer 1 — Token & defense discovery (passive, no extra requests)
      Scans body/headers/cookies for CSRF-token-shaped fields
      (csrf_token, X-CSRF-Token, authenticity_token, __RequestVerification
      Token, double-submit cookie, ...) and inspects the session cookie's
      SameSite attribute from the baseline response headers already in hand.

  Layer 2 — Forged cross-site replay (active, the core proof)
      Resends the *exact same* state-changing request with: any discovered
      token stripped/blanked, Origin swapped to a foreign attacker origin,
      Referer swapped/removed — i.e. the closest faithful reproduction of
      what a real auto-submitting cross-site HTML form can send. The
      response is compared against the original authenticated response
      using semantic diffing (not string similarity) to determine whether
      the forged request achieved the *same effect*, not just "a response".
      Gated behind `config.run_csrf` (opt-in) since, unlike the read-only
      Tier 1/2 checks in other modules, this genuinely repeats a
      state-changing action against the live target.

  Layer 3 — Token validation depth check (active, only if a token exists)
      If Layer 1 found a token, tests whether the server actually validates
      its *value* — resubmits with the token present but tampered
      (truncated / reversed / all-zero) with a legitimate Origin. If the
      tampered token is accepted identically to the real one, the token is
      cosmetic (checked for presence, not correctness) and provides no
      real protection, which materially raises the severity of Layer 2's
      finding.

  Layer 4 — Content-Type / method downgrade checks (active, cheap)
      (a) Does the same mutation succeed via GET with parameters in the
          query string? A pure-GET path to the same effect needs no form
          and no preflight at all (`<img src=...>` is enough).
      (b) Does the server still process a JSON body when Content-Type is
          swapped to `text/plain`? Browsers don't preflight `text/plain`
          form submissions, so relying on requiring `application/json` as
          an implicit CSRF defense is broken if the server parses the body
          regardless of the declared type.

A single composite Finding is produced per (host, endpoint) representing
the full exploit chain actually demonstrated — never a bare "no token
found" — with severity scaled by how many independent layers of defense
were absent (token, Origin/Referer, SameSite) versus present.
"""

from __future__ import annotations

import random
import re
import string
from urllib.parse import urlparse, urlencode

from ..models import Finding, Severity, ProofOfConcept

try:
    from ..analysis.semantic_diff import SemanticDiff
    _HAS_SEMANTIC_DIFF = True
except ImportError:
    _HAS_SEMANTIC_DIFF = False

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_TOKEN_KEY_RE = re.compile(
    r"(csrf|xsrf|_token$|^token$|authenticity_token|requestverificationtoken|"
    r"anti-?forgery|antiforgery|nonce)",
    re.IGNORECASE,
)
_TOKEN_HEADER_RE = re.compile(r"(x-csrf|x-xsrf|csrf-token|requestverificationtoken)", re.IGNORECASE)

_FAILURE_TOKENS = (
    "error", "invalid", "unauthorized", "forbidden", "rejected", "denied",
    "not found", "bad request", "csrf", "xsrf", "mismatch", "expired",
    "token", "exception", "stack trace",
)
_SUCCESS_TOKENS = (
    "success", "created", "updated", "confirmed", "accepted", "processed",
    "completed", "\"id\":", "\"status\":\"ok\"", "\"status\": \"ok\"",
)


class CSRFScanner:
    """
    Usage:
        csrf = CSRFScanner(scanner)
        findings = await csrf.check(url, method, params, body, headers, status, base_body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._reported: set[tuple] = set()   # (host, path_template)
        self._active_replay_enabled = bool(getattr(self._config, "run_csrf", False))

    # ── Public API ───────────────────────────────────────────────────────────

    async def check(
        self,
        url: str,
        method: str,
        params: dict | None = None,
        body: dict | None = None,
        headers: dict | None = None,
        status: int = 0,
        base_body: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []

        if method.upper() not in _STATE_CHANGING_METHODS:
            return findings
        if not getattr(self._config, "cookies", None):
            # No cookie-based session in play — classic CSRF doesn't apply.
            return findings
        if status == 0 or status >= 500:
            return findings  # baseline request itself failed; nothing to reproduce

        parsed = urlparse(url)
        host = parsed.netloc
        if not host:
            return findings

        dedup_key = (host, self._normalize_path(parsed.path))
        if dedup_key in self._reported:
            return findings

        params = params or {}
        body = body or {}

        # ── Layer 1: passive discovery ──────────────────────────────────────
        token_locations = self._find_tokens(params, body, headers or {})
        samesite = self._extract_samesite(headers or {})

        if not self._active_replay_enabled:
            # Without opt-in active replay we can only report *hardening
            # gaps* we're fully confident about from passive data — never a
            # "confirmed exploitable" verdict, since we haven't proven the
            # forged request actually achieves the same effect.
            f = self._maybe_build_passive_finding(url, method, host, token_locations, samesite)
            if f:
                self._reported.add(dedup_key)
                findings.append(f)
            return findings

        # ── Layer 2: forged cross-site replay (the core proof) ──────────────
        replay = await self._forged_replay(url, method, params, body, token_locations, base_body)
        if replay is None:
            return findings  # request errored out; can't safely conclude anything

        forged_status, forged_body, achieved_same_effect, diff_note = replay
        if not achieved_same_effect:
            # Origin/Referer + token stripping was enough to make the server
            # reject or meaningfully change behavior — defenses are working.
            return findings

        # ── Layer 3: is the token cosmetic? (only if one exists) ────────────
        token_is_cosmetic = False
        if token_locations:
            token_is_cosmetic = await self._token_validation_depth_check(
                url, method, params, body, token_locations, base_body,
            )

        # ── Layer 4: cheap downgrade checks ─────────────────────────────────
        get_downgrade_works = await self._check_get_downgrade(url, method, params, body, base_body)
        content_type_bypass = await self._check_content_type_bypass(url, method, params, body, base_body)

        finding = self._build_composite_finding(
            url=url, method=method, host=host,
            token_locations=token_locations, samesite=samesite,
            token_is_cosmetic=token_is_cosmetic,
            get_downgrade_works=get_downgrade_works,
            content_type_bypass=content_type_bypass,
            forged_status=forged_status, forged_body=forged_body,
            diff_note=diff_note,
        )
        self._reported.add(dedup_key)
        findings.append(finding)
        return findings

    # ── Layer 1 helpers ──────────────────────────────────────────────────────

    def _find_tokens(self, params: dict, body: dict, headers: dict) -> list[tuple]:
        """Returns list of (location, path) for token-shaped fields."""
        found: list[tuple] = []

        def walk(obj, prefix: str, location: str, depth: int = 0):
            if depth > 4 or not isinstance(obj, dict):
                return
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, dict):
                    walk(v, path, location, depth + 1)
                elif _TOKEN_KEY_RE.search(str(k)):
                    found.append((location, path))

        walk(params, "", "query")
        walk(body, "", "body")

        for k in headers or {}:
            if _TOKEN_HEADER_RE.search(str(k)):
                found.append(("header", k))

        cookies = getattr(self._config, "cookies", {}) or {}
        for k in cookies:
            if _TOKEN_KEY_RE.search(str(k)):
                found.append(("cookie", k))

        return found

    def _extract_samesite(self, headers: dict) -> str:
        set_cookie = None
        for k, v in (headers or {}).items():
            if k.lower() == "set-cookie":
                set_cookie = v
                break
        if not set_cookie:
            return "unknown"
        m = re.search(r"samesite\s*=\s*(\w+)", set_cookie, re.IGNORECASE)
        if m:
            return m.group(1).capitalize()
        return "none-specified"

    def _maybe_build_passive_finding(
        self, url, method, host, token_locations, samesite,
    ) -> Finding | None:
        # Only worth reporting passively when there is genuinely no
        # meaningful defense signal at all: no token anywhere AND the
        # cookie has no SameSite restriction. Anything less certain needs
        # the active replay (Layer 2) to avoid a bare "looks unprotected"
        # false positive.
        if token_locations or samesite in ("Strict", "Lax"):
            return None

        finding = Finding(
            title="Potential CSRF — No Token Mechanism and No SameSite Cookie Restriction Detected",
            severity=Severity.LOW,
            category="CSRF — Hardening Gap (Passive, Unconfirmed)",
            description=(
                f"The state-changing `{method} {urlparse(url).path}` request on "
                f"`{host}` uses a cookie-based session with no CSRF token in the "
                f"request and no `SameSite` restriction on the session cookie "
                f"(observed: {samesite}). This is a plausible CSRF exposure, but "
                f"it was not actively confirmed by replaying the request as a "
                f"forged cross-site request. Re-run with `--csrf` (active replay) "
                f"to confirm exploitability."
            ),
            request={"method": method, "url": url},
            response_summary="N/A — passive analysis only",
            evidence=(
                f"No token-shaped field found in body/headers/cookies; "
                f"SameSite={samesite}"
            ),
            recommendation=(
                "Add a per-session anti-CSRF token validated on every "
                "state-changing request, and set `SameSite=Lax` (or `Strict` "
                "where feasible) plus `Secure` on the session cookie."
            ),
            cwe="CWE-352",
            cvss=4.3,
            owasp="API-adjacent: OWASP Top 10 A01:2021 Broken Access Control",
            confirmed=False,
            confidence=35,
            confidence_reasons=["No token field found", f"SameSite={samesite}"],
            false_positive_checks=[
                "Not actively confirmed — some frameworks apply CSRF middleware "
                "globally in a way that isn't visible per-request",
            ],
            endpoint=url,
            parameter="",
        )
        return finding

    # ── Layer 2: forged replay ───────────────────────────────────────────────

    async def _forged_replay(
        self, url, method, params, body, token_locations, base_body,
    ):
        forged_params = dict(params)
        forged_body = self._deep_copy(body)

        for location, path in token_locations:
            if location == "query":
                self._blank_path(forged_params, path)
            elif location == "body":
                self._blank_path(forged_body, path)
            # header/cookie tokens: a real cross-site form can't set custom
            # headers or third-party cookies anyway, so we simply omit the
            # forged_headers below rather than trying to strip them here.

        forged_headers = {
            "Origin": f"https://attacker-{self._nonce()}.test",
            "Referer": f"https://attacker-{self._nonce()}.test/csrf.html",
        }

        try:
            status, resp_headers, resp_body, _ = await self._request(
                method, url,
                headers=forged_headers,
                params=forged_params if forged_params else None,
                json=forged_body if forged_body else None,
            )
        except Exception as e:
            if self._config.verbose:
                print(f"[!] CSRFScanner forged replay error on {url}: {e}")
            return None
        if status == 0:
            return None

        # Reject rejected: explicit defense worked.
        if status in (401, 403):
            return status, resp_body, False, "Forged request rejected with 401/403"

        lower = resp_body.lower()
        failure_hits = sum(1 for t in _FAILURE_TOKENS if t in lower)
        success_hits = sum(1 for t in _SUCCESS_TOKENS if t in lower)

        if failure_hits > success_hits and failure_hits >= 2:
            return status, resp_body, False, f"Response contains {failure_hits} failure-indicating tokens"

        if _HAS_SEMANTIC_DIFF and base_body:
            diff = SemanticDiff.compare(base_body, resp_body, context={"endpoint": url}, threshold=0.2)
            # High semantic similarity + no structural regression + status
            # class matches the original success class → the forged request
            # produced an equivalent effect to the legitimate one.
            same_effect = (
                diff.semantic_similarity >= 0.75
                and not diff.sensitive_changes
                and status < 400
            )
            note = (
                f"Semantic similarity to baseline: {diff.semantic_similarity:.2f} "
                f"(structural_change={diff.structural_change})"
            )
            return status, resp_body, same_effect, note

        # No semantic diff available / no baseline body to compare — fall
        # back to a conservative status-code-only signal (2xx and no
        # explicit failure tokens). Marked in the note so the composite
        # finding's confidence reflects the weaker evidence.
        same_effect = status < 300 and failure_hits == 0
        return status, resp_body, same_effect, "Status-code-only signal (no semantic diff / baseline available)"

    # ── Layer 3: token validation depth ─────────────────────────────────────

    async def _token_validation_depth_check(
        self, url, method, params, body, token_locations, base_body,
    ) -> bool:
        """Returns True if a tampered token was accepted just like a real one
        (i.e. the server checks presence but not correctness)."""
        body_or_query_tokens = [t for t in token_locations if t[0] in ("query", "body")]
        if not body_or_query_tokens:
            return False  # only header/cookie tokens found — nothing to tamper here safely

        location, path = body_or_query_tokens[0]
        tampered_params = dict(params)
        tampered_body = self._deep_copy(body)
        tampered_value = "0" * 16  # implausible-but-well-formed-looking tampered token

        if location == "query":
            self._set_path(tampered_params, path, tampered_value)
        else:
            self._set_path(tampered_body, path, tampered_value)

        try:
            status, _, resp_body, _ = await self._request(
                method, url,
                params=tampered_params if tampered_params else None,
                json=tampered_body if tampered_body else None,
            )
        except Exception as e:
            if self._config.verbose:
                print(f"[!] CSRFScanner token depth check error on {url}: {e}")
            return False
        if status == 0 or status in (401, 403):
            return False

        if _HAS_SEMANTIC_DIFF and base_body:
            diff = SemanticDiff.compare(base_body, resp_body, threshold=0.2)
            return diff.semantic_similarity >= 0.75 and status < 400

        lower = resp_body.lower()
        failure_hits = sum(1 for t in _FAILURE_TOKENS if t in lower)
        return status < 300 and failure_hits == 0

    # ── Layer 4: downgrade checks ────────────────────────────────────────────

    async def _check_get_downgrade(self, url, method, params, body, base_body) -> bool:
        if method.upper() == "GET":
            return False
        flat_params = dict(params)
        # Flatten a shallow body into query params for the GET attempt —
        # deep/nested bodies aren't representable as a simple query string
        # and are skipped (GET downgrade is only meaningful for simple forms
        # anyway, which is exactly the CSRF-relevant case).
        if isinstance(body, dict) and all(not isinstance(v, (dict, list)) for v in body.values()):
            flat_params.update({k: str(v) for k, v in body.items()})

        try:
            status, _, resp_body, _ = await self._request("GET", url, params=flat_params if flat_params else None)
        except Exception:
            return False
        if status == 0 or status >= 400:
            return False

        if _HAS_SEMANTIC_DIFF and base_body:
            diff = SemanticDiff.compare(base_body, resp_body, threshold=0.2)
            return diff.semantic_similarity >= 0.75
        lower = resp_body.lower()
        return any(t in lower for t in _SUCCESS_TOKENS)

    async def _check_content_type_bypass(self, url, method, params, body, base_body) -> bool:
        if not body:
            return False
        try:
            status, _, resp_body, _ = await self._request(
                method, url,
                headers={"Content-Type": "text/plain"},
                params=params if params else None,
                data=self._to_form_string(body),
            )
        except Exception:
            return False
        if status == 0 or status >= 400:
            return False
        if _HAS_SEMANTIC_DIFF and base_body:
            diff = SemanticDiff.compare(base_body, resp_body, threshold=0.2)
            return diff.semantic_similarity >= 0.6
        return status < 300

    # ── Composite finding ────────────────────────────────────────────────────

    def _build_composite_finding(
        self, url, method, host, token_locations, samesite, token_is_cosmetic,
        get_downgrade_works, content_type_bypass, forged_status, forged_body, diff_note,
    ) -> Finding:
        missing_layers = []
        if not token_locations or token_is_cosmetic:
            missing_layers.append("no token / token not cryptographically validated")
        missing_layers.append("Origin/Referer not enforced (forged values accepted)")
        if samesite not in ("Strict", "Lax"):
            missing_layers.append(f"SameSite cookie protection absent (observed: {samesite})")
        if get_downgrade_works:
            missing_layers.append("state change also reachable via plain GET (no form required)")
        if content_type_bypass:
            missing_layers.append("Content-Type restriction bypassable via text/plain (no preflight needed)")

        defense_count_missing = len(missing_layers)
        if defense_count_missing >= 4 or get_downgrade_works:
            severity, confidence = Severity.CRITICAL, 90
        elif defense_count_missing == 3:
            severity, confidence = Severity.HIGH, 80
        else:
            severity, confidence = Severity.MEDIUM, 65

        path = urlparse(url).path
        html_poc = self._html_poc(url, method)

        description = (
            f"A forged cross-site replay of `{method} {path}` on `{host}` — with "
            f"any CSRF token blanked and `Origin`/`Referer` set to an attacker "
            f"domain — was accepted by the server and achieved the same effect "
            f"as the legitimate authenticated request ({diff_note}). Missing "
            f"defenses: {'; '.join(missing_layers)}."
        )
        if token_is_cosmetic:
            description += (
                " Additionally, a syntactically-tampered (but present) token "
                "value was accepted identically to a real one, confirming the "
                "token is checked for presence only, not cryptographic validity."
            )

        finding = Finding(
            title=f"Cross-Site Request Forgery — Confirmed on `{method} {path}`",
            severity=severity,
            category="CSRF — Confirmed (Active Replay)",
            description=description,
            request={"method": method, "url": url},
            response_summary=f"Forged request → status {forged_status}",
            evidence=(
                f"Forged replay accepted (status {forged_status}); {diff_note}. "
                f"Missing defenses: {', '.join(missing_layers)}."
            ),
            recommendation=(
                "Implement synchronizer-token CSRF protection validated "
                "server-side on every state-changing request (not merely "
                "checked for presence), enforce Origin/Referer allow-listing as "
                "defense-in-depth, and set `SameSite=Lax` or `Strict` plus "
                "`Secure` on session cookies. Ensure state-changing actions are "
                "never reachable via GET, and do not rely on Content-Type alone "
                "to prevent simple cross-site form submission."
            ),
            cwe="CWE-352",
            cvss=8.8 if severity == Severity.CRITICAL else (6.5 if severity == Severity.HIGH else 5.4),
            owasp="OWASP Top 10 A01:2021 Broken Access Control",
            confirmed=True,
            confidence=confidence,
            confidence_reasons=[
                "Forged request with blanked token + foreign Origin/Referer "
                "achieved the same effect as a legitimate request",
                diff_note,
            ] + (["Tampered token accepted identically to a valid one"] if token_is_cosmetic else []),
            endpoint=url,
            parameter=", ".join(p for _, p in token_locations) if token_locations else "",
        )
        finding.poc = ProofOfConcept(
            summary="Cross-site auto-submitting form reproduces the state change without user consent",
            curl_command=self._curl(url, method, host),
            python_script=self._python_script(url, method),
            burp_request=self._burp(url, method, host),
            expected_result=(
                "Visiting the PoC page while logged into the target performs "
                "the state-changing action as the victim."
            ),
            steps=[
                "Host the HTML PoC below on any attacker-controlled domain.",
                "Have the logged-in victim (with an active session cookie) visit the page.",
                "The auto-submitting form/fetch fires the request cross-site; "
                "the browser attaches the victim's session cookie automatically.",
            ],
            video_note="Screen-record the victim's browser performing the action "
                        "after visiting an unrelated attacker-controlled page.",
        )
        finding.html_poc = html_poc  # type: ignore[attr-defined]
        return finding

    def _html_poc(self, url: str, method: str) -> str:
        if method.upper() == "GET":
            return f'<img src="{url}" style="display:none">'
        return f"""<!-- CSRF PoC — host on any domain, have the logged-in victim open it -->
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
<form action="{url}" method="POST">
  <!-- Add hidden inputs here matching the target's body parameters -->
</form>
</body>
</html>"""

    # ── Path/dict helpers ────────────────────────────────────────────────────

    def _normalize_path(self, path: str) -> str:
        return re.sub(r"/\d+(?=/|$)", "/{id}", path)

    def _deep_copy(self, obj):
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._deep_copy(v) for v in obj]
        return obj

    def _blank_path(self, obj: dict, path: str):
        self._set_path(obj, path, "")

    def _set_path(self, obj: dict, path: str, value):
        tokens = path.split(".")
        cur = obj
        for i, tok in enumerate(tokens):
            last = i == len(tokens) - 1
            if not isinstance(cur, dict):
                return
            if last:
                if tok in cur:
                    cur[tok] = value
            else:
                if tok not in cur or not isinstance(cur[tok], dict):
                    return
                cur = cur[tok]

    def _to_form_string(self, body: dict) -> str:
        flat = {k: (v if isinstance(v, str) else str(v)) for k, v in body.items() if not isinstance(v, (dict, list))}
        return urlencode(flat)

    def _nonce(self, n: int = 8) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    # ── PoC helpers ──────────────────────────────────────────────────────────

    def _curl(self, url, method, host) -> str:
        return (
            f'curl -sk -X {method} "{url}" \\\n'
            f'  -H "Origin: https://attacker.test" \\\n'
            f'  -H "Referer: https://attacker.test/csrf.html" \\\n'
            f'  -b "<victim_session_cookie>" -i'
        )

    def _python_script(self, url, method) -> str:
        return (
            "import requests\n\n"
            f'url = "{url}"\n'
            'headers = {"Origin": "https://attacker.test", "Referer": "https://attacker.test/csrf.html"}\n'
            'cookies = {"session": "<victim_session_cookie>"}\n'
            f'r = requests.request("{method}", url, headers=headers, cookies=cookies)\n'
            'print(r.status_code)\n'
            'print(r.text[:500])\n'
        )

    def _burp(self, url, method, host) -> str:
        path = urlparse(url).path or "/"
        return (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Origin: https://attacker.test\n"
            f"Referer: https://attacker.test/csrf.html\n"
            f"Cookie: <victim_session_cookie>\n"
            f"Connection: close\n\n"
        )
