"""
BLFinder — core/modules/tenant_bola.py
Cross-Tenant / Organization-Boundary BOLA Scanner

Distinct from idor_mass_enum.py's resource-ID enumeration: that module asks
"can I change the resource ID and see someone else's record?" This module
asks a different question — "can I keep MY OWN valid resource ID/token and
just change the org/tenant/workspace scoping value to reach another
customer's entire account?" That's the bug class B2B SaaS programs
(Stripe/Shopify/GitLab-style targets) pay the most for, because it usually
exposes an entire organization's data rather than one record.

Two techniques, tried in order of reliability:

  1. Cross-account confirmation (requires `second_user_token` in config —
     a valid token for a SECOND, DIFFERENT tenant account). Replays the
     exact original org-scoped URL, unmodified, with the second account's
     token. If it succeeds, that's a direct, unambiguous proof: account B
     reached account A's org-scoped resource. No guessing involved.

  2. Same-token org-ID swap (works with only the primary token). Keeps the
     token fixed and swaps the org/tenant/workspace identifier in the URL
     to a harvested or guessed alternate value, then checks whether the
     response is a genuine, meaningfully-different success response (not
     a 404 for a nonexistent org, and not the same data being echoed back
     because the parameter was silently ignored).

Known limitation, stated plainly rather than hidden: technique 1 assumes
`second_user_token` belongs to an ordinary member of a genuinely different
tenant, not an admin/staff account — an admin token legitimately reaching
other tenants' data is not a bug. This module has no way to verify that
assumption on its own; it's on the operator to configure a real second
low-privilege account for this check to be meaningful.

Only path segments and query parameters are covered in this version — a
tenant identifier passed purely via a request header or JSON body field
would need the caller to hand those in separately, which the current
scanner call site doesn't do. Worth a follow-up if you hit APIs that only
scope tenancy through headers.
"""

from __future__ import annotations

import difflib
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from ..models import Finding, Severity, ProofOfConcept
from .idor_mass_enum import _detect_id_type, _build_numeric_range

try:
    from ..analysis.semantic_diff import SemanticDiff
    _HAS_SEMANTIC_DIFF = True
except ImportError:
    _HAS_SEMANTIC_DIFF = False

_TENANT_PATH_KEYWORDS = (
    "org", "orgs", "organization", "organizations",
    "tenant", "tenants", "workspace", "workspaces",
    "company", "companies", "team", "teams",
)



_TENANT_PATH_KEYWORDS_SOFT = ("account", "accounts")

_TENANT_QUERY_KEY_RE = re.compile(
    r"^(org|organization|tenant|workspace|company|team)_?id$", re.I
)

_TENANT_HARVEST_RE = re.compile(
    r'"(org_?id|organization_?id|tenant_?id|workspace_?id|company_?id)"\s*:\s*"?([A-Za-z0-9_\-]{1,64})"?',
    re.I,
)


class TenantBOLAScanner:
    """
    Usage:
        tenant_bola = TenantBOLAScanner(scanner)
        findings = await tenant_bola.check(url, method, status, body)
        scanner.findings.extend(findings)
    """

    def __init__(self, scanner):
        self._scanner = scanner
        self._config = scanner.config
        self._request = scanner._request
        self._resp_ok = getattr(scanner, "_response_indicates_success", None)
        self._second_token = getattr(self._config, "second_user_token", "") or ""
        self._harvested_ids: set[str] = set()
        self._reported: set[tuple] = set()   



    async def check(self, url: str, method: str, status: int, body: str) -> list[Finding]:
        findings: list[Finding] = []
        self._harvest_ids(body)

        if status not in (200, 201) or not self._looks_ok(body, status):
            return findings  

        locations = self._find_tenant_locations(url)
        if not locations:
            return findings

        for loc in locations[:3]:   
            key = (self._normalise_path(url), loc["signature"])
            if key in self._reported:
                continue

            finding = None
            if self._second_token:
                finding = await self._test_cross_account(url, method, body, loc)

            if not finding:
                finding = await self._test_same_token_swap(url, method, body, loc)

            if finding:
                self._reported.add(key)
                findings.append(finding)

        return findings



    async def _test_cross_account(self, url, method, base_body, loc):
        try:
            status2, _, body2, _ = await self._request(
                method, url, token_override=self._second_token
            )
        except Exception as e:
            if self._config.verbose:
                print(f"[!] TenantBOLAScanner cross-account probe on {url}: {e}")
            return None
        if status2 == 0 or status2 not in (200, 201):
            return None
        if not self._looks_ok(body2, status2):
            return None

        return self._build(
            url, method, loc,
            title=f"Cross-Tenant BOLA — {loc['keyword']} Boundary Not Enforced",
            severity=Severity.CRITICAL, confidence=90,
            technique="cross_account",
            description=(
                f"A second account's token (a different tenant/user, configured "
                f"as `second_user_token`) successfully accessed this "
                f"`{loc['keyword']}`-scoped resource unmodified: `{url}`. The "
                f"backend is not verifying that the requesting account actually "
                f"belongs to the `{loc['keyword']}` referenced in the URL — any "
                f"authenticated account can reach another organization's data "
                f"by hitting its URLs directly, regardless of membership."
            ),
            recommendation=(
                f"On every request, verify server-side that the authenticated "
                f"user is a member of the `{loc['keyword']}` in the URL/params "
                f"before returning data — never rely on the URL alone to scope "
                f"the query."
            ),
            evidence=(
                f"Second account's token → {method} {url} → HTTP {status2}, "
                f"recognised as a successful authenticated response."
            ),
            cwe="CWE-863", cvss=8.5,
            confirmed_note=(
                "Confirmed with an independent second account — not a guess."
            ),
        )



    async def _test_same_token_swap(self, url, method, base_body, loc):
        candidates = self._build_candidates(loc)
        for candidate in candidates:
            test_url = self._substitute(url, loc, candidate)
            if test_url == url:
                continue
            try:
                status2, _, body2, _ = await self._request(method, test_url)
            except Exception as e:
                if self._config.verbose:
                    print(f"[!] TenantBOLAScanner swap probe on {test_url}: {e}")
                continue
            if status2 == 0 or status2 not in (200, 201):
                continue
            if not self._looks_ok(body2, status2):
                continue
            if not self._differs_meaningfully(base_body, body2):
                continue  

            return self._build(
                test_url, method, loc,
                title=f"Cross-Tenant BOLA — {loc['keyword']} ID Swap Returns Different Org's Data",
                severity=Severity.HIGH, confidence=68,
                technique="same_token_swap",
                description=(
                    f"Using the same authenticated token, swapping the "
                    f"`{loc['keyword']}` identifier from `{loc['value']}` to "
                    f"`{candidate}` in `{url}` returned a distinct, successful "
                    f"response — not a 404/error and not the original account's "
                    f"own data being echoed back. This suggests the backend "
                    f"trusts the `{loc['keyword']}` value from the request "
                    f"instead of verifying the caller's actual membership."
                ),
                recommendation=(
                    f"Verify server-side that the authenticated user belongs to "
                    f"the `{loc['keyword']}` being requested; do not trust a "
                    f"client-supplied scoping identifier."
                ),
                evidence=(
                    f"{method} {url} (orig `{loc['value']}`) vs {method} {test_url} "
                    f"(swapped `{candidate}`) → both HTTP {status2}, responses "
                    f"differ meaningfully (not the same data, not an error page)."
                ),
                cwe="CWE-863", cvss=7.1,
                confirmed_note=(
                    "Single-account test — no independent second identity "
                    "confirmed this; verify manually that this genuinely "
                    "crosses a tenant boundary rather than a multi-org "
                    "membership your own account legitimately has."
                ),
            )
        return None



    def _find_tenant_locations(self, url: str) -> list[dict]:
        locations = []
        parsed = urlparse(url)
        segments = parsed.path.strip("/").split("/")

        for i, seg in enumerate(segments):
            seg_l = seg.lower()
            is_soft = seg_l in _TENANT_PATH_KEYWORDS_SOFT
            if (seg_l in _TENANT_PATH_KEYWORDS or is_soft) and i + 1 < len(segments):
                value = segments[i + 1]
                if _detect_id_type(value) != "none" or re.match(r"^[a-z0-9\-]{2,40}$", value, re.I):
                    locations.append({
                        "type": "path", "index": i + 1, "keyword": seg_l,
                        "value": value, "signature": f"path:{seg_l}",
                    })

        for key, value in parse_qsl(parsed.query):
            if _TENANT_QUERY_KEY_RE.match(key):
                locations.append({
                    "type": "query", "key": key, "keyword": key,
                    "value": value, "signature": f"query:{key.lower()}",
                })



        locations.sort(key=lambda l: l["keyword"] in _TENANT_PATH_KEYWORDS_SOFT)
        return locations

    def _harvest_ids(self, body: str) -> None:
        if not body:
            return
        for _, val in _TENANT_HARVEST_RE.findall(body[:20000]):
            self._harvested_ids.add(val)

    def _build_candidates(self, loc: dict) -> list[str]:
        value = loc["value"]
        candidates: list[str] = []

        others = [h for h in self._harvested_ids if h != value]
        candidates.extend(others[:2])

        if _detect_id_type(value) == "numeric":
            try:
                nearby = _build_numeric_range(int(value), max_range=4)
                candidates.extend(nearby[:2])
            except ValueError:
                pass
            if value != "1":
                candidates.append("1")


        seen = set()
        deduped = []
        for c in candidates:
            if c not in seen and c != value:
                seen.add(c)
                deduped.append(c)
        return deduped[:4]

    def _substitute(self, url: str, loc: dict, candidate: str) -> str:
        parsed = urlparse(url)
        if loc["type"] == "path":
            segments = parsed.path.strip("/").split("/")
            segments[loc["index"]] = candidate
            new_path = "/" + "/".join(segments)
            return urlunparse(parsed._replace(path=new_path))
        else:
            q = parse_qsl(parsed.query)
            new_q = [(k, candidate if k == loc["key"] else v) for k, v in q]
            return urlunparse(parsed._replace(query=urlencode(new_q)))

    def _normalise_path(self, url: str) -> str:
        parsed = urlparse(url)
        segments = parsed.path.strip("/").split("/")
        norm = ["{id}" if _detect_id_type(s) != "none" else s for s in segments]
        return parsed.netloc + "/" + "/".join(norm)

    def _differs_meaningfully(self, base: str, other: str, threshold: float = 0.08) -> bool:
        if not base or not other:
            return bool(other and not base)








        if _HAS_SEMANTIC_DIFF:
            try:
                sim = SemanticDiff.compare(base[:4000], other[:4000]).semantic_similarity
                return (1.0 - sim) > threshold
            except Exception:
                pass
        sim = difflib.SequenceMatcher(None, base[:4000], other[:4000]).ratio()
        return (1.0 - sim) > threshold

    def _looks_ok(self, body: str, status: int) -> bool:
        if self._resp_ok:
            return self._resp_ok(body, status)
        if not body:
            return False
        lower = body.lower()
        return status in (200, 201) and not any(
            s in lower for s in ("unauthorized", "forbidden", "not found", "error")
        )



    def _build(
        self, url, method, loc, title, severity, confidence, technique,
        description, recommendation, evidence, cwe, cvss, confirmed_note,
    ) -> Finding:
        host = urlparse(url).netloc
        path = urlparse(url).path or "/"

        curl = f'curl -sk -X {method} "{url}" -H "Authorization: Bearer <TOKEN>"'
        python_script = (
            "import requests\n\n"
            f'url = "{url}"\n'
            f'r = requests.request("{method}", url, headers={{"Authorization": "Bearer <TOKEN>"}})\n'
            "print(r.status_code)\n"
            "print(r.text[:500])\n"
        )
        burp = f"{method} {path} HTTP/1.1\nHost: {host}\nAuthorization: Bearer <TOKEN>\nConnection: close\n\n"

        poc = ProofOfConcept(
            summary=f"{title} — {confirmed_note}",
            curl_command=curl,
            python_script=python_script,
            burp_request=burp,
            expected_result=evidence,
            steps=[
                f"Send the request above to `{url}`.",
                "Confirm the response contains data belonging to an "
                "organization/tenant the requesting account is not a "
                "member of.",
                confirmed_note,
            ],
        )

        finding = Finding(
            title=title,
            severity=severity,
            category="Business Logic — Cross-Tenant BOLA",
            description=description,
            request={"method": method, "url": url},
            response_summary=f"Tenant-scoped resource accessible outside membership ({technique})",
            evidence=evidence,
            recommendation=recommendation,
            cwe=cwe, cvss=cvss,
            owasp="API1:2023 Broken Object Level Authorization",
            confirmed=(technique == "cross_account"),
            confidence=confidence,
            confidence_reasons=[technique, confirmed_note],
            endpoint=url,
            parameter=loc["keyword"],
        )
        finding.poc = poc
        return finding
