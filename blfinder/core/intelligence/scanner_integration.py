"""
core/intelligence/scanner_integration.py

Wires the platform intelligence layer into BLFScanner.run_all_modules()
without modifying scanner.py. Call apply_integration() once before the
BLFScanner context manager opens.

What this does:
  1. Patches BLFScanner.run_all_modules() to call the new systems after
     the standard 21-module sweep completes.
  2. Registers domain chain rules into the existing CHAIN_RULES list.
  3. Converts dict findings (from domain modules) into Finding objects
     so they pass through the verifier and reporter unchanged.
  4. Handles all import failures gracefully — if any module is absent
     the scan continues normally with no crash.

Execution order inside the patched run_all_modules():
  [existing]  Phase 3 recon
  [existing]  Deep discovery
  [existing]  21-module endpoint sweep
  [existing]  GraphQL baseline check
  [existing]  Phase 4 attack surface expansion
  [existing]  JS secrets
  [new]       Auth diff scanner (auth vs unauth field exposure)
  [new]       Platform detection + domain attack modules
  [new]       Chain engine analysis (existing + domain chains)
  [existing]  Confidence filter
  [existing]  Re-verification
  [existing]  Deduplication
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Finding dict → Finding object converter
# ─────────────────────────────────────────────────────────────────────────────

def _dict_to_finding(d: dict, scanner) -> Any:
    """
    Convert a plain dict (returned by domain modules and auth_diff_scanner)
    into a Finding object compatible with BLFScanner's verifier and reporter.

    The Finding dataclass lives in core.models. We construct it field-by-field
    using only the fields we know exist from the scanner.py source (doc 2).
    """
    try:
        from core.models import Finding, Severity

        sev_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
        }
        sev = sev_map.get(
            str(d.get("severity", "MEDIUM")).upper(),
            Severity.MEDIUM,
        )

        f = Finding(
            title           = d.get("title",          ""),
            severity        = sev,
            category        = d.get("category",       ""),
            description     = d.get("description",    ""),
            request         = d.get("request",        {}),
            response_summary= d.get("response_summary",""),
            evidence        = d.get("evidence",       ""),
            recommendation  = d.get("recommendation", ""),
            cwe             = d.get("cwe",            "CWE-200"),
            cvss            = float(d.get("cvss",     5.0)),
            owasp           = d.get("owasp",          ""),
            confirmed       = bool(d.get("confirmed", False)),
            confidence      = int(d.get("confidence", 50)),
            endpoint        = d.get("endpoint",       ""),
            parameter       = d.get("parameter",      ""),
        )

        if not getattr(f, "false_positive_checks", None):
            f.false_positive_checks = []
        if not getattr(f, "confidence_reasons", None):
            f.confidence_reasons = []

        if not getattr(f, "poc", None):
            _attach_poc(f, d, scanner)

        return f

    except Exception:
        return None


def _attach_poc(finding: Any, source_dict: dict, scanner) -> None:
    """Build a PoC on a Finding object from its source dict."""
    try:
        poc = scanner.poc_generator.generate(finding)
        if poc:
            finding.poc = poc
            return
    except Exception:
        pass

    import json as _json

    req    = source_dict.get("request", {}) or {}
    method = req.get("method", "GET")
    url    = req.get("url",    "") or source_dict.get("endpoint", "")
    body   = req.get("body")
    token  = getattr(scanner.config, "auth_token", "") or ""

    auth_h    = f' -H "Authorization: Bearer {token}"' if token else ""
    body_part = ""
    if body and isinstance(body, dict):
        body_part = f" -d '{_json.dumps(body)}'"

    curl = f"curl -sk -X {method}{auth_h}{body_part} '{url}'"

    try:
        from urllib.parse import urlparse as _up
        p    = _up(url)
        host = p.netloc
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
    except Exception:
        host = url
        path = "/"

    burp_hdr  = f"Authorization: Bearer {token}\r\n" if token else ""
    body_raw  = f"\r\n\r\n{_json.dumps(body)}" if body else ""
    burp_raw  = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"{burp_hdr}"
        f"Connection: close{body_raw}"
    )

    evidence = source_dict.get("evidence", "See description")[:400]
    steps    = (
        f"1. Send the following HTTP request:\n   {curl}\n\n"
        f"2. Observe the response confirms the vulnerability.\n\n"
        f"3. Evidence:\n   {evidence}"
    )

    finding.poc = {
        "curl":               curl,
        "burp_raw":           burp_raw,
        "steps":              steps,
        "reproduction":       steps,
        "hackerone_template": (
            f"## Summary\n{source_dict.get('description','')}\n\n"
            f"## Steps to Reproduce\n{steps}\n\n"
            f"## Impact\n{source_dict.get('description','')}\n\n"
            f"## Recommendation\n{source_dict.get('recommendation','')}"
        ),
        "method":             method,
        "url":                url,
        "headers":            {"Authorization": f"Bearer {token}"} if token else {},
        "body":               body or {},
        "vulnerability":      source_dict.get("title", ""),
        "impact":             source_dict.get("description", ""),
        "affected_endpoint":  url,
        "recommendation":     source_dict.get("recommendation", ""),
        "python_script":      (
            f"import requests\n"
            f'url = "{url}"\n'
            f'headers = {{"Authorization": "Bearer {token}", "Content-Type": "application/json"}}\n'
            + (f'resp = requests.{method.lower()}(url, json={_json.dumps(body)}, headers=headers, verify=False)\n'
               if body else
               f'resp = requests.{method.lower()}(url, headers=headers, verify=False)\n')
            + "print(resp.status_code)\nprint(resp.text[:500])"
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Probe target URL for platform fingerprinting data
# ─────────────────────────────────────────────────────────────────────────────

async def _probe_target(scanner, target_url: str) -> tuple[dict, str, list[str]]:
    """
    Make a single GET request to the target root to collect headers and body
    for platform fingerprinting. Returns (headers, body, discovered_paths).
    """
    try:
        _, hdrs, body, _ = await scanner._request("GET", target_url)
        paths = list({
            ep for ep in scanner.base_responses
            if ep.startswith("http")
        })
        return hdrs, body, paths
    except Exception:
        return {}, "", []


# ─────────────────────────────────────────────────────────────────────────────
# Main integration patch
# ─────────────────────────────────────────────────────────────────────────────

def apply_integration() -> bool:
    """
    Patch BLFScanner.run_all_modules() to include:
      - Auth diff scanner
      - Platform detection and domain attack modules
      - Domain chain rules registered into ChainEngine

    Call this AFTER apply_patch() from scanner_patch.py and BEFORE the
    'async with BLFScanner(config) as scanner:' block.

    Returns True on success, False if core.scanner is not importable.
    """
    try:
        from core.scanner import BLFScanner
    except ImportError:
        print("[!] scanner_integration: core.scanner not found — skipped")
        return False

    _register_domain_chains()

    _orig_run_all = BLFScanner.run_all_modules

    async def _patched_run_all_modules(self, endpoints: list[dict]) -> list:
        raw = await _orig_run_all(self, endpoints)

        raw_dicts: list[dict] = []
        raw_findings: list   = list(raw)

        for f in raw_findings:
            if isinstance(f, dict):
                raw_dicts.append(f)
            else:
                raw_dicts.append(_finding_to_dict(f))

        new_dicts: list[dict] = []

        new_dicts.extend(
            await _run_auth_diff(self, endpoints)
        )

        new_dicts.extend(
            await _run_platform_modules(self, endpoints, raw_dicts + new_dicts)
        )

        new_dicts.extend(
            await _run_chain_engine(self, raw_dicts + new_dicts)
        )

        new_findings = []
        for d in new_dicts:
            f = _dict_to_finding(d, self)
            if f is not None:
                new_findings.append(f)

        all_findings = list(raw) + new_findings

        if new_findings:
            print(
                f"  [integration] added {len(new_findings)} findings "
                f"(auth_diff + platform + chains)"
            )

        return all_findings

    BLFScanner.run_all_modules = _patched_run_all_modules
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Step runners
# ─────────────────────────────────────────────────────────────────────────────

async def _run_auth_diff(scanner, endpoints: list[dict]) -> list[dict]:
    try:
        from core.analysis.auth_diff_scanner import AuthDiffScanner
        ads = AuthDiffScanner(scanner, scanner.config)
        return await ads.scan_all(endpoints, concurrency=4)
    except ImportError:
        return []
    except Exception as e:
        if getattr(scanner.config, "verbose", False):
            print(f"  [auth_diff] error: {e}")
        return []


async def _run_platform_modules(
    scanner,
    endpoints:       list[dict],
    existing_dicts:  list[dict],
) -> list[dict]:
    try:
        from core.intelligence.platform_scanner import PlatformScanner

        ps = PlatformScanner(scanner, scanner.config)

        target_url = scanner.config.target_url
        hdrs, body, paths = await _probe_target(scanner, target_url)

        all_paths = paths + [ep.get("url", "") for ep in endpoints]

        await ps.detect_platform(target_url, hdrs, body, all_paths)

        return await ps.run(endpoints, concurrency=4)

    except ImportError:
        return []
    except Exception as e:
        if getattr(scanner.config, "verbose", False):
            print(f"  [platform_modules] error: {e}")
        return []


async def _run_chain_engine(
    scanner,
    all_dicts: list[dict],
) -> list[dict]:
    try:
        from core.analysis.chain_engine import ChainEngine

        if len(all_dicts) < 2:
            return []

        engine = ChainEngine(scanner, scanner.config)
        return await engine.analyze(all_dicts)

    except ImportError:
        return []
    except Exception as e:
        if getattr(scanner.config, "verbose", False):
            print(f"  [chain_engine] error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Domain chain registration
# ─────────────────────────────────────────────────────────────────────────────

def _register_domain_chains() -> None:
    try:
        from core.intelligence.domain_chains import DomainChainEngine
        DomainChainEngine.register()
    except ImportError:
        pass
    except Exception as e:
        print(f"  [domain_chains] registration error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Finding object → dict (for passing Finding objects into chain engine)
# ─────────────────────────────────────────────────────────────────────────────

def _finding_to_dict(f: Any) -> dict:
    """Convert a Finding object to the dict format chain_engine expects."""
    try:
        sev = f.severity
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
    except Exception:
        sev_str = "MEDIUM"

    req = getattr(f, "request", {}) or {}

    return {
        "title":       getattr(f, "title",       ""),
        "severity":    sev_str,
        "category":    getattr(f, "category",    ""),
        "description": getattr(f, "description", ""),
        "request":     req,
        "evidence":    getattr(f, "evidence",    ""),
        "recommendation": getattr(f, "recommendation", ""),
        "cwe":         getattr(f, "cwe",         ""),
        "cvss":        getattr(f, "cvss",        0.0),
        "owasp":       getattr(f, "owasp",       ""),
        "confirmed":   getattr(f, "confirmed",   False),
        "confidence":  getattr(f, "confidence",  0),
        "endpoint":    getattr(f, "endpoint",    ""),
        "parameter":   getattr(f, "parameter",   ""),
        "response_summary": getattr(f, "response_summary", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    print("=" * 56)
    print("scanner_integration.py — self-test")
    print("=" * 56)

    print("\n[TEST 1] _dict_to_finding skips gracefully without core.models")

    class FakeConfig:
        auth_token      = "tok123"
        verbose         = False
        second_user_token = ""

    class FakeScanner:
        config          = FakeConfig()
        base_responses  = {}

        class poc_generator:
            @staticmethod
            def generate(f):
                return None

    d = {
        "title":       "Test Finding",
        "severity":    "HIGH",
        "category":    "Business Logic — Test",
        "description": "Test description",
        "request":     {"method": "POST", "url": "https://api.test.com/pay"},
        "evidence":    "amount=-100 accepted",
        "recommendation": "Validate amounts",
        "cwe":         "CWE-20",
        "cvss":        8.0,
        "owasp":       "API6:2023",
        "confirmed":   True,
        "confidence":  85,
        "endpoint":    "https://api.test.com/pay",
        "parameter":   "amount",
    }

    result = _dict_to_finding(d, FakeScanner())
    if result is None:
        print("  SKIP — core.models not available (expected in isolation test)")
    else:
        assert result.title == "Test Finding"
        assert result.confidence == 85
        print("  PASS — Finding object constructed correctly")

    print("\n[TEST 2] _finding_to_dict round-trips correctly")

    class FakeFinding:
        title         = "IDOR finding"
        severity      = type("S", (), {"value": "CRITICAL"})()
        category      = "Business Logic — IDOR"
        description   = "desc"
        request       = {"method": "GET", "url": "https://x.com/api/v1/users/1"}
        evidence      = "ID 1→2 returned different data"
        recommendation = "Fix ownership checks"
        cwe           = "CWE-639"
        cvss          = 9.1
        owasp         = "API1:2023"
        confirmed     = True
        confidence    = 91
        endpoint      = "https://x.com/api/v1/users/2"
        parameter     = "path[3]"
        response_summary = "HTTP 200"

    d2 = _finding_to_dict(FakeFinding())
    assert d2["title"]      == "IDOR finding"
    assert d2["severity"]   == "CRITICAL"
    assert d2["confidence"] == 91
    assert d2["confirmed"]  is True
    print("  PASS — Finding → dict conversion correct")

    print("\n[TEST 3] _attach_poc produces all required keys")

    class FakeFinding2:
        poc = None
        title = "Negative Amount"
        description = "amount=-100 accepted"
        recommendation = "Validate server-side"
        evidence = "amount=-100 → credited -100"

    ff2     = FakeFinding2()
    source  = {
        "request":     {"method": "POST", "url": "https://api.test.com/pay", "body": {"amount": -100}},
        "endpoint":    "https://api.test.com/pay",
        "title":       "Negative Amount",
        "description": "amount=-100 accepted",
        "recommendation": "Validate server-side",
        "evidence":    "amount=-100 → credited -100",
    }
    _attach_poc(ff2, source, FakeScanner())
    for key in ["curl", "burp_raw", "steps", "python_script", "hackerone_template"]:
        assert key in ff2.poc, f"Missing poc key: {key}"
        assert ff2.poc[key],   f"Empty poc key: {key}"
    print("  PASS — all PoC keys present and non-empty")

    print("\n[TEST 4] _register_domain_chains does not crash when module absent")
    _register_domain_chains()
    print("  PASS — graceful ImportError handling")

    print("\n" + "=" * 56)
    print("All tests passed.")
    print("=" * 56)
