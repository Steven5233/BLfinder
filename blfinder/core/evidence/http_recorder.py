"""
BLFinder v3.1 — core/evidence/http_recorder.py
Raw HTTP / Burp Suite Format Recorder

Converts RequestRecord and ResponseRecord objects into:
  1. Burp Suite Repeater raw HTTP format (importable)
  2. Copy-paste curl commands
  3. Python requests snippets
  4. HTTPie commands (Termux-friendly)

The output of this module is what goes directly into HackerOne reports.
"""

from __future__ import annotations

import json
import shlex
from urllib.parse import urlparse

from .capture import RequestRecord, ResponseRecord


class HTTPRecorder:
    """
    Converts request/response objects to raw HTTP formats.
    All methods are static — no state required.
    """



    @staticmethod
    def request_to_burp(req: RequestRecord) -> str:
        """
        Convert a RequestRecord to Burp Suite Repeater raw HTTP format.
        This can be copy-pasted directly into Burp Suite Repeater.
        """
        parsed = urlparse(req.url)
        path   = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{req.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")


        for k, v in req.headers.items():
            if k.lower() != "host":
                lines.append(f"{k}: {v}")


        body_str = _body_to_string(req.body)
        if body_str:
            lines.append(f"Content-Length: {len(body_str.encode())}")
            lines.append("")
            lines.append(body_str)
        else:
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def response_to_burp(resp: ResponseRecord) -> str:
        """
        Convert a ResponseRecord to Burp Suite raw HTTP response format.
        """

        reason = _status_reason(resp.status)
        lines  = [f"HTTP/1.1 {resp.status} {reason}"]

        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")

        lines.append("")
        lines.append(resp.body)
        return "\n".join(lines)

    @staticmethod
    def pair_to_burp(req: RequestRecord, resp: ResponseRecord, label: str = "") -> str:
        """
        Format a complete request+response pair in Burp style.
        """
        sections = []
        if label:
            sections.append(f"{'='*60}")
            sections.append(f"  {label.upper()}")
            sections.append(f"{'='*60}")
        sections.append(">>> REQUEST")
        sections.append(HTTPRecorder.request_to_burp(req))
        sections.append("")
        sections.append("<<< RESPONSE")
        sections.append(HTTPRecorder.response_to_burp(resp))
        return "\n".join(sections)



    @staticmethod
    def request_to_curl(req: RequestRecord, include_comments: bool = True) -> str:
        """
        Convert a RequestRecord to a copy-paste curl command.
        Verified to work on Termux/Android.
        """
        parts = ["curl -sk"]
        parts.append(f"-X {req.method}")
        parts.append(f'"{req.url}"')

        for k, v in req.headers.items():

            if k.lower() in ("content-length", "transfer-encoding", "host"):
                continue

            parts.append(f'-H "{k}: {v}"')

        body_str = _body_to_string(req.body)
        if body_str:

            safe_body = body_str.replace("'", "'\"'\"'")
            parts.append(f"-d '{safe_body}'")


        cmd = " \\\n  ".join(parts)

        if include_comments and req.label:
            comment = f"# {req.label.replace('_', ' ').title()} Request"
            if req.label == "attack":
                comment += " — EXPLOIT"
            cmd = f"{comment}\n{cmd}"

        return cmd

    @staticmethod
    def pair_to_curl(req: RequestRecord, resp: ResponseRecord, label: str = "") -> str:
        """Format request + expected response as a commented curl block."""
        lines = []
        if label:
            lines.append(f"# ── {label.upper()} ──")
        lines.append(HTTPRecorder.request_to_curl(req, include_comments=False))
        lines.append("")
        lines.append(f"# Expected response: HTTP {resp.status}")

        body_preview = resp.body.strip()[:200]
        for line in body_preview.split("\n")[:3]:
            lines.append(f"# {line}")
        return "\n".join(lines)



    @staticmethod
    def request_to_python(req: RequestRecord) -> str:
        """
        Convert a RequestRecord to a standalone Python requests script.
        """
        lines = [
            "#!/usr/bin/env python3",
            '"""BLFinder v3.1 — Auto-generated PoC"""',
            "import requests",
            "import json",
            "",
            "requests.packages.urllib3.disable_warnings()",
            "",
            f'TARGET = "{req.url}"',
            f"HEADERS = {json.dumps(req.headers, indent=4)}",
            "",
        ]

        body_str = _body_to_string(req.body)
        if body_str:
            lines.append(f"BODY = {json.dumps(json.loads(body_str) if _is_json(body_str) else body_str, indent=4)}")
            lines.append("")
            lines.append(
                f'r = requests.request("{req.method}", TARGET, '
                f'json=BODY, headers=HEADERS, verify=False)'
            )
        else:
            lines.append(
                f'r = requests.request("{req.method}", TARGET, '
                f'headers=HEADERS, verify=False)'
            )

        lines += [
            "",
            "print(f'Status: {r.status_code}')",
            "print(f'Response: {r.text[:500]}')",
        ]
        return "\n".join(lines)



    @staticmethod
    def request_to_httpie(req: RequestRecord) -> str:
        """
        Convert a RequestRecord to an HTTPie command.
        HTTPie is more readable than curl and works well on Termux.
        Install: pip install httpie
        """
        parts = [f"http --verify=no {req.method} '{req.url}'"]

        for k, v in req.headers.items():
            if k.lower() in ("content-length", "host"):
                continue
            parts.append(f"'{k}: {v}'")

        body_str = _body_to_string(req.body)
        if body_str and _is_json(body_str):
            try:
                data = json.loads(body_str)
                for k, v in data.items():
                    if isinstance(v, str):
                        parts.append(f"{k}='{v}'")
                    elif isinstance(v, (int, float)):
                        parts.append(f"{k}:={v}")
                    elif isinstance(v, bool):
                        parts.append(f"{k}:={'true' if v else 'false'}")
            except (json.JSONDecodeError, ValueError):
                parts.append(f"<<<'{body_str}'")

        return " \\\n  ".join(parts)



    @staticmethod
    def build_poc_bundle(req: RequestRecord, resp: ResponseRecord) -> dict:
        """
        Build all PoC formats at once.
        Returns a dict with all formats ready for embedding in reports.
        """
        return {
            "burp":    HTTPRecorder.pair_to_burp(req, resp, label=req.label),
            "curl":    HTTPRecorder.request_to_curl(req),
            "python":  HTTPRecorder.request_to_python(req),
            "httpie":  HTTPRecorder.request_to_httpie(req),
        }




def _body_to_string(body: str | dict | list | None) -> str:
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if isinstance(body, (dict, list)):
        return json.dumps(body, separators=(",", ":"))
    return str(body)


def _is_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _status_reason(status: int) -> str:
    reasons = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed",
        429: "Too Many Requests", 500: "Internal Server Error",
        502: "Bad Gateway", 503: "Service Unavailable",
    }
    return reasons.get(status, "Unknown")
