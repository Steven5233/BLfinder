"""
BLFinder Phase 5 — core/integrations/burp_importer.py
Traffic Importer — Burp Suite / HAR / mitmproxy

Eliminates the #1 workflow friction point: building endpoints.json manually.
Browse the app in Burp Suite, export, import, scan.

Supported formats:
  - Burp Suite XML export (right-click → Save items → XML)
  - Burp Suite JSON export
  - Browser HAR (DevTools → Network tab → Export HAR)
  - mitmproxy flows file (mitmdump -w flows.mitm)

All formats produce the same output: list[dict] compatible with
the existing endpoints.json format used by BLFinder.

Path pattern detection:
  /api/orders/123  +  /api/orders/456  →  /api/orders/{id}
  Deduplicates similar paths to avoid redundant testing.

FP reduction:
  - Filters static assets (JS, CSS, images, fonts)
  - Filters non-API content types
  - Only includes requests with JSON bodies or API-like paths
  - Deduplicates by (method, path_pattern) — not full URL
"""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs


# ── Static asset filter ───────────────────────────────────────────────────────

_SKIP_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".pdf", ".zip", ".gz", ".tar",
}

_SKIP_CONTENT_TYPES = {
    "text/html", "text/css", "text/javascript",
    "application/javascript", "image/", "font/",
    "audio/", "video/",
}

_API_PATH_PATTERNS = [
    r"/api/", r"/v\d+/", r"/graphql", r"/rest/",
    r"/service/", r"/gateway/", r"/rpc/",
]

# Regex to detect numeric IDs in URL paths
_NUMERIC_ID_RE  = re.compile(r'/(\d{1,12})(?=/|$)')
_UUID_ID_RE     = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
    re.I,
)
_MONGO_ID_RE    = re.compile(r'/([a-f0-9]{24})(?=/|$)', re.I)
_HASH_ID_RE     = re.compile(r'/([a-zA-Z0-9_\-]{20,64})(?=/|$)')


@dataclass
class RawRequest:
    """A single HTTP request parsed from any traffic format."""
    method:       str
    url:          str
    path:         str
    host:         str
    headers:      dict
    body:         str | None
    body_parsed:  dict | list | None
    content_type: str
    source:       str           # "burp_xml" | "burp_json" | "har" | "mitmproxy"
    is_api:       bool = False
    path_pattern: str = ""      # /api/orders/{id} — after normalisation


@dataclass
class ImportResult:
    """Result of importing a traffic file."""
    source_file:   str
    source_format: str
    total_parsed:  int = 0
    total_kept:    int = 0
    total_skipped: int = 0
    endpoints:     list[dict] = field(default_factory=list)
    raw_requests:  list[RawRequest] = field(default_factory=list)
    skipped_urls:  list[str] = field(default_factory=list)
    errors:        list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Imported {self.total_kept} endpoints from {self.source_file} "
            f"({self.source_format}). "
            f"Skipped {self.total_skipped} static/irrelevant requests."
        )


class TrafficImporter:
    """
    Converts Burp Suite / HAR / mitmproxy traffic into BLFinder endpoints.

    Usage:
        importer  = TrafficImporter(verbose=True)

        # From Burp XML
        result = importer.import_file("burp_export.xml")

        # From HAR
        result = importer.import_file("requests.har")

        # Filter to specific paths
        result = importer.import_file(
            "burp_export.xml",
            url_filter=r"/api/",
        )

        # Save to disk
        importer.save(result.endpoints, "endpoints.json")

        # Use in scanner
        scanner.run_all_modules(result.endpoints)
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    # ── Public API ────────────────────────────────────────────────────────────

    def import_file(
        self,
        path:         str,
        url_filter:   str | None = None,
        api_only:     bool = True,
        deduplicate:  bool = True,
    ) -> ImportResult:
        """
        Auto-detect format and import a traffic file.

        Args:
            path:        Path to Burp XML, Burp JSON, HAR, or mitmproxy file
            url_filter:  Optional regex — only include matching URLs
            api_only:    If True, skip non-API requests (recommended)
            deduplicate: If True, merge duplicate path patterns

        Returns:
            ImportResult with endpoints list ready for BLFinder
        """
        fmt = self._detect_format(path)
        if self.verbose:
            print(f"[*] Importing {fmt} from {path}")

        if fmt == "burp_xml":
            result = self._import_burp_xml(path)
        elif fmt == "burp_json":
            result = self._import_burp_json(path)
        elif fmt == "har":
            result = self._import_har(path)
        elif fmt == "mitmproxy":
            result = self._import_mitmproxy(path)
        else:
            result = ImportResult(
                source_file=path,
                source_format="unknown",
            )
            result.errors.append(f"Unknown file format: {path}")
            return result

        # Filter
        if url_filter:
            pat = re.compile(url_filter, re.I)
            kept = [r for r in result.raw_requests if pat.search(r.url)]
            skipped = len(result.raw_requests) - len(kept)
            result.raw_requests = kept
            result.total_skipped += skipped

        if api_only:
            kept = [r for r in result.raw_requests if r.is_api]
            result.total_skipped += len(result.raw_requests) - len(kept)
            result.raw_requests = kept

        # Normalise and build endpoints
        endpoints = self._normalise(result.raw_requests)

        # Deduplicate
        if deduplicate:
            endpoints = self._deduplicate(endpoints)

        result.endpoints     = endpoints
        result.total_kept    = len(endpoints)
        result.total_skipped = result.total_parsed - result.total_kept

        if self.verbose:
            print(f"  [+] {result.summary()}")

        return result

    def save(self, endpoints: list[dict], output_path: str):
        """Save endpoints to a JSON file compatible with BLFinder."""
        with open(output_path, "w") as fh:
            json.dump(endpoints, fh, indent=2)
        if self.verbose:
            print(f"  [+] Saved {len(endpoints)} endpoints → {output_path}")

    # ── Format detection ──────────────────────────────────────────────────────

    def _detect_format(self, path: str) -> str:
        path_lower = path.lower()
        if path_lower.endswith(".xml"):
            return "burp_xml"
        if path_lower.endswith(".har"):
            return "har"
        if path_lower.endswith((".mitm", ".flows", ".mitmproxy")):
            return "mitmproxy"
        if path_lower.endswith(".json"):
            # Peek inside to distinguish Burp JSON from HAR JSON
            try:
                with open(path) as f:
                    first = f.read(200).strip()
                if '"log"' in first and '"entries"' in first:
                    return "har"
                return "burp_json"
            except Exception:
                return "burp_json"
        # Try XML peek
        try:
            with open(path) as f:
                first = f.read(100).strip()
            if first.startswith("<"):
                return "burp_xml"
        except Exception:
            pass
        return "unknown"

    # ── Burp Suite XML ────────────────────────────────────────────────────────

    def _import_burp_xml(self, path: str) -> ImportResult:
        """
        Parse Burp Suite XML export.
        Format: <items><item><url/><method/><request base64="true"/></item></items>
        """
        result = ImportResult(source_file=path, source_format="burp_xml")
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            result.errors.append(f"XML parse error: {e}")
            return result

        items = root.findall(".//item")
        for item in items:
            result.total_parsed += 1
            try:
                raw = self._parse_burp_xml_item(item)
                if raw:
                    result.raw_requests.append(raw)
                else:
                    result.skipped_urls.append(
                        item.findtext("url") or "unknown"
                    )
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Burp XML item error: {e}")

        return result

    def _parse_burp_xml_item(self, item: ET.Element) -> RawRequest | None:
        url    = item.findtext("url") or ""
        method = (item.findtext("method") or "GET").upper()

        # Decode base64 request body if present
        req_el   = item.find("request")
        raw_body = ""
        headers  = {}
        body_str = None

        if req_el is not None:
            raw_req = req_el.text or ""
            is_b64  = req_el.get("base64", "false").lower() == "true"
            if is_b64:
                try:
                    raw_req = base64.b64decode(raw_req).decode("utf-8", errors="replace")
                except Exception:
                    raw_req = ""

            # Parse raw HTTP request
            lines = raw_req.split("\n")
            header_done = False
            body_lines  = []
            for line in lines[1:]:  # Skip request line
                line_s = line.rstrip("\r")
                if not header_done:
                    if line_s == "":
                        header_done = True
                        continue
                    if ":" in line_s:
                        k, v = line_s.split(":", 1)
                        headers[k.strip()] = v.strip()
                else:
                    body_lines.append(line_s)
            raw_body = "\n".join(body_lines).strip()

        return self._build_raw_request(
            method, url, headers, raw_body, "burp_xml"
        )

    # ── Burp Suite JSON ───────────────────────────────────────────────────────

    def _import_burp_json(self, path: str) -> ImportResult:
        """Parse Burp Suite JSON export format."""
        result = ImportResult(source_file=path, source_format="burp_json")
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            result.errors.append(f"JSON parse error: {e}")
            return result

        # Burp JSON can be a list of items or wrapped
        items = data if isinstance(data, list) else data.get("items", [])
        for item in items:
            result.total_parsed += 1
            try:
                url    = item.get("url", "")
                method = item.get("method", "GET").upper()
                hdrs   = {}
                for h in item.get("requestHeaders", []):
                    if isinstance(h, dict):
                        hdrs[h.get("name", "")] = h.get("value", "")

                body_raw = item.get("requestBody", "") or ""
                if isinstance(body_raw, dict):
                    body_raw = json.dumps(body_raw)

                raw = self._build_raw_request(method, url, hdrs, body_raw, "burp_json")
                if raw:
                    result.raw_requests.append(raw)
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Burp JSON item error: {e}")

        return result

    # ── HAR ───────────────────────────────────────────────────────────────────

    def _import_har(self, path: str) -> ImportResult:
        """
        Parse browser HAR file.
        Filters to XHR/fetch requests only — skips static assets.
        """
        result = ImportResult(source_file=path, source_format="har")
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            result.errors.append(f"HAR parse error: {e}")
            return result

        entries = data.get("log", {}).get("entries", [])
        for entry in entries:
            result.total_parsed += 1
            try:
                req    = entry.get("request", {})
                method = req.get("method", "GET").upper()
                url    = req.get("url", "")

                # Filter: only XHR/fetch, skip static
                initiator = entry.get("_initiator", {})
                resp_type = entry.get("_resourceType", "")
                if resp_type in ("stylesheet", "image", "font", "media", "script"):
                    result.skipped_urls.append(url)
                    continue

                # Extract headers
                hdrs = {}
                for h in req.get("headers", []):
                    if isinstance(h, dict):
                        hdrs[h.get("name", "")] = h.get("value", "")

                # Extract body
                post_data = req.get("postData", {}) or {}
                body_raw  = post_data.get("text", "") or ""
                if not body_raw and post_data.get("params"):
                    body_raw = urlencode({
                        p["name"]: p.get("value", "")
                        for p in post_data["params"]
                    })

                # Extract query params
                params = {}
                for qp in req.get("queryString", []):
                    if isinstance(qp, dict):
                        params[qp.get("name", "")] = qp.get("value", "")

                raw = self._build_raw_request(
                    method, url, hdrs, body_raw, "har", params
                )
                if raw:
                    result.raw_requests.append(raw)
                else:
                    result.skipped_urls.append(url)

            except Exception as e:
                if self.verbose:
                    print(f"  [!] HAR entry error: {e}")

        return result

    # ── mitmproxy ─────────────────────────────────────────────────────────────

    def _import_mitmproxy(self, path: str) -> ImportResult:
        """
        Parse mitmproxy flows file.
        mitmproxy stores flows as a stream of JSON objects (one per line)
        or in its binary format. We handle the JSON dump format.
        Usage: mitmdump -r flows.mitm --flow-detail 3 > flows.json
        Or:    mitmproxy --set save_stream_file=flows.mitm
        """
        result = ImportResult(source_file=path, source_format="mitmproxy")
        try:
            with open(path) as f:
                content = f.read().strip()
        except Exception as e:
            result.errors.append(f"mitmproxy file read error: {e}")
            return result

        # Try parsing as JSON array first
        flows = []
        try:
            parsed = json.loads(content)
            flows  = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            # Try NDJSON (newline-delimited JSON)
            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    flows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for flow in flows:
            result.total_parsed += 1
            try:
                req_data = flow.get("request", {})
                method   = req_data.get("method", "GET").upper()
                scheme   = req_data.get("scheme", "https")
                host     = req_data.get("host", "")
                port     = req_data.get("port", 443)
                path_raw = req_data.get("path", "/")
                url      = f"{scheme}://{host}{path_raw}"

                # Headers
                hdrs = {}
                for k, v in (req_data.get("headers", {}) or {}).items():
                    hdrs[k] = v

                # Body
                body_raw = req_data.get("content", "") or ""
                if isinstance(body_raw, list):
                    try:
                        body_raw = bytes(body_raw).decode("utf-8", errors="replace")
                    except Exception:
                        body_raw = ""

                raw = self._build_raw_request(method, url, hdrs, body_raw, "mitmproxy")
                if raw:
                    result.raw_requests.append(raw)
                else:
                    result.skipped_urls.append(url)

            except Exception as e:
                if self.verbose:
                    print(f"  [!] mitmproxy flow error: {e}")

        return result

    # ── Normalisation ─────────────────────────────────────────────────────────

    def _build_raw_request(
        self,
        method:   str,
        url:      str,
        headers:  dict,
        body_raw: str,
        source:   str,
        params:   dict | None = None,
    ) -> RawRequest | None:
        """Build a RawRequest, parsing body and determining if it's an API call."""
        if not url or not url.startswith("http"):
            return None

        parsed = urlparse(url)
        path   = parsed.path

        # Skip static assets
        if any(path.lower().endswith(ext) for ext in _SKIP_EXTENSIONS):
            return None

        # Content-type
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break

        # Skip non-API content types
        if any(bad in ct for bad in _SKIP_CONTENT_TYPES) and "json" not in ct:
            return None

        # Parse body
        body_parsed = None
        if body_raw and body_raw.strip():
            try:
                body_parsed = json.loads(body_raw)
            except (json.JSONDecodeError, ValueError):
                if "=" in body_raw and not body_raw.strip().startswith("{"):
                    # URL-encoded form
                    body_parsed = dict(parse_qs(body_raw, keep_blank_values=True))
                    body_parsed = {
                        k: v[0] if len(v) == 1 else v
                        for k, v in body_parsed.items()
                    }

        # Determine if API request
        is_api = (
            "json" in ct
            or bool(body_parsed)
            or any(re.search(p, path, re.I) for p in _API_PATH_PATTERNS)
            or path.count("/") >= 2
        )

        # Build path pattern (replace IDs with {id})
        path_pattern = _make_path_pattern(path)

        return RawRequest(
            method=method,
            url=url,
            path=path,
            host=parsed.netloc,
            headers=headers,
            body=body_raw if body_raw else None,
            body_parsed=body_parsed,
            content_type=ct,
            source=source,
            is_api=is_api,
            path_pattern=path_pattern,
        )

    def _normalise(self, requests: list[RawRequest]) -> list[dict]:
        """Convert RawRequest objects to BLFinder endpoint format."""
        endpoints = []
        for req in requests:
            # Strip auth headers from the endpoint definition
            clean_headers = {
                k: v for k, v in req.headers.items()
                if k.lower() not in (
                    "authorization", "cookie", "x-api-key", "x-auth-token"
                )
            }
            ep = {
                "url":    req.url,
                "method": req.method,
                "body":   req.body_parsed or {},
                "params": {},
                "_source": req.source,
                "_path_pattern": req.path_pattern,
            }
            endpoints.append(ep)
        return endpoints

    def _deduplicate(self, endpoints: list[dict]) -> list[dict]:
        """
        Merge duplicate endpoints by (method, path_pattern).
        Keeps the richest body (most keys) for each unique pattern.
        """
        seen:   dict[str, dict] = {}
        for ep in endpoints:
            key = f"{ep['method']}:{ep.get('_path_pattern', ep['url'])}"
            if key not in seen:
                seen[key] = ep
            else:
                # Keep the one with more body keys
                existing_keys = len(seen[key].get("body") or {})
                new_keys      = len(ep.get("body") or {})
                if new_keys > existing_keys:
                    seen[key] = ep

        result = list(seen.values())
        if self.verbose:
            print(
                f"  [*] Deduplicated: {len(endpoints)} → {len(result)} unique endpoints"
            )
        return result


# ── Path pattern helpers ──────────────────────────────────────────────────────

def _make_path_pattern(path: str) -> str:
    """Replace ID segments in a path with {id} placeholder."""
    # UUID
    path = _UUID_ID_RE.sub("/{id}", path)
    # Mongo ObjectID (24 hex chars)
    path = _MONGO_ID_RE.sub("/{id}", path)
    # Numeric IDs
    path = _NUMERIC_ID_RE.sub("/{id}", path)
    return path
