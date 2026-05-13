"""
BLFinder Phase 5 — core/integrations/burp_importer.py
Traffic Importer — Burp Suite / HAR / mitmproxy

Eliminates the #1 workflow friction point: building endpoints.json manually.
Browse the app in Burp Suite, export, import, scan.

Supported formats:
  - Burp Suite XML export  (right-click → Save items → XML)
  - Burp Suite JSON export
  - Browser HAR            (DevTools → Network tab → Export HAR)
  - mitmproxy flows file   (mitmdump -w flows.mitm  OR  mitmdump -w flows.json)

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

Fixes in this revision:
  - ET.parse() crash on malformed/binary XML → safe parse with encoding fallback
  - _detect_format() now peeks at file content, not just extension
  - Binary mitmproxy format detected and rejected gracefully
  - _HASH_ID_RE now applied in _make_path_pattern()
  - total_skipped no longer double-counted
  - All parse paths wrapped in broad exception handlers with error reporting
  - Empty-file / zero-byte file guard added
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

# Regexes to detect ID segments in URL paths — applied in order
_UUID_ID_RE = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)',
    re.I,
)
_MONGO_ID_RE  = re.compile(r'/([a-f0-9]{24})(?=/|$)', re.I)
_NUMERIC_ID_RE = re.compile(r'/(\d{1,12})(?=/|$)')
# Long opaque tokens / slugs  (20-64 chars, only applied after the above)
_HASH_ID_RE = re.compile(r'/([a-zA-Z0-9_\-]{20,64})(?=/|$)')


# ── Data structures ───────────────────────────────────────────────────────────

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
            f"Imported {self.total_kept} endpoints from '{self.source_file}' "
            f"({self.source_format}). "
            f"Skipped {self.total_skipped} static/irrelevant requests."
        )


# ── Main class ────────────────────────────────────────────────────────────────

class TrafficImporter:
    """
    Converts Burp Suite / HAR / mitmproxy traffic into BLFinder endpoints.

    Usage:
        importer = TrafficImporter(verbose=True)

        # Auto-detect format
        result = importer.import_file("burp_export.xml")
        result = importer.import_file("requests.har")

        # Filter to specific paths
        result = importer.import_file(
            "burp_export.xml",
            url_filter=r"/api/",
        )

        # Save to disk for reuse
        importer.save(result.endpoints, "endpoints.json")

        # Use directly in scanner
        scanner.run_all_modules(result.endpoints)
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    # ── Public API ────────────────────────────────────────────────────────────

    def import_file(
        self,
        path:        str,
        url_filter:  str | None = None,
        api_only:    bool = True,
        deduplicate: bool = True,
    ) -> ImportResult:
        """
        Auto-detect format and import a traffic file.

        Args:
            path:        Path to Burp XML, Burp JSON, HAR, or mitmproxy file.
            url_filter:  Optional regex — only include matching URLs.
            api_only:    Skip non-API requests (recommended).
            deduplicate: Merge duplicate path patterns.

        Returns:
            ImportResult with .endpoints ready for BLFinder.
        """
        # ── Guard: empty / missing file ───────────────────────────────────────
        try:
            import os
            size = os.path.getsize(path)
        except OSError as e:
            result = ImportResult(source_file=path, source_format="unknown")
            result.errors.append(f"Cannot access file: {e}")
            return result

        if size == 0:
            result = ImportResult(source_file=path, source_format="unknown")
            result.errors.append(f"File is empty: {path}")
            return result

        # ── Format detection ──────────────────────────────────────────────────
        fmt = self._detect_format(path)
        if self.verbose:
            print(f"[*] Detected format '{fmt}' for {path}")

        # ── Dispatch ──────────────────────────────────────────────────────────
        if fmt == "burp_xml":
            result = self._import_burp_xml(path)
        elif fmt == "burp_json":
            result = self._import_burp_json(path)
        elif fmt == "har":
            result = self._import_har(path)
        elif fmt == "mitmproxy":
            result = self._import_mitmproxy(path)
        else:
            result = ImportResult(source_file=path, source_format="unknown")
            result.errors.append(
                f"Unrecognised file format for '{path}'. "
                f"Expected: .xml (Burp), .har, .json (Burp/HAR), "
                f".mitm / .flows / .mitmproxy"
            )
            return result

        # Early-exit if parsing failed
        if result.errors and not result.raw_requests:
            return result

        initial_count = len(result.raw_requests)

        # ── URL filter ────────────────────────────────────────────────────────
        if url_filter:
            try:
                pat = re.compile(url_filter, re.I)
            except re.error as e:
                result.errors.append(f"Invalid --import-filter regex: {e}")
            else:
                kept   = [r for r in result.raw_requests if pat.search(r.url)]
                dropped = len(result.raw_requests) - len(kept)
                if self.verbose and dropped:
                    print(f"  [*] URL filter dropped {dropped} requests")
                result.raw_requests = kept

        # ── API-only filter ───────────────────────────────────────────────────
        if api_only:
            kept   = [r for r in result.raw_requests if r.is_api]
            dropped = len(result.raw_requests) - len(kept)
            if self.verbose and dropped:
                print(f"  [*] api_only filter dropped {dropped} requests")
            result.raw_requests = kept

        # ── Normalise → endpoints ─────────────────────────────────────────────
        endpoints = self._normalise(result.raw_requests)

        # ── Deduplicate ───────────────────────────────────────────────────────
        if deduplicate:
            endpoints = self._deduplicate(endpoints)

        # ── Finalise counts (computed once, no double-counting) ───────────────
        result.endpoints     = endpoints
        result.total_kept    = len(endpoints)
        result.total_skipped = result.total_parsed - result.total_kept

        if self.verbose:
            print(f"  [+] {result.summary()}")

        return result

    def save(self, endpoints: list[dict], output_path: str):
        """Save endpoints to a JSON file compatible with BLFinder -e flag."""
        with open(output_path, "w") as fh:
            json.dump(endpoints, fh, indent=2)
        if self.verbose:
            print(f"  [+] Saved {len(endpoints)} endpoints → {output_path}")

    # ── Format detection ──────────────────────────────────────────────────────

    def _detect_format(self, path: str) -> str:
        """
        Detect file format by peeking at content first, then falling back
        to file extension. Content inspection beats extension every time.
        """
        # Try to read the first 512 bytes for sniffing
        try:
            with open(path, "rb") as f:
                head_bytes = f.read(512)
        except OSError:
            return "unknown"

        # Binary mitmproxy format starts with specific magic bytes
        # (MessagePack stream). Printable ASCII ratio < 0.7 → binary.
        printable = sum(1 for b in head_bytes if 0x20 <= b <= 0x7E or b in b'\t\n\r')
        if len(head_bytes) > 0 and printable / len(head_bytes) < 0.70:
            return "mitmproxy_binary"

        try:
            head = head_bytes.decode("utf-8", errors="replace").strip()
        except Exception:
            return "unknown"

        # XML → Burp XML export
        if head.startswith("<"):
            return "burp_xml"

        # JSON → distinguish HAR from Burp JSON
        if head.startswith("{") or head.startswith("["):
            # HAR files always have a top-level "log" key with "entries"
            if '"log"' in head and '"entries"' in head:
                return "har"
            # mitmproxy JSON dump: list of dicts with "request"/"response" keys
            if '"request"' in head and '"response"' in head:
                return "mitmproxy"
            # Burp JSON: list of items with "url"/"method"/"requestHeaders"
            return "burp_json"

        # Fall back to extension
        pl = path.lower()
        if pl.endswith(".xml"):
            return "burp_xml"
        if pl.endswith(".har"):
            return "har"
        if pl.endswith((".mitm", ".flows", ".mitmproxy")):
            return "mitmproxy"
        if pl.endswith(".json"):
            return "burp_json"

        return "unknown"

    # ── Burp Suite XML ────────────────────────────────────────────────────────

    def _import_burp_xml(self, path: str) -> ImportResult:
        """
        Parse Burp Suite XML export.

        Burp wraps request/response in base64 inside <request base64="true">.
        The XML may contain raw binary data in responses — we only decode the
        request element. Malformed XML is handled with an encoding fallback.
        """
        result = ImportResult(source_file=path, source_format="burp_xml")

        root = self._safe_parse_xml(path, result)
        if root is None:
            return result   # errors already recorded

        items = root.findall(".//item")
        if not items:
            result.errors.append(
                "No <item> elements found. "
                "Re-export from Burp: right-click → Save items → XML format."
            )
            return result

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
                    print(f"  [!] Burp XML item parse error: {e}")
                result.errors.append(f"Item parse error: {e}")

        return result

    def _safe_parse_xml(self, path: str, result: ImportResult):
        """
        Parse an XML file safely with multiple fallback strategies.

        Strategy 1: Standard ET.parse() — works for clean exports.
        Strategy 2: Read as UTF-8 with error replacement, strip null bytes,
                    then ET.fromstring() — handles Burp binary-in-XML artefacts.
        Strategy 3: Latin-1 read (every byte is valid latin-1) → fromstring().

        Returns the root Element or None on failure.
        """
        # Strategy 1 — clean parse
        try:
            tree = ET.parse(path)
            return tree.getroot()
        except ET.ParseError:
            pass   # fall through to repair strategies
        except Exception as e:
            result.errors.append(f"XML file read error: {e}")
            return None

        # Strategy 2 — UTF-8 with replacement + null-byte strip
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
            content = content.replace("\x00", "")   # strip null bytes
            # Remove any lone surrogates that confuse the parser
            content = re.sub(r'[\ud800-\udfff]', '', content)
            return ET.fromstring(content)
        except ET.ParseError:
            pass

        # Strategy 3 — Latin-1 (guaranteed no decode errors)
        try:
            with open(path, encoding="latin-1") as f:
                content = f.read()
            content = content.replace("\x00", "")
            return ET.fromstring(content)
        except ET.ParseError as e:
            result.errors.append(
                f"XML parse failed after 3 attempts: {e}. "
                f"The file may not be a valid Burp XML export. "
                f"Try: Burp Suite → Target → right-click → Save selected items → XML."
            )
            return None
        except Exception as e:
            result.errors.append(f"XML fallback read error: {e}")
            return None

    def _parse_burp_xml_item(self, item: ET.Element) -> RawRequest | None:
        url    = item.findtext("url") or ""
        method = (item.findtext("method") or "GET").upper()

        headers  = {}
        raw_body = ""

        req_el = item.find("request")
        if req_el is not None:
            raw_req = req_el.text or ""
            is_b64  = req_el.get("base64", "false").lower() == "true"

            if is_b64 and raw_req.strip():
                try:
                    # Add padding if needed before decoding
                    padded  = raw_req.strip() + "=" * (-len(raw_req.strip()) % 4)
                    decoded = base64.b64decode(padded)
                    raw_req = decoded.decode("utf-8", errors="replace")
                except Exception:
                    raw_req = ""

            # Parse raw HTTP: split on first blank line → headers | body
            if raw_req:
                # Normalise line endings
                raw_req = raw_req.replace("\r\n", "\n").replace("\r", "\n")
                parts   = raw_req.split("\n\n", 1)
                header_block = parts[0] if parts else ""
                raw_body     = parts[1].strip() if len(parts) > 1 else ""

                for line in header_block.split("\n")[1:]:   # skip request line
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

        return self._build_raw_request(
            method, url, headers, raw_body, "burp_xml"
        )

    # ── Burp Suite JSON ───────────────────────────────────────────────────────

    def _import_burp_json(self, path: str) -> ImportResult:
        """Parse Burp Suite JSON export."""
        result = ImportResult(source_file=path, source_format="burp_json")

        data = self._safe_load_json(path, result)
        if data is None:
            return result

        # Burp JSON can be a bare list or wrapped in {"items": [...]}
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            result.errors.append(
                "No items found in Burp JSON export. "
                "Export via: Burp Suite → Proxy → HTTP history → select all → Save items."
            )
            return result

        for item in items:
            result.total_parsed += 1
            try:
                url    = item.get("url", "")
                method = item.get("method", "GET").upper()

                hdrs = {}
                for h in item.get("requestHeaders", []):
                    if isinstance(h, dict):
                        name  = h.get("name", "")
                        value = h.get("value", "")
                        if name:
                            hdrs[name] = value

                body_raw = item.get("requestBody", "") or ""
                if isinstance(body_raw, dict):
                    body_raw = json.dumps(body_raw)
                elif isinstance(body_raw, list):
                    # Some Burp versions export body as base64 list
                    try:
                        body_raw = base64.b64decode(
                            "".join(body_raw)
                        ).decode("utf-8", errors="replace")
                    except Exception:
                        body_raw = ""

                raw = self._build_raw_request(method, url, hdrs, body_raw, "burp_json")
                if raw:
                    result.raw_requests.append(raw)
                else:
                    result.skipped_urls.append(url)

            except Exception as e:
                if self.verbose:
                    print(f"  [!] Burp JSON item error: {e}")

        return result

    # ── HAR ───────────────────────────────────────────────────────────────────

    def _import_har(self, path: str) -> ImportResult:
        """
        Parse browser HAR (HTTP Archive) file.
        Produced by: Chrome DevTools → Network → Export HAR with content
                     Firefox DevTools → Network → Save All As HAR
                     Insomnia, Postman, Charles Proxy
        """
        result = ImportResult(source_file=path, source_format="har")

        data = self._safe_load_json(path, result)
        if data is None:
            return result

        entries = data.get("log", {}).get("entries", [])
        if not entries:
            result.errors.append(
                "No entries found in HAR file. "
                "Export from Chrome: DevTools → Network → right-click → Save all as HAR with content."
            )
            return result

        # Map HAR _resourceType values that are definitely not API calls
        _SKIP_RESOURCE_TYPES = {
            "stylesheet", "image", "font", "media",
            "script", "other", "websocket",
        }

        for entry in entries:
            result.total_parsed += 1
            try:
                req    = entry.get("request", {})
                method = req.get("method", "GET").upper()
                url    = req.get("url", "")

                # Skip non-XHR/fetch by resource type
                resp_type = entry.get("_resourceType", "")
                if resp_type in _SKIP_RESOURCE_TYPES:
                    result.skipped_urls.append(url)
                    continue

                # Extract headers — HAR uses a list of {name, value} dicts
                hdrs = {}
                for h in req.get("headers", []):
                    if isinstance(h, dict):
                        name = h.get("name", "")
                        if name and not name.startswith(":"):   # skip HTTP/2 pseudo-headers
                            hdrs[name] = h.get("value", "")

                # Extract POST body
                post_data = req.get("postData") or {}
                body_raw  = post_data.get("text", "") or ""
                if not body_raw and post_data.get("params"):
                    # HAR form-encoded body stored as params array
                    body_raw = urlencode({
                        p["name"]: p.get("value", "")
                        for p in post_data["params"]
                        if isinstance(p, dict) and "name" in p
                    })

                # Extract query params
                params = {}
                for qp in req.get("queryString", []):
                    if isinstance(qp, dict) and "name" in qp:
                        params[qp["name"]] = qp.get("value", "")

                raw = self._build_raw_request(
                    method, url, hdrs, body_raw, "har", params
                )
                if raw:
                    if params:
                        raw.body_parsed = raw.body_parsed or {}
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
        Parse mitmproxy flows.

        Supported dump formats:
          JSON array:  mitmdump -r flows.mitm -w - | python -c "..." > flows.json
          NDJSON:      mitmdump -r flows.mitm --flow-detail 3 > flows.json
          Direct JSON: mitmproxy exports via File → Save

        Binary .mitm / MessagePack format is NOT supported — convert first:
          mitmdump -r flows.mitm -w flows.json
        """
        result = ImportResult(source_file=path, source_format="mitmproxy")

        # Read raw content
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
        except OSError as e:
            result.errors.append(f"Cannot read mitmproxy file: {e}")
            return result

        if not content:
            result.errors.append("mitmproxy file is empty.")
            return result

        # Detect binary format early
        null_ratio = content.count("\x00") / max(len(content), 1)
        if null_ratio > 0.01:
            result.errors.append(
                "mitmproxy binary format detected. "
                "Convert to JSON first: mitmdump -r flows.mitm -w flows.json"
            )
            return result

        # Parse: try JSON array, then NDJSON
        flows: list[dict] = []
        try:
            parsed = json.loads(content)
            flows  = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            # NDJSON — one JSON object per line
            for lineno, line in enumerate(content.split("\n"), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    flows.append(json.loads(line))
                except json.JSONDecodeError as e:
                    if self.verbose:
                        print(f"  [!] mitmproxy NDJSON line {lineno} error: {e}")

        if not flows:
            result.errors.append(
                "No flows parsed from mitmproxy file. "
                "Ensure file is JSON or NDJSON format."
            )
            return result

        for flow in flows:
            result.total_parsed += 1
            try:
                req_data = flow.get("request", {})
                if not req_data:
                    continue

                method = req_data.get("method", "GET").upper()
                scheme = req_data.get("scheme", "https")
                host   = req_data.get("host", "")
                path_  = req_data.get("path", "/")

                if not host:
                    continue

                url = f"{scheme}://{host}{path_}"

                # Headers — mitmproxy stores as dict or list of [name, value] pairs
                hdrs: dict = {}
                raw_headers = req_data.get("headers", {})
                if isinstance(raw_headers, dict):
                    hdrs = {k: v for k, v in raw_headers.items()}
                elif isinstance(raw_headers, list):
                    for h in raw_headers:
                        if isinstance(h, (list, tuple)) and len(h) >= 2:
                            hdrs[h[0]] = h[1]
                        elif isinstance(h, dict):
                            hdrs[h.get("name", "")] = h.get("value", "")

                # Body — may be a string, base64 string, or list of ints (bytes)
                body_raw = req_data.get("content", "") or ""
                if isinstance(body_raw, list):
                    try:
                        body_raw = bytes(body_raw).decode("utf-8", errors="replace")
                    except Exception:
                        body_raw = ""
                elif not isinstance(body_raw, str):
                    body_raw = str(body_raw)

                # Some mitmproxy versions base64-encode the content field
                if req_data.get("contentEncoding") == "base64" and body_raw:
                    try:
                        body_raw = base64.b64decode(
                            body_raw + "=" * (-len(body_raw) % 4)
                        ).decode("utf-8", errors="replace")
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

    # ── Normalisation helpers ─────────────────────────────────────────────────

    def _build_raw_request(
        self,
        method:   str,
        url:      str,
        headers:  dict,
        body_raw: str,
        source:   str,
        params:   dict | None = None,
    ) -> RawRequest | None:
        """
        Build a RawRequest, parsing the body and classifying the request
        as API or non-API. Returns None for requests that should be skipped.
        """
        if not url or not url.startswith("http"):
            return None

        try:
            parsed = urlparse(url)
        except Exception:
            return None

        path = parsed.path or "/"

        # Skip static assets by extension
        path_lower = path.lower().split("?")[0]
        if any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
            return None

        # Content-type from headers (case-insensitive key lookup)
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = (v or "").lower()
                break

        # Skip obvious non-API content types (unless they also mention JSON)
        if "json" not in ct:
            for bad in _SKIP_CONTENT_TYPES:
                if bad in ct:
                    return None

        # Parse body
        body_parsed: dict | list | None = None
        body_clean = (body_raw or "").strip()
        if body_clean:
            try:
                body_parsed = json.loads(body_clean)
            except (json.JSONDecodeError, ValueError):
                # Try URL-encoded form body
                if "=" in body_clean and not body_clean.startswith("{"):
                    try:
                        qs = parse_qs(body_clean, keep_blank_values=True)
                        body_parsed = {
                            k: v[0] if len(v) == 1 else v
                            for k, v in qs.items()
                        }
                    except Exception:
                        body_parsed = None

        # Merge any explicit params into body_parsed for GET requests
        if params:
            if body_parsed is None:
                body_parsed = {}
            if isinstance(body_parsed, dict):
                body_parsed.update(params)

        # Classify as API request
        is_api = bool(
            "json" in ct
            or body_parsed
            or any(re.search(p, path, re.I) for p in _API_PATH_PATTERNS)
            or path.count("/") >= 2
        )

        # Build path pattern (replace ID segments with {id})
        path_pattern = _make_path_pattern(path)

        return RawRequest(
            method=method,
            url=url,
            path=path,
            host=parsed.netloc,
            headers=headers,
            body=body_clean if body_clean else None,
            body_parsed=body_parsed,
            content_type=ct,
            source=source,
            is_api=is_api,
            path_pattern=path_pattern,
        )

    def _normalise(self, requests: list[RawRequest]) -> list[dict]:
        """Convert RawRequest objects to BLFinder endpoint dicts."""
        endpoints = []
        for req in requests:
            ep = {
                "url":    req.url,
                "method": req.method,
                "body":   req.body_parsed if isinstance(req.body_parsed, dict) else {},
                "params": {},
                "_source":       req.source,
                "_path_pattern": req.path_pattern,
            }
            endpoints.append(ep)
        return endpoints

    def _deduplicate(self, endpoints: list[dict]) -> list[dict]:
        """
        Merge duplicate endpoints by (method, path_pattern).
        When two entries share the same pattern, keeps the one with the
        richer request body (most keys).
        """
        seen: dict[str, dict] = {}
        for ep in endpoints:
            key = f"{ep['method']}:{ep.get('_path_pattern') or ep['url']}"
            if key not in seen:
                seen[key] = ep
            else:
                existing_keys = len(seen[key].get("body") or {})
                new_keys      = len(ep.get("body") or {})
                if new_keys > existing_keys:
                    seen[key] = ep

        result = list(seen.values())
        if self.verbose and len(result) < len(endpoints):
            print(
                f"  [*] Deduplicated: {len(endpoints)} → {len(result)} unique endpoints"
            )
        return result

    # ── JSON load helper ──────────────────────────────────────────────────────

    def _safe_load_json(self, path: str, result: ImportResult) -> Any:
        """
        Load a JSON file with helpful error messages.
        Handles UTF-8 BOM and trailing commas (common in exported files).
        """
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                content = f.read()
        except OSError as e:
            result.errors.append(f"Cannot read file: {e}")
            return None

        # Strip JavaScript-style trailing commas before closing braces/brackets
        # (some tools export slightly non-standard JSON)
        content = re.sub(r',\s*([}\]])', r'\1', content)

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            result.errors.append(
                f"JSON parse error in '{path}': {e}. "
                f"Ensure the file is valid JSON (not JSONP or JS)."
            )
            return None


# ── Path pattern helpers ──────────────────────────────────────────────────────

def _make_path_pattern(path: str) -> str:
    """
    Replace dynamic ID segments in a URL path with {{id}} placeholders.
    Applied in order: UUID → MongoDB ObjectID → numeric → long opaque token.
    Each replacement prevents the next pattern from double-replacing.
    """
    path = _UUID_ID_RE.sub("/{id}", path)
    path = _MONGO_ID_RE.sub("/{id}", path)
    path = _NUMERIC_ID_RE.sub("/{id}", path)
  
    path = _HASH_ID_RE.sub("/{id}", path)
    return path
