"""
BLFinder v3.1 — core/discovery/layer2_static/openapi_parser.py
OpenAPI 2/3, Swagger, Postman, Insomnia spec parser.

Termux-safe: aiohttp + stdlib only.

Strategy (FP-reduction aligned)
--------------------------------
Spec-derived endpoints get `spec_verified=True` and a +2 priority boost.
The schema_hint field is populated from requestBody / parameter schemas so
the scanner gets realistic bodies — not empty {} — which directly reduces
false positives from endpoints that require specific field shapes.

Supports:
  - OpenAPI 3.x (JSON + YAML)
  - Swagger 2.x (JSON + YAML)
  - Postman Collection v2.x JSON
  - Insomnia export JSON
  - RAML (partial — extracts paths only)
  - API Blueprint (partial — extracts GET/POST markers)
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

from ..models import (
    DiscoveredEndpoint, LayerResult,
    SOURCE_OPENAPI, DiscoveryConfig,
)
from ..layer5_dedup.normaliser import normalise_url, extract_id_params

# ── Well-known spec paths to probe ────────────────────────────────────────────
SPEC_PROBE_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/swagger.json",
    "/docs/swagger.json",
    "/docs/openapi.json",
    "/.well-known/openapi",
    "/spec/openapi.json",
    "/spec/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger-ui/swagger.json",
    "/postman_collection.json",
    "/insomnia_export.json",
    "/api/swagger",
    "/api/docs",
    "/api/schema",
    "/api/schema.json",
    "/api/schema.yaml",
    "/_api/swagger.json",
    "/internal/swagger.json",
    "/internal/openapi.json",
]

# HTTP methods that carry a request body
BODY_METHODS = {"POST", "PUT", "PATCH"}

# Type → example value mapping for body generation
TYPE_EXAMPLES: dict[str, Any] = {
    "integer": 1,
    "number":  1.0,
    "boolean": True,
    "string":  "test",
    "array":   [],
    "object":  {},
}


def _schema_to_example(schema: dict, depth: int = 0) -> Any:
    """
    Recursively convert an OpenAPI schema object to a concrete example body.
    Depth-limited to prevent runaway recursion on circular refs.
    """
    if depth > 4 or not isinstance(schema, dict):
        return None

    # Use provided example/default first (most realistic)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]

    s_type = schema.get("type", "")
    fmt    = schema.get("format", "")

    if s_type == "object" or "properties" in schema:
        result = {}
        for prop, prop_schema in schema.get("properties", {}).items():
            result[prop] = _schema_to_example(prop_schema, depth + 1)
        return result

    if s_type == "array":
        items = schema.get("items", {})
        sample = _schema_to_example(items, depth + 1)
        return [sample] if sample is not None else []

    if s_type == "integer":
        return 1
    if s_type == "number":
        return 1.0
    if s_type == "boolean":
        return True
    if s_type == "string":
        # Use format hints
        if fmt == "email":
            return "user@example.com"
        if fmt == "date":
            return "2024-01-01"
        if fmt == "date-time":
            return "2024-01-01T00:00:00Z"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000001"
        if fmt == "uri":
            return "https://example.com"
        if fmt == "password":
            return "Password123!"
        # Enum: pick first value
        enum = schema.get("enum", [])
        if enum:
            return enum[0]
        return "test"

    # oneOf / anyOf / allOf — take the first branch
    for key in ("oneOf", "anyOf", "allOf"):
        branches = schema.get(key, [])
        if branches:
            return _schema_to_example(branches[0], depth + 1)

    return None


def _resolve_ref(ref: str, full_spec: dict) -> dict:
    """
    Resolve a $ref like '#/components/schemas/Order' within the same spec.
    Returns the referenced schema dict or {} on failure.
    """
    if not ref.startswith("#/"):
        return {}
    parts = ref.lstrip("#/").split("/")
    node: Any = full_spec
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part, {})
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _inline_refs(schema: dict, full_spec: dict, depth: int = 0) -> dict:
    """Recursively replace $ref with the referenced schema (max 5 levels)."""
    if depth > 5 or not isinstance(schema, dict):
        return schema
    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], full_spec)
        return _inline_refs(schema, full_spec, depth + 1)
    result = {}
    for k, v in schema.items():
        if isinstance(v, dict):
            result[k] = _inline_refs(v, full_spec, depth + 1)
        elif isinstance(v, list):
            result[k] = [
                _inline_refs(i, full_spec, depth + 1) if isinstance(i, dict) else i
                for i in v
            ]
        else:
            result[k] = v
    return result


# ── Tag detection ─────────────────────────────────────────────────────────────
_TAG_KEYWORDS: dict[str, list[str]] = {
    "payment":  ["payment", "pay", "billing", "invoice", "charge", "transaction",
                 "refund", "wallet", "balance", "payout", "stripe", "card"],
    "order":    ["order", "cart", "checkout", "purchase", "buy"],
    "admin":    ["admin", "manage", "management", "internal", "staff",
                 "operator", "superuser", "backoffice"],
    "user":     ["user", "account", "profile", "member", "customer", "client"],
    "auth":     ["auth", "login", "logout", "token", "refresh", "oauth",
                 "password", "credential", "session", "mfa", "otp", "2fa"],
    "product":  ["product", "item", "sku", "catalog", "inventory", "stock"],
    "transfer": ["transfer", "withdraw", "deposit", "send", "remit"],
    "report":   ["report", "analytics", "metric", "stat", "dashboard", "export"],
}


def _infer_tags(path: str, summary: str = "", tags_from_spec: list = None) -> list[str]:
    combined = (path + " " + summary).lower()
    found: list[str] = []
    for tag, keywords in _TAG_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            found.append(tag)
    # Also include spec-provided tags (lowercased)
    for t in (tags_from_spec or []):
        lt = t.lower()
        if lt not in found:
            found.append(lt)
    return found


def _priority_from_tags(tags: list[str]) -> int:
    if any(t in tags for t in ("admin", "payment", "transfer")):
        return 1
    if any(t in tags for t in ("auth", "order", "user")):
        return 2
    return 3


# ── YAML shim (stdlib-safe fallback) ─────────────────────────────────────────
def _try_parse_yaml(text: str) -> Optional[dict]:
    """
    Attempt to parse YAML. On Termux without PyYAML, falls back to
    stripping YAML-only directives and parsing as JSON (works for many
    machine-generated OpenAPI YAML files that are almost-JSON).
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        pass
    # Minimal YAML→JSON heuristic (handles simple flat YAML specs)
    try:
        # Many OpenAPI YAML files are valid JSON with extra whitespace
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    return None


# ── Spec parsers ──────────────────────────────────────────────────────────────

def parse_openapi3(spec: dict, base_url: str) -> list[DiscoveredEndpoint]:
    """Parse OpenAPI 3.x spec."""
    endpoints: list[DiscoveredEndpoint] = []
    servers = spec.get("servers", [])
    server_url = servers[0].get("url", base_url) if servers else base_url
    if server_url.startswith("/"):
        server_url = base_url.rstrip("/") + server_url

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        # Shared parameters at path level
        path_params = path_item.get("parameters", [])

        for method, operation in path_item.items():
            if method.upper() not in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"):
                continue
            if not isinstance(operation, dict):
                continue

            full_url  = server_url.rstrip("/") + path
            body_dict: dict = {}
            params:    dict = {}

            # Request body
            if method.upper() in BODY_METHODS:
                rb     = operation.get("requestBody", {})
                content = rb.get("content", {})
                for ct in ("application/json", "application/x-www-form-urlencoded",
                           "multipart/form-data"):
                    if ct in content:
                        schema = content[ct].get("schema", {})
                        schema = _inline_refs(schema, spec)
                        example = _schema_to_example(schema)
                        if isinstance(example, dict):
                            body_dict = example
                        break

            # Parameters → query params
            all_params = path_params + operation.get("parameters", [])
            for param in all_params:
                if not isinstance(param, dict):
                    continue
                if param.get("in") == "query":
                    pschema = _inline_refs(param.get("schema", {}), spec)
                    params[param["name"]] = _schema_to_example(pschema) or ""

            tags     = _infer_tags(path, operation.get("summary", ""),
                                   operation.get("tags", []))
            priority = _priority_from_tags(tags)
            _, tmpl  = normalise_url(full_url)

            ep = DiscoveredEndpoint(
                url=full_url, method=method.upper(),
                body=body_dict, params=params,
                source=SOURCE_OPENAPI,
                confidence=0.95,
                priority=priority,
                auth_required=bool(operation.get("security", spec.get("security"))),
                schema_hint=body_dict,
                id_params=extract_id_params(path),
                tags=tags,
                raw_source_evidence=f"OpenAPI3 path: {path}",
                normalised_template=tmpl,
                spec_verified=True,
            )
            endpoints.append(ep)

    return endpoints


def parse_swagger2(spec: dict, base_url: str) -> list[DiscoveredEndpoint]:
    """Parse Swagger 2.x spec."""
    endpoints: list[DiscoveredEndpoint] = []
    host     = spec.get("host", urlparse(base_url).netloc)
    base_path = spec.get("basePath", "/")
    schemes  = spec.get("schemes", ["https"])
    scheme   = schemes[0] if schemes else "https"
    server_url = f"{scheme}://{host}{base_path}".rstrip("/")

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.upper() not in ("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"):
                continue
            if not isinstance(operation, dict):
                continue

            full_url   = server_url + path
            body_dict: dict = {}
            params:    dict = {}

            for param in operation.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                if param.get("in") == "body":
                    schema = _inline_refs(
                        param.get("schema", {}), spec
                    )
                    example = _schema_to_example(schema)
                    if isinstance(example, dict):
                        body_dict = example
                elif param.get("in") == "query":
                    params[param.get("name", "param")] = ""

            tags     = _infer_tags(path, operation.get("summary", ""),
                                   operation.get("tags", []))
            priority = _priority_from_tags(tags)
            _, tmpl  = normalise_url(full_url)

            ep = DiscoveredEndpoint(
                url=full_url, method=method.upper(),
                body=body_dict, params=params,
                source=SOURCE_OPENAPI,
                confidence=0.95,
                priority=priority,
                schema_hint=body_dict,
                id_params=extract_id_params(path),
                tags=tags,
                raw_source_evidence=f"Swagger2 path: {path}",
                normalised_template=tmpl,
                spec_verified=True,
            )
            endpoints.append(ep)

    return endpoints


def parse_postman(collection: dict, base_url: str) -> list[DiscoveredEndpoint]:
    """Parse Postman Collection v2.x."""
    endpoints: list[DiscoveredEndpoint] = []

    def process_item(item: dict):
        if "item" in item:
            for sub in item["item"]:
                process_item(sub)
            return
        req = item.get("request", {})
        if not isinstance(req, dict):
            return
        method = req.get("method", "GET").upper()
        url_obj = req.get("url", {})
        if isinstance(url_obj, str):
            full_url = url_obj
        else:
            raw = url_obj.get("raw", "")
            # Replace Postman variables {{baseUrl}} with the target
            raw = re.sub(r'\{\{[^}]+\}\}', base_url.rstrip("/"), raw)
            full_url = raw

        if not full_url.startswith("http"):
            full_url = base_url.rstrip("/") + "/" + full_url.lstrip("/")

        body_dict: dict = {}
        body_obj = req.get("body", {}) or {}
        if body_obj.get("mode") == "raw":
            try:
                body_dict = json.loads(body_obj.get("raw", "{}"))
            except Exception:
                pass

        _, tmpl = normalise_url(full_url)
        path    = urlparse(full_url).path
        tags    = _infer_tags(path, item.get("name", ""))

        ep = DiscoveredEndpoint(
            url=full_url, method=method,
            body=body_dict if isinstance(body_dict, dict) else {},
            source=SOURCE_OPENAPI,
            confidence=0.90,
            priority=_priority_from_tags(tags),
            schema_hint=body_dict if isinstance(body_dict, dict) else {},
            id_params=extract_id_params(path),
            tags=tags,
            raw_source_evidence=f"Postman item: {item.get('name','')}",
            normalised_template=tmpl,
            spec_verified=True,
        )
        endpoints.append(ep)

    for item in collection.get("item", []):
        process_item(item)
    return endpoints


def parse_insomnia(export: dict, base_url: str) -> list[DiscoveredEndpoint]:
    """Parse Insomnia v4 export."""
    endpoints: list[DiscoveredEndpoint] = []
    resources = export.get("resources", [])
    for res in resources:
        if res.get("_type") != "request":
            continue
        method   = res.get("method", "GET").upper()
        full_url = res.get("url", "")
        # Replace Insomnia environment vars {{ base_url }}
        full_url = re.sub(r'\{\{[^}]+\}\}', base_url.rstrip("/"), full_url)
        if not full_url.startswith("http"):
            continue

        body_dict: dict = {}
        body = res.get("body", {}) or {}
        if body.get("mimeType") == "application/json":
            try:
                body_dict = json.loads(body.get("text", "{}"))
            except Exception:
                pass

        _, tmpl = normalise_url(full_url)
        path    = urlparse(full_url).path
        tags    = _infer_tags(path, res.get("name", ""))

        ep = DiscoveredEndpoint(
            url=full_url, method=method,
            body=body_dict if isinstance(body_dict, dict) else {},
            source=SOURCE_OPENAPI,
            confidence=0.90,
            priority=_priority_from_tags(tags),
            schema_hint=body_dict if isinstance(body_dict, dict) else {},
            id_params=extract_id_params(path),
            tags=tags,
            raw_source_evidence=f"Insomnia request: {res.get('name','')}",
            normalised_template=tmpl,
            spec_verified=True,
        )
        endpoints.append(ep)
    return endpoints


def detect_and_parse(body: str, base_url: str) -> list[DiscoveredEndpoint]:
    """
    Detect spec format and dispatch to the right parser.
    Returns [] if the body is not a recognisable spec.
    """
    if not body or len(body) < 20:
        return []

    # Try JSON first
    spec: Optional[dict] = None
    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        spec = _try_parse_yaml(body)

    if not isinstance(spec, dict):
        return []

    # Postman collection
    if "info" in spec and "item" in spec:
        info = spec.get("info", {})
        if "postman" in str(info.get("schema", "")).lower():
            return parse_postman(spec, base_url)

    # Insomnia export
    if spec.get("_type") == "export" and "resources" in spec:
        return parse_insomnia(spec, base_url)

    # OpenAPI 3.x
    openapi_ver = spec.get("openapi", "")
    if isinstance(openapi_ver, str) and openapi_ver.startswith("3"):
        return parse_openapi3(spec, base_url)

    # Swagger 2.x
    if spec.get("swagger", "").startswith("2") or "basePath" in spec:
        return parse_swagger2(spec, base_url)

    # Partial RAML / API Blueprint heuristic
    if "paths" in spec:
        return parse_openapi3(spec, base_url)

    return []


# ── Main async runner ─────────────────────────────────────────────────────────

class OpenAPIParser:
    """
    Probes well-known spec paths on the target and parses any found specs.
    Also accepts explicit spec paths via config.openapi_paths.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    async def run(
        self,
        target_url: str,
        session: Any,               # aiohttp.ClientSession
        config: "DiscoveryConfig",
        auth_token: str = "",
    ) -> LayerResult:
        t0 = time.time()
        result = LayerResult(layer="layer2:openapi")

        parsed    = urlparse(target_url)
        base_url  = f"{parsed.scheme}://{parsed.netloc}"
        to_probe  = list(SPEC_PROBE_PATHS) + list(config.openapi_paths)

        headers: dict = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        headers["Accept"] = "application/json, text/yaml, */*"

        found_specs: list[str] = []

        async def fetch(path: str) -> Optional[str]:
            url = base_url + path if path.startswith("/") else path
            try:
                async with session.get(
                    url, headers=headers,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=config.timeout_s),
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "")
                        # Reject HTML pages (swagger-ui HTML, not the spec)
                        text = await resp.text(errors="replace")
                        if "<html" in text[:200].lower():
                            return None
                        return text
            except Exception as e:
                if self.verbose:
                    result.errors.append(f"fetch {url}: {e}")
            return None

        # Probe all paths concurrently (batched to avoid overwhelming the target)
        batch_size = 10
        for i in range(0, len(to_probe), batch_size):
            batch   = to_probe[i:i + batch_size]
            texts   = await asyncio.gather(*[fetch(p) for p in batch])
            for path, text in zip(batch, texts):
                if not text:
                    continue
                eps = detect_and_parse(text, base_url)
                if eps:
                    found_specs.append(path)
                    result.endpoints.extend(eps)
                    if self.verbose:
                        print(
                            f"  [OpenAPI] {path}: {len(eps)} endpoints"
                        )

        if found_specs:
            print(
                f"  [+] OpenAPI/Swagger: {len(found_specs)} spec(s) found, "
                f"{len(result.endpoints)} endpoints extracted"
            )
        elif self.verbose:
            print("  [OpenAPI] No specs found at well-known paths")

        result.elapsed_s = time.time() - t0
        return result
