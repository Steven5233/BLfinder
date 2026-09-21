from __future__ import annotations

import re

_ERROR_PHRASES = (
    "not found", "does not exist", "no resource", "no such",
    "invalid id", "invalid request", "invalid token",
    "not authorized", "unauthorized", "access denied", "permission denied",
    "forbidden", "not allowed",
    "internal server error", "stack trace", "traceback (most recent",
    "validation failed", "bad request",
)

_ERROR_JSON_FIELD_RE = re.compile(
    r'"(error|errors)"\s*:\s*(true|\{|\[|"(?!\s*(null|none|ok|false)?\s*"))',
    re.I,
)


def looks_like_error(body: str, status: int | None = None) -> bool:
    if not body:
        return True
    if status is not None:
        if status in (403, 404, 410, 422):
            return True
        if status >= 500:
            return True
    b = body.lower()
    if any(p in b for p in _ERROR_PHRASES):
        return True
    if _ERROR_JSON_FIELD_RE.search(body):
        return True
    return False
