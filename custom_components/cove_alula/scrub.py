"""Scrub panel payloads before they are kept for diagnostics (pure, no HA imports)."""

from __future__ import annotations

from typing import Any

_SENSITIVE = ("name", "pin", "code", "user", "email", "phone", "passw", "tok")
_ID_KEYS = ("name", "field", "fieldName", "key", "label", "type")


def _is_sensitive(text: Any) -> bool:
    t = str(text).lower()
    return any(w in t for w in _SENSITIVE)


def scrub(obj: Any, depth: int = 0) -> Any:
    """Copy of obj without names, PINs/codes or user identifiers, at any depth.

    Keys that look sensitive are dropped. A record that names a sensitive field
    (e.g. {"name": "pin", "value": "1234"}) is dropped whole. Strings are truncated.
    Returns None for anything that should be dropped.
    """
    if depth > 6:
        return None
    if isinstance(obj, dict):
        for k in _ID_KEYS:
            if k in obj and isinstance(obj[k], str) and _is_sensitive(obj[k]):
                return None
        out = {}
        for k, v in obj.items():
            if _is_sensitive(k):
                continue
            sv = scrub(v, depth + 1)
            if sv is not None or v is None:
                out[k] = sv
        return out
    if isinstance(obj, list):
        return [s for s in (scrub(v, depth + 1) for v in obj[:128]) if s is not None]
    if isinstance(obj, (bool, int, float)) or obj is None:
        return obj
    return str(obj)[:40]
