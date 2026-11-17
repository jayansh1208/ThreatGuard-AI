"""Small, testable helpers for the tenant intelligence dashboard."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit


def fetch_payload(request_fn: Callable[..., Any], path: str, *, params: dict | None = None) -> tuple[dict | None, Any | None]:
    """Make one authenticated API request and return either JSON or its response error."""
    try:
        response = request_fn("GET", path, params=params or {})
    except Exception as exc:
        return None, exc
    if not response.ok:
        return None, response
    try:
        payload = response.json()
    except (ValueError, AttributeError):
        return None, response
    return (payload if isinstance(payload, dict) else {}), None


def search_params(query: str, record_types: list[str], page: int, page_size: int) -> dict:
    params: dict[str, Any] = {"q": query.strip(), "page": page, "page_size": page_size}
    if record_types:
        params["record_type"] = record_types
    return params


def page_count(total: int, page_size: int) -> int:
    return max(1, (max(0, int(total)) + max(1, int(page_size)) - 1) // max(1, int(page_size)))


def safe_source_url(url: Any) -> str | None:
    """Do not render query strings or fragments that could contain credentials."""
    if not isinstance(url, str) or not url.startswith(("https://", "http://")):
        return None
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def sanitize_evidence(value: Any) -> Any:
    """Remove URL query strings recursively before rendering evidence or job errors."""
    if isinstance(value, dict):
        return {key: (safe_source_url(item) if key.lower() in {"url", "source_url"} else sanitize_evidence(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"https?://[^\s\"'<>]+", lambda match: safe_source_url(match.group(0)) or "[redacted URL]", value)
    return value


def graphviz_source(record: dict, relationships: list[dict]) -> str:
    """Render only identifiers and labels returned by the API; no relationship is inferred here."""
    def quote(value: Any) -> str:
        return str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")

    current = f'{record.get("record_type", "record")}:{record.get("record_id", "")}'
    lines = ["digraph intelligence {", '  graph [bgcolor="#0b1220", pad="0.25"];',
             '  node [shape=box, style="rounded,filled", fillcolor="#17243a", color="#405777", fontcolor="white"];',
             '  edge [fontcolor="#d6deeb", color="#7186a6"];',
             f'  "{quote(current)}" [label="{quote(record.get("record_id"))}", fillcolor="#174b67"];']
    for index, relation in enumerate(relationships):
        source = relation.get("source") or {}
        target = relation.get("target") or {}
        if not source and not target:
            source = {"type": record.get("record_type"), "id": record.get("record_id")}
            target = {"type": "related", "id": relation.get("target_record_id") or relation.get("source_record_id") or "related"}
        left = f'{source.get("type", "record")}:{source.get("id", "")}'
        right = f'{target.get("type", "record")}:{target.get("id", "")}'
        origin = relation.get("origin") or ("inferred" if relation.get("inferred") else "official_source")
        label = f'{relation.get("relationship_type") or relation.get("type") or "related"} · {origin}'
        for node in (left, right):
            if node != current:
                lines.append(f'  "{quote(node)}" [label="{quote(node.split(":", 1)[-1])}"];')
        lines.append(f'  "{quote(left)}" -> "{quote(right)}" [label="{quote(label)}", style="{"dashed" if origin == "inferred" else "solid"}"];')
    lines.append("}")
    return "\n".join(lines)
