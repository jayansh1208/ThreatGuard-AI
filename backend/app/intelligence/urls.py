"""Helpers for safely exposing source URLs without query credentials."""

from urllib.parse import urlsplit, urlunsplit


def safe_source_url(url: str | None) -> str | None:
    """Remove query strings and fragments before a source URL is persisted or returned."""
    if not url or not isinstance(url, str):
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
