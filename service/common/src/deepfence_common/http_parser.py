"""평문 HTTP 요청 metadata 파서."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote_plus, urlsplit


_HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "CONNECT",
}


@dataclass(frozen=True, slots=True)
class HttpRequestMetadata:
    method: str
    path: str
    query: str
    host: str
    user_agent: str
    body_preview: str


def parse_http_request(payload_preview: str) -> HttpRequestMetadata | None:
    """payload preview가 평문 HTTP 요청이면 구조화된 metadata를 반환."""
    if not payload_preview:
        return None

    normalized = payload_preview.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line]
    if not lines:
        return None

    parts = lines[0].split()
    if len(parts) < 3:
        return None

    method, raw_target, version = parts[0].upper(), parts[1], parts[2].upper()
    if method not in _HTTP_METHODS or not version.startswith("HTTP/"):
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    target = urlsplit(raw_target)
    path = unquote_plus(target.path or raw_target)
    query = unquote_plus(target.query)

    return HttpRequestMetadata(
        method=method,
        path=path,
        query=query,
        host=headers.get("host", ""),
        user_agent=headers.get("user-agent", ""),
        body_preview=unquote_plus(body[:512]),
    )
