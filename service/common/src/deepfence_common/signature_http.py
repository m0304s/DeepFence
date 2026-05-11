"""평문 HTTP metadata 기반 시그니처 룰."""

from __future__ import annotations

from deepfence_common.schemas import FlowRecord
from deepfence_common.signature_types import SignatureMatch, metadata_text, score_for


_SQLI_PATTERNS = (
    " union select",
    "' or 1=1",
    "\" or 1=1",
    " or 1=1",
    "information_schema",
    "sleep(",
    "benchmark(",
    "extractvalue(",
)

_TRAVERSAL_PATTERNS = (
    "../",
    "..\\",
    "%2e%2e",
    "/etc/passwd",
    "boot.ini",
    "win.ini",
)

_SUSPICIOUS_USER_AGENTS = (
    "sqlmap",
    "nikto",
    "acunetix",
    "nmap scripting engine",
    "masscan",
    "zgrab",
)

_EXPLOIT_MARKERS = (
    "${jndi:",
    "cmd.exe",
    "powershell",
    "wget http",
    "curl http",
    "/bin/sh",
)


def _contains_any(value: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        if pattern in value:
            return pattern
    return ""


def evaluate_http_signatures(
    flow: FlowRecord,
    score_map: dict[str, int],
) -> tuple[SignatureMatch, ...]:
    if flow.metadata.get("http_is_plaintext") is not True:
        return ()

    path = metadata_text(flow, "http_path").lower()
    query = metadata_text(flow, "http_query").lower()
    user_agent = metadata_text(flow, "http_user_agent").lower()
    body = metadata_text(flow, "http_body_preview").lower()
    searchable = "\n".join((path, query, body))
    matches: list[SignatureMatch] = []

    pattern = _contains_any(searchable, _SQLI_PATTERNS)
    if pattern:
        rule_id = "http-sqli-keyword"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(SignatureMatch(rule_id, score, f"pattern={pattern}"))

    pattern = _contains_any(path, _TRAVERSAL_PATTERNS)
    if pattern:
        rule_id = "http-path-traversal"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(SignatureMatch(rule_id, score, f"path_pattern={pattern}"))

    pattern = _contains_any(user_agent, _SUSPICIOUS_USER_AGENTS)
    if pattern:
        rule_id = "http-suspicious-user-agent"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(SignatureMatch(rule_id, score, f"agent={pattern}"))

    pattern = _contains_any(searchable, _EXPLOIT_MARKERS)
    if pattern:
        rule_id = "http-known-exploit-marker"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(SignatureMatch(rule_id, score, f"marker={pattern}"))

    return tuple(matches)
