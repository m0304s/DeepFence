"""이벤트 저장소 구현."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from urllib import error, request

from deepfence_common.config import RuntimeConfig
from deepfence_common.logging import configure_logging
from deepfence_common.schemas import DetectionResult


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def serialize_detection_event(result: DetectionResult) -> dict[str, object]:
    """탐지 결과를 저장용 이벤트로 직렬화."""
    metadata = result.flow.metadata
    key = result.flow.key
    return {
        "@timestamp": _utc_now_iso(),
        "label": result.label,
        "confidence": result.confidence,
        "risk_score": result.risk_score,
        "action": result.action,
        "should_block": result.should_block,
        "policy_reason": result.policy_reason,
        "observation_count": result.observation_count,
        "matched_rules": list(result.matched_rules),
        "suspicious": result.suspicious,
        "suspicious_reason": result.suspicious_reason,
        "src_ip": key.src_ip,
        "src_port": key.src_port,
        "dst_ip": key.dst_ip,
        "dst_port": key.dst_port,
        "protocol": key.protocol,
        "packet_count": metadata.get("packet_count"),
        "forward_packets": metadata.get("forward_packets"),
        "backward_packets": metadata.get("backward_packets"),
        "source": metadata.get("source"),
        "src_roles": metadata.get("src_asset_roles"),
        "dst_roles": metadata.get("dst_asset_roles"),
        "likely_response_traffic": metadata.get("likely_response_traffic"),
        "likely_outbound_client_traffic": metadata.get("likely_outbound_client_traffic"),
        "probabilities": result.probabilities,
    }


class OpenSearchEventStore:
    """OpenSearch로 이벤트를 저장."""

    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.event_store")
        self._endpoint = (
            f"{config.opensearch_url.rstrip('/')}/{config.opensearch_index}/_doc"
        )

    def save(self, result: DetectionResult) -> None:
        """탐지 이벤트 1건 저장."""
        body = json.dumps(serialize_detection_event(result)).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
        }

        if self._config.opensearch_username:
            token = f"{self._config.opensearch_username}:{self._config.opensearch_password}"
            encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"

        req = request.Request(
            self._endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self._config.opensearch_timeout_seconds):
                return
        except error.HTTPError as exc:
            message = exc.read().decode("utf-8", errors="replace")
            self._logger.exception(
                "OpenSearch 이벤트 저장 실패: status=%s body=%s",
                exc.code,
                message,
            )
        except error.URLError as exc:
            self._logger.exception("OpenSearch 이벤트 저장 실패: %s", exc)
