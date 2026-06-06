"""TLS metadata 기반 시그니처 룰.

현재 센서는 TLS 복호화를 하지 않으므로 HTTP path/query/header/body 기반 룰은
HTTPS에 적용하지 않는다. 이 모듈은 향후 SNI, ALPN, JA3/JA4, 인증서 metadata가
들어오면 확장하는 자리다.
"""

from __future__ import annotations

from deepfence_common.schemas import FlowRecord
from deepfence_common.signature_types import SignatureMatch


def evaluate_tls_signatures(
    flow: FlowRecord,
    score_map: dict[str, int],
) -> tuple[SignatureMatch, ...]:
    return ()
