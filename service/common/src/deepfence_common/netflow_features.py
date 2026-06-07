"""NetFlow v1 런타임 피처 생성."""

from __future__ import annotations


NETFLOW_V1_FEATURES = [
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "TOTAL_BYTES",
    "TOTAL_PKTS",
    "BYTES_PER_PACKET",
    "BYTES_PER_SECOND",
    "PACKETS_PER_SECOND",
    "IN_OUT_BYTES_RATIO",
    "IN_OUT_PKTS_RATIO",
]

_L7_PROTO_MAP = {
    "http": 7.0,
    "dns": 5.0,
    "tls": 91.0,
    "ssl": 91.0,
    "ssh": 92.0,
    "ftp": 1.0,
    "smtp": 25.0,
}


def protocol_number(protocol: str) -> float:
    normalized = protocol.upper()
    if normalized == "TCP":
        return 6.0
    if normalized == "UDP":
        return 17.0
    if normalized == "ICMP":
        return 1.0
    return 0.0


def l7_protocol_number(app_proto: object) -> float:
    value = str(app_proto or "").lower()
    for key, number in _L7_PROTO_MAP.items():
        if key in value:
            return number
    return 0.0


def tcp_flags_number(value: object) -> float:
    """Suricata 문자열/정수 플래그 값을 NetFlow 누적 TCP_FLAGS 값으로 변환."""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip().lower()
    if not text:
        return 0.0
    try:
        return float(int(text, 16))
    except ValueError:
        pass

    flags = 0
    if "f" in text or "fin" in text:
        flags |= 0x01
    if "s" in text or "syn" in text:
        flags |= 0x02
    if "r" in text or "rst" in text:
        flags |= 0x04
    if "p" in text or "psh" in text:
        flags |= 0x08
    if "a" in text or "ack" in text:
        flags |= 0x10
    if "u" in text or "urg" in text:
        flags |= 0x20
    return float(flags)


def build_netflow_v1_features(
    *,
    src_port: int,
    dst_port: int,
    protocol: str,
    app_proto: object = "",
    in_bytes: float = 0.0,
    out_bytes: float = 0.0,
    in_pkts: float = 0.0,
    out_pkts: float = 0.0,
    tcp_flags: object = 0,
    duration_milliseconds: float = 0.0,
) -> dict[str, float]:
    """NF-CSE-CIC-IDS2018 NetFlow v1 학습 피처와 동일한 이름으로 생성."""
    duration_ms = max(float(duration_milliseconds), 1.0)
    duration_seconds = duration_ms / 1000.0
    total_bytes = float(in_bytes) + float(out_bytes)
    total_pkts = float(in_pkts) + float(out_pkts)

    return {
        "L4_SRC_PORT": float(src_port),
        "L4_DST_PORT": float(dst_port),
        "PROTOCOL": protocol_number(protocol),
        "L7_PROTO": l7_protocol_number(app_proto),
        "IN_BYTES": float(in_bytes),
        "OUT_BYTES": float(out_bytes),
        "IN_PKTS": float(in_pkts),
        "OUT_PKTS": float(out_pkts),
        "TCP_FLAGS": tcp_flags_number(tcp_flags),
        "FLOW_DURATION_MILLISECONDS": duration_ms,
        "TOTAL_BYTES": total_bytes,
        "TOTAL_PKTS": total_pkts,
        "BYTES_PER_PACKET": total_bytes / total_pkts if total_pkts > 0 else 0.0,
        "BYTES_PER_SECOND": total_bytes / duration_seconds,
        "PACKETS_PER_SECOND": total_pkts / duration_seconds,
        "IN_OUT_BYTES_RATIO": float(in_bytes) / float(out_bytes) if float(out_bytes) > 0 else 0.0,
        "IN_OUT_PKTS_RATIO": float(in_pkts) / float(out_pkts) if float(out_pkts) > 0 else 0.0,
    }
