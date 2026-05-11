"""실시간 패킷 수집 입력."""

from __future__ import annotations

from collections.abc import Iterable
from time import time

from deepfence_common import PacketEvent, RuntimeConfig


_PAYLOAD_PREVIEW_BYTES = 512


def _payload_preview(packet) -> str:
    """룰 평가용으로 짧은 printable payload preview만 보관."""
    if not packet.haslayer("Raw"):
        return ""
    raw_payload = bytes(getattr(packet["Raw"], "load", b""))[:_PAYLOAD_PREVIEW_BYTES]
    return raw_payload.decode("latin-1", errors="ignore")


def _dns_query(packet) -> tuple[str, str]:
    if not packet.haslayer("DNSQR"):
        return "", ""
    query = packet["DNSQR"]
    qname = getattr(query, "qname", b"")
    if isinstance(qname, bytes):
        qname_text = qname.decode("utf-8", errors="ignore")
    else:
        qname_text = str(qname)
    qtype = str(getattr(query, "qtype", ""))
    return qname_text.rstrip("."), qtype


def _flag_set(tcp_layer) -> frozenset[str]:
    """TCP 플래그 집합 변환."""
    flags = set()
    raw_flags = str(getattr(tcp_layer, "flags", ""))
    mapping = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "C": "CWE",
        "E": "ECE",
    }
    for flag, name in mapping.items():
        if flag in raw_flags:
            flags.add(name)
    return frozenset(flags)


def _to_packet_event(packet) -> PacketEvent | None:
    """Scapy 패킷을 공용 이벤트로 변환."""
    if not packet.haslayer("IP"):
        return None

    ip_layer = packet["IP"]
    protocol = "TCP" if packet.haslayer("TCP") else "UDP" if packet.haslayer("UDP") else "IP"

    src_port = 0
    dst_port = 0
    header_length = int(getattr(ip_layer, "ihl", 5)) * 4
    payload_bytes = max(len(bytes(packet)) - header_length, 0)
    window_bytes = 0
    flags = frozenset()
    payload_preview = _payload_preview(packet)
    dns_query, dns_query_type = _dns_query(packet)

    if packet.haslayer("TCP"):
        tcp_layer = packet["TCP"]
        src_port = int(getattr(tcp_layer, "sport", 0))
        dst_port = int(getattr(tcp_layer, "dport", 0))
        header_length += int(getattr(tcp_layer, "dataofs", 5)) * 4
        payload_bytes = max(len(bytes(packet)) - header_length, 0)
        window_bytes = int(getattr(tcp_layer, "window", 0))
        flags = _flag_set(tcp_layer)
    elif packet.haslayer("UDP"):
        udp_layer = packet["UDP"]
        src_port = int(getattr(udp_layer, "sport", 0))
        dst_port = int(getattr(udp_layer, "dport", 0))
        header_length += 8
        payload_bytes = max(len(bytes(packet)) - header_length, 0)

    return PacketEvent(
        timestamp=float(getattr(packet, "time", 0.0)),
        src_ip=str(getattr(ip_layer, "src", "")),
        dst_ip=str(getattr(ip_layer, "dst", "")),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=len(bytes(packet)),
        payload_bytes=payload_bytes,
        header_length=header_length,
        window_bytes=window_bytes,
        flags=flags,
        payload_preview=payload_preview,
        dns_query=dns_query,
        dns_query_type=dns_query_type,
    )


def capture_live_packets(config: RuntimeConfig) -> Iterable[PacketEvent]:
    """실시간 패킷 묶음 수집."""
    try:
        from scapy.all import sniff
    except ImportError as error:
        raise RuntimeError("scapy 패키지가 필요합니다.") from error

    packets = sniff(
        iface=config.capture_interface,
        count=config.capture_packet_count,
        timeout=config.capture_timeout_seconds,
        store=True,
    )

    for packet in packets:
        event = _to_packet_event(packet)
        if event is not None:
            yield event


def current_timestamp() -> float:
    """현재 시각 반환."""
    return time()
