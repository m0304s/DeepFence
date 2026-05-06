"""실시간 패킷 수집 입력."""

from __future__ import annotations

from collections.abc import Iterable

from deepfence_common import PacketEvent, RuntimeConfig


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
    )


def capture_live_packets(config: RuntimeConfig) -> Iterable[PacketEvent]:
    """실시간 패킷 수집."""
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
