"""샘플 패킷 시퀀스 생성 (Scapy 제거)."""

from __future__ import annotations
import json

from deepfence_common import RuntimeConfig, RuntimePaths
from deepfence_common.schemas import FlowKey, FlowRecord

def load_mock_flow(paths: RuntimePaths, config: RuntimeConfig):
    """샘플 플로우 1건 직접 생성."""
    key = FlowKey(
        src_ip="192.0.2.10",
        dst_ip="198.51.100.20",
        src_port=51515,
        dst_port=443,
        protocol="TCP"
    )
    
    feature_names_path = paths.processed_dir / "feature_names.json"
    with feature_names_path.open(encoding="utf-8") as f:
        feature_names = json.load(f)
    
    features = {name: 0.0 for name in feature_names}
    
    # 더미 피처 덮어쓰기
    features.update({
        "Dst Port": 443.0,
        "Protocol": 6.0,
        "Flow Duration": 0.14,
        "Tot Fwd Pkts": 4.0,
        "Tot Bwd Pkts": 4.0,
        "TotLen Fwd Pkts": 642.0,
        "TotLen Bwd Pkts": 760.0,
        "Flow Byts/s": 10014.28,
        "Flow Pkts/s": 57.14,
    })
    
    metadata = {
        "source": "샘플-패킷-시퀀스",
        "sample_index": config.sample_index,
        "packet_count": 8,
        "forward_packets": 4,
        "backward_packets": 4,
        "total_payload_bytes": 1000,
        "payload_preview": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
        "http_is_plaintext": True,
        "http_method": "GET",
        "http_path": "/",
        "http_query": "",
        "http_host": "example.com",
    }
    
    return FlowRecord(key=key, features=features, metadata=metadata, pre_scaled=False)
