"""샘플 센서 입력 생성."""

from __future__ import annotations

import json

import numpy as np

from deepfence_common import FlowKey, FlowRecord, RuntimeConfig, RuntimePaths


def load_mock_flow(paths: RuntimePaths, config: RuntimeConfig) -> FlowRecord:
    """전처리 샘플 1건 로드."""
    feature_names_path = paths.processed_dir / "feature_names.json"
    features_path = paths.processed_dir / "X.npy"

    with feature_names_path.open(encoding="utf-8") as file:
        feature_names = json.load(file)

    samples = np.load(features_path, mmap_mode="r")
    sample = samples[config.sample_index]
    feature_map = {name: float(value) for name, value in zip(feature_names, sample, strict=True)}

    return FlowRecord(
        key=FlowKey(
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
        ),
        features=feature_map,
        metadata={
            "source": "샘플-전처리-데이터",
            "sample_index": config.sample_index,
        },
        pre_scaled=True,
    )
