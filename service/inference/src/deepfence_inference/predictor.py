"""CatBoost 기반 최소 추론기."""

from __future__ import annotations

import json
import pickle

import numpy as np
from catboost import CatBoostClassifier

from deepfence_common import DetectionResult, FlowRecord, RuntimeConfig, RuntimePaths


class Predictor:
    """런타임 아티팩트 로드 및 예측."""

    def __init__(self, paths: RuntimePaths, config: RuntimeConfig):
        self._paths = paths
        self._config = config

        with (paths.processed_dir / "feature_names.json").open(encoding="utf-8") as file:
            self._feature_names = json.load(file)
        with (paths.processed_dir / "label_mapping.json").open(encoding="utf-8") as file:
            label_mapping = json.load(file)
        with (paths.processed_dir / "scaler.pkl").open("rb") as file:
            self._scaler = pickle.load(file)

        self._idx_to_label = {index: label for label, index in label_mapping.items()}
        self._model = CatBoostClassifier()
        self._model.load_model(paths.model_dir / config.default_model_name)

    def predict(self, flow: FlowRecord) -> DetectionResult:
        """플로우 1건 예측."""
        ordered_features = np.array(
            [[flow.features[name] for name in self._feature_names]],
            dtype=np.float32,
        )
        model_input = ordered_features if flow.pre_scaled else self._scaler.transform(ordered_features)
        probabilities = self._model.predict_proba(model_input)[0]

        predicted_idx = int(np.argmax(probabilities))
        predicted_label = self._idx_to_label[predicted_idx]
        confidence = float(probabilities[predicted_idx])
        should_block = (
            predicted_label not in self._config.label_allowlist
            and confidence >= self._config.block_confidence_threshold
        )

        return DetectionResult(
            label=predicted_label,
            confidence=confidence,
            should_block=should_block,
            flow=flow,
            probabilities={
                self._idx_to_label[index]: float(score)
                for index, score in enumerate(probabilities)
            },
        )
