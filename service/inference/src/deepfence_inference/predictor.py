"""CatBoost 기반 추론기."""

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
        with (paths.processed_dir / "scaler.pkl").open("rb") as file:
            self._scaler = pickle.load(file)

        self._model_mode = config.model_mode
        if self._model_mode in {"netflow_v2_twostage", "netflow_v3_rescue"}:
            self._load_twostage_models()
        else:
            self._load_multiclass_model()

    def predict(self, flow: FlowRecord) -> DetectionResult:
        """플로우 1건 예측."""
        model_input = self._model_input_for(flow)
        if self._model_mode in {"netflow_v2_twostage", "netflow_v3_rescue"}:
            return self._predict_twostage(flow, model_input)
        return self._predict_multiclass(flow, model_input)

    def _model_input_for(self, flow: FlowRecord) -> np.ndarray:
        ordered_features = np.array(
            [[flow.features.get(name, 0.0) for name in self._feature_names]],
            dtype=np.float32,
        )
        return ordered_features if flow.pre_scaled else self._scaler.transform(ordered_features)

    def _load_multiclass_model(self) -> None:
        with (self._paths.processed_dir / "label_mapping.json").open(encoding="utf-8") as file:
            label_mapping = json.load(file)
        self._idx_to_label = {index: label for label, index in label_mapping.items()}
        self._model = CatBoostClassifier()
        self._model.load_model(self._paths.model_dir / self._config.default_model_name)

    def _load_twostage_models(self) -> None:
        with (self._paths.processed_dir / "attack_label_mapping.json").open(encoding="utf-8") as file:
            attack_label_mapping = json.load(file)
        self._attack_idx_to_label = {
            index: label for label, index in attack_label_mapping.items()
        }
        self._binary_model = CatBoostClassifier()
        self._binary_model.load_model(self._paths.model_dir / self._config.default_model_name)
        self._attack_model = CatBoostClassifier()
        self._attack_model.load_model(self._paths.model_dir / self._config.attack_model_name)

    def _predict_multiclass(self, flow: FlowRecord, model_input: np.ndarray) -> DetectionResult:
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
            policy_reason="model-threshold",
            observation_count=0,
        )

    def _predict_twostage(self, flow: FlowRecord, model_input: np.ndarray) -> DetectionResult:
        binary_probabilities = self._binary_model.predict_proba(model_input)[0]
        benign_probability = float(binary_probabilities[0])
        attack_probability = float(binary_probabilities[1])

        attack_probabilities = self._attack_model.predict_proba(model_input)[0]
        attack_idx = int(np.argmax(attack_probabilities))
        attack_label = self._attack_idx_to_label[attack_idx]
        attack_label_probability = float(attack_probabilities[attack_idx])

        combined_probabilities = {"Benign": benign_probability}
        combined_probabilities.update(
            {
                self._attack_idx_to_label[index]: attack_probability * float(score)
                for index, score in enumerate(attack_probabilities)
            }
        )

        if attack_probability < self._config.binary_attack_threshold:
            rescued = self._rescued_result_if_needed(
                flow=flow,
                benign_probability=benign_probability,
                attack_probability=attack_probability,
                attack_probabilities=attack_probabilities,
                combined_probabilities=combined_probabilities,
            )
            if rescued is not None:
                return rescued
            return DetectionResult(
                label="Benign",
                confidence=benign_probability,
                should_block=False,
                flow=flow,
                probabilities=combined_probabilities,
                policy_reason=(
                    f"binary-attack-below-threshold({self._config.binary_attack_threshold:.2f})"
                ),
                observation_count=0,
            )

        confidence = attack_probability * attack_label_probability
        should_block = confidence >= self._config.block_confidence_threshold
        return DetectionResult(
            label=attack_label,
            confidence=confidence,
            should_block=should_block,
            flow=flow,
            probabilities=combined_probabilities,
            policy_reason="twostage-attack-threshold",
            observation_count=0,
        )

    def _rescued_result_if_needed(
        self,
        *,
        flow: FlowRecord,
        benign_probability: float,
        attack_probability: float,
        attack_probabilities: np.ndarray,
        combined_probabilities: dict[str, float],
    ) -> DetectionResult | None:
        if self._model_mode != "netflow_v3_rescue":
            return None

        rescue_index = None
        for index, label in self._attack_idx_to_label.items():
            if label == self._config.rescue_label:
                rescue_index = index
                break
        if rescue_index is None:
            return None

        rescue_probability = float(attack_probabilities[rescue_index])
        if attack_probability < self._config.rescue_min_binary_attack_probability:
            return None
        if rescue_probability < self._config.rescue_attack_label_threshold:
            return None

        result = DetectionResult(
            label="Benign",
            confidence=benign_probability,
            should_block=False,
            flow=flow,
            probabilities=combined_probabilities,
            policy_reason=(
                f"v3-rescue({self._config.rescue_label}={rescue_probability:.4f},"
                f"binary_attack={attack_probability:.4f})"
            ),
            observation_count=0,
            suspicious=True,
            suspicious_reason=(
                f"v3-rescue({self._config.rescue_label}={rescue_probability:.4f},"
                f"binary_attack={attack_probability:.4f})"
            ),
        )
        return result
