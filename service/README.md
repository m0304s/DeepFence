# Service Workspace

`service/`는 실시간 IPS 파이프라인 구현용 작업 영역입니다.

## 현재 구조

- `sensor/src/deepfence_sensor/`: 패킷 수집, 5-tuple 플로우 집계
- `inference/src/deepfence_inference/`: 피처 정렬, 스케일링, 모델 추론
- `blocker/src/deepfence_blocker/`: 정책 판단, 차단 실행
- `common/src/deepfence_common/`: 공용 설정, 데이터 스키마, 로깅

## 권장 역할

- `sensor`: `packet_source.py`, `flow_table.py`, `main.py`
- `inference`: `model_loader.py`, `predictor.py`, `main.py`
- `blocker`: `rule_engine.py`, `blocker.py`, `main.py`
- `common`: `config.py`, `schemas.py`, `logging.py`

현재는 실행 골격과 책임 분리만 적용한 상태이며, 실제 런타임 로직은 이후 단계에서 채워 넣으면 됩니다.
