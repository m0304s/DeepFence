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

## 최소 실행

현재는 `detect-only` 기준 최소 런타임이 연결되어 있습니다.

```powershell
.\venv\Scripts\python.exe service\scripts\run_detect_only.py
```

이 스크립트는:
- `sensor`에서 mock flow 1건 생성
- `inference`에서 `best_model_v6_catboost.cbm` 로드 후 예측
- `blocker`에서 detect-only 정책 적용

까지를 한 번에 검증합니다.
