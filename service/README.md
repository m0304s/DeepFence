# Service Workspace

`service/`는 실시간 IPS 파이프라인 구현용 작업 영역입니다.

## 권장 배치

- `src/deepfence_service/flow_table.py`: 5-tuple 기반 플로우 집계
- `src/deepfence_service/feature_extractor.py`: 70개 피처 계산
- `src/deepfence_service/rule_engine.py`: 임계값 기반 선차단 룰
- `src/deepfence_service/inference.py`: 학습 모델 로딩 및 추론
- `src/deepfence_service/blocker.py`: eBPF/XDP 차단 연동
- `src/deepfence_service/main.py`: 전체 서비스 엔트리 포인트

현재는 구조 분리만 적용한 상태이며, 실제 서비스 코드는 이후 단계에서 채워 넣으면 됩니다.
