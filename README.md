# DeepFence

DeepFence는 네트워크 침입 탐지 모델 학습 자산과 향후 IPS 서비스 런타임을 분리해 관리하는 프로젝트입니다.

## 디렉터리 구조

```text
DeepFence/
├── docs/
│   └── ARCHITECTURE.md          # 전체 설계 문서
├── service/
│   ├── configs/                 # 서비스 설정 파일
│   ├── blocker/                 # 차단 정책 및 실행
│   ├── common/                  # 공용 설정, 스키마, 로깅
│   ├── inference/               # 모델 로딩 및 추론
│   ├── sensor/                  # 패킷 수집 및 플로우 집계
│   ├── scripts/                 # 실행/배포 보조 스크립트
│   └── tests/                   # 서비스 테스트
├── training/
│   ├── artifacts/
│   │   ├── catboost_info/       # CatBoost 로그/아티팩트
│   │   └── models/              # 학습된 모델과 체크포인트
│   ├── data/
│   │   ├── raw/                 # CIC-IDS-2018 원본 CSV
│   │   └── processed/           # 전처리 결과물
│   ├── notebooks/               # 전처리, 단일 모델, 앙상블 실험 노트북
│   └── results/                 # 평가 결과 리포트
└── venv/
```

## 작업 원칙

- 학습 관련 코드는 `training/` 아래에서 관리합니다.
- 앙상블 실험 노트북도 `training/notebooks/` 아래에 둡니다.
- 데이터 입출력 기준 경로는 `training/data/`입니다.
- 서비스 런타임 코드는 `service/sensor`, `service/inference`, `service/blocker`, `service/common`으로 역할 분리합니다.
- 공용 설계 문서는 `docs/` 아래에 둡니다.

## 현재 상태

- `training/data/processed/` 기준 전처리 산출물과 `best_model_v6_catboost.cbm`을 사용해 실시간 `detect-only` 파이프라인이 동작합니다.
- macOS에서 실시간 패킷 캡처는 `sudo` 권한이 필요합니다.
- 정책 엔진은 allowlist, label별 threshold, 반복 탐지 횟수, whitelist IP, 내부망 예외를 지원합니다.

## 빠른 실행

```bash
cd /Users/minseok/Desktop/codex/프로젝트/DeepFence
source venv/bin/activate
python service/scripts/run_detect_only.py
sudo venv/bin/python service/scripts/run_live_detect.py
```
