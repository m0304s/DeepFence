# DeepFence

DeepFence는 네트워크 침입 탐지 모델 학습 자산과 향후 IPS 서비스 런타임을 분리해 관리하는 프로젝트입니다.

## 디렉터리 구조

```text
DeepFence/
├── data/
│   ├── raw/                     # CIC-IDS-2018 원본 CSV
│   └── processed/               # 전처리 결과물
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
│   ├── notebooks/               # 전처리, 단일 모델, 앙상블 실험 노트북
│   └── results/                 # 평가 결과 리포트
└── venv/
```

## 작업 원칙

- 학습 관련 코드는 `training/` 아래에서 관리합니다.
- 앙상블 실험 노트북도 `training/notebooks/` 아래에 둡니다.
- 서비스 런타임 코드는 `service/sensor`, `service/inference`, `service/blocker`, `service/common`으로 역할 분리합니다.
- 데이터 입출력 기준 경로는 `data/`입니다.
- 공용 설계 문서는 `docs/` 아래에 둡니다.
