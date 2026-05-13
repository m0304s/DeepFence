<div align="center">

# DeepFence

</div>

**AI 기반 네트워크 침입 탐지 및 대응 시스템**<br>
**Suricata 이벤트 수집**, **머신러닝 추론**, **정책 기반 위험 점수화**, **자동 차단**을 하나의 파이프라인으로 연결한 실험형 IPS 프로젝트입니다.<br>
실시간 네트워크 플로우를 분석해 공격 가능성을 분류하고,<br>
시그니처 기반 탐지와 행위 기반 탐지를 함께 적용하여 단순 분류를 넘어 실제 대응 가능한 구조를 목표로 합니다.<br><br>

> Detect, Score, Block. **DeepFence**

- **프로젝트 기간** : 2026.03.13 ~ 2026.05.13 (약 2개월)
- **플랫폼** : Python Runtime / Network Security
- **개발 형태** : 개인 프로젝트
- **주요 실행 환경** : macOS 개발 환경, Ubuntu 계열 IPS 운영 환경
- **주요 데이터셋** : CIC-IDS-2018<br><br>

## 목차

<div align="center">

### <a href="#overview">프로젝트 개요</a>
### <a href="#tech-stack">기술 스택</a>
### <a href="#architecture">시스템 아키텍처</a>
### <a href="#pipeline">탐지 파이프라인</a>
### <a href="#features">핵심 기능</a>
### <a href="#directories">디렉터리 구조</a>
### <a href="#quick-start">빠른 실행</a>
### <a href="#opensearch">OpenSearch 연동</a>

</div>

## 프로젝트 개요

<a name="overview"></a>

DeepFence는 네트워크 트래픽을 실시간으로 수집하고, 이를 플로우 단위로 변환한 뒤 머신러닝 모델과 정책 엔진을 통해 공격 여부를 판단하는 프로젝트입니다.

현재 저장소는 크게 두 축으로 구성됩니다.

- `training/`: CIC-IDS-2018 기반 전처리, 모델 학습, 실험 결과 관리
- `service/`: 실시간 탐지, 정책 적용, 차단, 이벤트 저장을 담당하는 런타임 코드

주요 특징은 다음과 같습니다.

- Suricata `eve.json`를 기반으로 실시간 플로우를 수집
- CatBoost 모델을 사용한 공격 분류
- Allowlist, confidence threshold, repeat observation 기반 정책 엔진
- HTTP, DNS, Flow metadata 시그니처 탐지 지원
- Port scan, fan-out 행위 기반 이상 징후 탐지 지원
- Suricata 룰, XDP/eBPF, iptables를 이용한 차단 경로 포함
- OpenSearch로 탐지 이벤트 적재 가능

## 기술 스택

<a name="tech-stack"></a>

### Runtime / ML / Infra

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![CatBoost](https://img.shields.io/badge/CatBoost-FFCC00?style=for-the-badge&logoColor=black)
![NumPy](https://img.shields.io/badge/NumPy-013243?style=for-the-badge&logo=numpy&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?style=for-the-badge&logoColor=white)
![OpenSearch](https://img.shields.io/badge/OpenSearch-005EB8?style=for-the-badge&logo=opensearch&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

</div>

| Category | Stack |
| :-- | :-- |
| Language | Python |
| Packet Sensor | Suricata |
| ML Inference | CatBoost |
| Experimental Training Assets | PyTorch, CatBoost, scikit-learn |
| Data Processing | NumPy, pandas |
| Security Controls | XDP/eBPF, iptables, Suricata Rules |
| Event Storage | OpenSearch |
| Environment | macOS, Ubuntu, Docker Compose |

## 시스템 아키텍처

<a name="architecture"></a>

```text
[Network Traffic]
        |
        v
[Suricata Sensor]
  - flow / dns / http / tls / alert
        |
        v
[DeepFence Sensor]
  - eve.json tailing
  - FlowRecord 변환
  - metadata 가공
        |
        v
[Inference]
  - scaler 로드
  - CatBoost 모델 추론
        |
        v
[Policy Engine]
  - label threshold
  - repeat observation
  - signature scoring
  - behavior scoring
        |
        +--------------------+
        |                    |
        v                    v
[Blocker]              [Event Store]
  - Suricata rules       - OpenSearch
  - XDP/eBPF
  - iptables
```

## 탐지 파이프라인

<a name="pipeline"></a>

### 1. 실시간 이벤트 수집

- Suricata가 네트워크 인터페이스를 모니터링합니다.
- `eve.json`에 기록된 `flow`, `dns`, `http`, `tls`, `alert` 이벤트를 DeepFence가 읽어옵니다.

### 2. 플로우 정규화

- `flow_id` 기준으로 DNS, HTTP, TLS 메타데이터를 캐싱합니다.
- 종료된 `flow` 이벤트를 기준으로 `FlowRecord`를 생성합니다.
- 모델 입력에 필요한 피처와 정책 판단용 메타데이터를 함께 구성합니다.

### 3. 머신러닝 추론

- 전처리 산출물의 `feature_names.json`, `label_mapping.json`, `scaler.pkl`을 로드합니다.
- 기본 모델은 `best_model_v6_catboost.cbm`입니다.
- 플로우별 클래스 확률과 예측 라벨을 계산합니다.

### 4. 정책 평가

- 단순 confidence threshold만 보지 않고 추가 정책을 적용합니다.
- Allowlisted label 여부
- Label별 차단 threshold
- 반복 탐지 횟수
- 민감 포트 가중치
- Trusted service / response traffic 감점
- 시그니처 매칭 점수
- 행위 기반 이상 징후 점수

### 5. 대응 및 저장

- 최종 action이 `block_candidate` 또는 `block`이면 차단 경로를 실행합니다.
- 필요 시 OpenSearch에 탐지 이벤트를 저장합니다.

## 핵심 기능

<a name="features"></a>

### 1. 하이브리드 탐지

- ML 분류 결과와 룰 기반 탐지를 함께 사용합니다.
- 오탐을 줄이기 위해 allowlist, suspicious second-choice, threshold 기반 보정이 들어갑니다.

### 2. 시그니처 기반 보강

- HTTP 키워드 기반 SQL Injection, XSS, Command Injection 탐지
- DNS 장문 질의, 고엔트로피 도메인, TXT 질의 기반 이상 탐지
- Flow metadata 기반 포트 프로브, half-open, RST probe 탐지
- 외부 TI 연동용 확장 포인트 제공

### 3. 행위 기반 보강

- 짧은 시간 창에서 동일 출발지의 다중 포트 접근 패턴 추적
- 동일 포트로 다수 호스트에 접근하는 fan-out 패턴 추적

### 4. 다중 차단 경로

- Suricata 동적 룰 파일 갱신
- XDP/eBPF 기반 빠른 차단 경로
- iptables 기반 커널 레벨 차단

### 5. 분석 및 관측성

- Flow context를 포함한 구조화 로그 출력
- OpenSearch 적재를 통한 탐지 이벤트 검색 및 시각화 지원

## 디렉터리 구조

<a name="directories"></a>

```text
DeepFence/
├── docs/
│   └── ARCHITECTURE.md
├── infra/
│   └── opensearch/
│       ├── docker-compose.yml
│       └── opensearch_dashboards.yml
├── service/
│   ├── blocker/
│   │   └── src/deepfence_blocker/
│   ├── common/
│   │   └── src/deepfence_common/
│   ├── configs/
│   │   └── assets.example.json
│   ├── inference/
│   │   └── src/deepfence_inference/
│   ├── scripts/
│   │   ├── run_detect_only.py
│   │   └── run_live_detect.py
│   ├── sensor/
│   │   └── src/deepfence_sensor/
│   └── tests/
├── training/
│   ├── artifacts/
│   │   ├── catboost_info/
│   │   └── models/
│   ├── notebooks/
│   └── results/
└── requirements.txt
```

### 서비스 모듈 역할

| Module | Description |
| :-- | :-- |
| `service/sensor` | Suricata 실행, `eve.json` tailing, 플로우 변환 |
| `service/inference` | 모델 및 scaler 로드, 플로우별 예측 수행 |
| `service/blocker` | 정책 평가, 차단 룰 관리, XDP/iptables 연동 |
| `service/common` | 공용 설정, 스키마, 로깅, 시그니처, 이벤트 저장 |
| `training` | 전처리, 학습 실험, 모델 아티팩트 관리 |

## 빠른 실행

<a name="quick-start"></a>

### 1. 가상환경 활성화

```bash
cd /Users/minseok/Desktop/Project/DeepFence
source venv/bin/activate
```

### 2. 샘플 플로우 기반 detect-only 실행

```bash
python service/scripts/run_detect_only.py
```

### 3. 실시간 탐지 파이프라인 실행

macOS에서는 root 권한이 필요합니다.

```bash
sudo venv/bin/python service/scripts/run_live_detect.py
```

### 4. 필수 런타임 아티팩트

아래 파일이 존재해야 정상 동작합니다.

- `training/data/processed/feature_names.json`
- `training/data/processed/label_mapping.json`
- `training/data/processed/scaler.pkl`
- `training/artifacts/models/best_model_v6_catboost.cbm`

## OpenSearch 연동

<a name="opensearch"></a>

개발용 OpenSearch와 OpenSearch Dashboards는 Docker Compose로 실행할 수 있습니다.

```bash
cd /Users/minseok/Desktop/Project/DeepFence/infra/opensearch
docker compose up -d
```

기본 포트는 다음과 같습니다.

- OpenSearch: `http://localhost:9200`
- OpenSearch Dashboards: `http://localhost:5601`

DeepFence에서 이벤트를 OpenSearch로 저장하려면 `service/configs/.env`에 아래 값을 설정합니다.

```env
OPENSEARCH_ENABLED=true
OPENSEARCH_URL=http://localhost:9200
OPENSEARCH_INDEX=deepfence-events
OPENSEARCH_USERNAME=
OPENSEARCH_PASSWORD=
OPENSEARCH_TIMEOUT_SECONDS=5
```

연결 확인 예시는 아래와 같습니다.

```bash
curl http://localhost:9200
curl http://localhost:9200/deepfence-events/_search?pretty
```

## 참고 문서

- [시스템 설계 문서](./docs/ARCHITECTURE.md)
- [OpenSearch Dashboards 설정](./infra/opensearch/opensearch_dashboards.yml)
