# DeepFence Architecture

## 1. 문서 목적

이 문서는 DeepFence의 현재 구현 기준 아키텍처를 설명합니다.

기존 설계 문서에는 초기 실험 단계의 `1D-CNN`, `scapy`, 단일 파이프라인 구상이 포함돼 있었지만, 현재 저장소의 실제 런타임은 다음 구조를 기준으로 동작합니다.

- `Suricata` 기반 실시간 이벤트 수집
- `CatBoost` 기반 플로우 분류
- 시그니처 + 행동 기반 보강이 포함된 정책 엔진
- `Suricata Rules`, `XDP/eBPF`, `iptables`를 통한 차단 경로
- `OpenSearch` 기반 이벤트 저장

## 2. 시스템 목표

DeepFence의 목표는 단순한 오프라인 침입 탐지 모델이 아니라, 실시간 네트워크 이벤트를 수집하고 위험도를 계산해 실제 차단까지 이어지는 실험형 IPS 파이프라인을 만드는 것입니다.

핵심 목표는 다음과 같습니다.

- 실시간 네트워크 이벤트를 플로우 단위로 정규화
- 머신러닝 모델로 공격 유형 분류
- 룰 기반 탐지와 행위 기반 탐지로 ML 분류 보강
- 반복 탐지, 민감 포트, 화이트리스트 정책을 반영한 최종 액션 결정
- 필요 시 즉시 차단 및 이벤트 저장

## 3. 상위 아키텍처

```text
[Network Interface]
        |
        v
[Suricata]
  - flow
  - dns
  - http
  - tls
  - alert
        |
        v
[Sensor Layer]
  - eve.json tailing
  - flow_id 기준 metadata 캐싱
  - FlowRecord 생성
        |
        v
[Inference Layer]
  - scaler 로드
  - CatBoost 모델 추론
  - 확률 분포 계산
        |
        v
[Policy Layer]
  - allowlist
  - threshold
  - repeat observation
  - signature scoring
  - behavior scoring
  - dampening
        |
        +-----------------------+
        |                       |
        v                       v
[Block Layer]              [Storage Layer]
  - Suricata rules          - OpenSearch
  - XDP/eBPF
  - iptables
```

## 4. 서비스 경계

현재 저장소는 `training/`과 `service/`를 분리해 관리합니다.

### 4.1 Training 영역

`training/`은 모델 학습과 실험 자산을 담당합니다.

- 데이터 전처리 노트북
- 모델 실험 노트북
- 학습 결과물
- 모델 아티팩트
- 평가 리포트

주요 산출물은 런타임에서 직접 사용됩니다.

- `training/data/processed/feature_names.json`
- `training/data/processed/label_mapping.json`
- `training/data/processed/scaler.pkl`
- `training/artifacts/models/best_model_v6_catboost.cbm`

### 4.2 Runtime 영역

`service/`는 실시간 탐지와 대응을 담당합니다.

| 모듈 | 역할 |
| :-- | :-- |
| `service/sensor` | Suricata 구동, `eve.json` 수집, 이벤트를 `FlowRecord`로 변환 |
| `service/inference` | 모델 및 scaler 로드, 플로우별 추론 수행 |
| `service/blocker` | 정책 엔진, 차단 룰 관리, XDP/iptables 연동 |
| `service/common` | 공용 설정, 스키마, 로깅, 시그니처, 저장 로직 |
| `service/scripts` | 전체 파이프라인 실행 스크립트 |

## 5. 데이터 모델

런타임은 몇 가지 핵심 데이터 구조를 중심으로 동작합니다.

### 5.1 PacketEvent

패킷 단위 메타데이터를 표현하기 위한 구조입니다. 현재 실시간 주 경로에서는 직접 중심이 되지는 않지만 공용 스키마 계층에 정의돼 있습니다.

### 5.2 FlowKey

5-튜플 기반 플로우 식별자입니다.

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`

### 5.3 FlowRecord

센서가 추론기에 넘기는 핵심 단위입니다.

- `key`: 플로우 식별자
- `features`: 모델 입력용 숫자 피처
- `metadata`: 정책 엔진과 저장 계층에서 사용하는 부가 정보
- `pre_scaled`: 입력 피처가 이미 스케일링됐는지 여부

### 5.4 DetectionResult

추론 결과와 정책 결과를 모두 담는 통합 구조입니다.

- 예측 라벨
- confidence
- should_block
- 클래스별 확률
- risk score
- action
- matched rules
- matched signatures
- matched behaviors

## 6. 센서 계층

센서 계층의 목표는 Suricata가 생성한 이벤트를 ML과 정책 엔진이 처리 가능한 `FlowRecord`로 바꾸는 것입니다.

### 6.1 SuricataRunner

`SuricataRunner`는 Suricata 프로세스를 서브프로세스로 실행합니다.

주요 역할:

- 네트워크 인터페이스 지정
- 로그 디렉터리 설정
- 동적 차단 룰 파일 연결
- `eve.json` 출력 항목 활성화
- flow timeout 단축 설정

현재 출력 대상으로 활성화되는 이벤트는 다음과 같습니다.

- `flow`
- `http`
- `dns`
- `alert`
- `tls`

### 6.2 SuricataTailer

`SuricataTailer`는 `eve.json`를 tailing 하면서 새 이벤트를 순차적으로 읽습니다.

핵심 처리:

1. `dns`, `http`, `tls` 이벤트를 `flow_id` 기준으로 캐싱
2. `alert` 이벤트는 즉시 `FlowRecord`로 변환 가능
3. `flow.state == "closed"` 인 종료 플로우만 최종 처리
4. 플로우 메타데이터와 모델 피처를 함께 생성

### 6.3 이벤트 정규화 전략

현재 구현은 Suricata의 flow 통계를 기반으로 CICFlowMeter 계열 피처 일부를 근사합니다.

예시:

- `Tot Fwd Pkts`
- `Tot Bwd Pkts`
- `TotLen Fwd Pkts`
- `TotLen Bwd Pkts`
- `Flow Duration`
- `Flow Byts/s`
- `Flow Pkts/s`

중요한 제약:

- 학습 데이터의 모든 피처를 실시간으로 동일하게 복원하는 구조는 아직 아닙니다.
- 일부 피처는 `0` 또는 근사값으로 채워집니다.
- 따라서 실시간 입력 분포와 학습 데이터 분포 사이의 차이가 발생할 수 있습니다.

### 6.4 센서 메타데이터

정책 엔진과 시그니처 엔진은 피처 외에 다음 메타데이터를 활용합니다.

- `packet_count`
- `forward_packets`
- `backward_packets`
- `total_payload_bytes`
- `dns_queries`
- `http_method`
- `http_path`
- `http_query`
- `tls_sni`
- `suricata_alert_signature`
- `suricata_alert_severity`
- `dst_is_trusted_service`
- `likely_response_traffic`

## 7. 추론 계층

### 7.1 모델 아티팩트

현재 런타임 기본 모델은 CatBoost 분류기입니다.

- 모델: `best_model_v6_catboost.cbm`
- 피처 순서: `feature_names.json`
- 라벨 매핑: `label_mapping.json`
- 스케일러: `scaler.pkl`

### 7.2 Predictor 동작

`Predictor`는 다음 순서로 동작합니다.

1. `FlowRecord.features`를 학습 피처 순서대로 정렬
2. 필요 시 `StandardScaler` 적용
3. CatBoost `predict_proba` 호출
4. 최고 확률 클래스 선택
5. `DetectionResult` 생성

### 7.3 분류 클래스

현재 프로젝트 문서 기준 클래스 체계는 아래와 같습니다.

| 번호 | 클래스 | 원본 레이블 |
| :-- | :-- | :-- |
| 0 | Benign | Benign |
| 1 | Bot | Bot |
| 2 | Brute Force | FTP-BruteForce, SSH-Bruteforce, Brute Force -Web, Brute Force -XSS |
| 3 | DDoS | DDoS attacks-LOIC-HTTP, DDOS attack-LOIC-UDP, DDOS attack-HOIC |
| 4 | DoS | DoS attacks-Hulk, GoldenEye, Slowloris, SlowHTTPTest |
| 5 | Infiltration | Infilteration |
| 6 | SQL Injection | SQL Injection |

## 8. 정책 계층

정책 계층은 DeepFence의 핵심입니다. 단순히 ML confidence만 보고 차단하지 않고, 여러 보정 규칙을 적용해 최종 액션을 결정합니다.

### 8.1 기본 판단 요소

- `label_allowlist`
- `block_confidence_threshold`
- `label_block_thresholds`
- `whitelist_ips`
- `min_block_observations`
- `repeat_observation_score`
- `skip_private_peer_blocking`

### 8.2 액션 체계

현재 액션 단계는 다음과 같습니다.

```text
log -> suspicious -> alert -> block_candidate -> block
```

정책 엔진은 최종 `risk_score`를 계산한 뒤 이 단계 중 하나로 매핑합니다.

### 8.3 보정 요소

#### Allowlisted label

- 기본 허용 라벨은 `Benign`
- 다만 second-choice 공격 확률이 높으면 `suspicious`로 격상 가능

#### 반복 관측

- 동일 `(src_ip, dst_ip, dst_port, label)` 키에 대해 반복 탐지를 추적
- 첫 탐지에서는 `alert` 이하로 캡
- 반복 횟수가 기준을 넘으면 `repeat_observation_score`를 추가

#### 민감 포트 가중치

기본적으로 아래 포트는 추가 위험 점수를 부여할 수 있습니다.

- `22`
- `53`
- `445`
- `3389`

#### 신뢰 서비스 / 응답 트래픽 감점

- CDN, 클라우드, 알려진 서비스 트래픽은 감점 가능
- 서버 응답 성격 트래픽은 감점 가능

## 9. 시그니처 기반 탐지

ML 추론만으로는 설명력이 부족하거나 놓치기 쉬운 케이스를 보강하기 위해 시그니처 엔진을 사용합니다.

### 9.1 Flow metadata signatures

탐지 예시:

- 민감 포트에 대한 low-packet probe
- half-open probe
- RST probe

### 9.2 HTTP signatures

탐지 예시:

- SQL Injection 키워드
- XSS 키워드
- Path Traversal
- Command Injection 패턴
- Suspicious User-Agent

### 9.3 DNS signatures

탐지 예시:

- 비정상적으로 긴 질의
- TXT 기반 의심 질의
- 고엔트로피 도메인
- 수상한 TLD
- 터널링 의심 서브도메인

### 9.4 TLS signatures

현재 TLS 시그니처 계층은 확장 포인트 중심입니다.

- 향후 SNI, JA3/JA4, 인증서 메타데이터 기반 룰 확장 가능

### 9.5 Threat Intelligence

선택적으로 외부 TI 피드를 주기적으로 받아 악성 IP, 악성 도메인을 대조할 수 있습니다.

기본 피드 예시:

- Emerging Threats compromised IP feed
- URLhaus hostfile

## 10. 행동 기반 탐지

`BehaviorTracker`는 시간창 내 관측 패턴을 추적합니다.

현재 지원하는 패턴:

- `behavior-port-scan`
  - 동일 출발지가 동일 목적지의 여러 포트에 접근
- `behavior-fanout`
  - 동일 출발지가 동일 포트로 여러 목적지에 접근

이 계층은 Allowlisted 결과에도 보조적으로 적용될 수 있습니다.

## 11. 차단 계층

### 11.1 SuricataUpdater

정책 결과가 `block_candidate` 또는 `block`이면 차단 계층이 개입합니다.

주요 역할:

- 차단 대상 IP TTL 관리
- Suricata 동적 룰 파일 재작성
- Suricata 프로세스 룰 리로드
- XDP 차단 요청
- iptables 룰 삽입 및 제거

### 11.2 XDPManager

`XDPManager`는 eBPF/XDP 기반 빠른 차단 경로를 담당합니다.

현재 구조:

- `xdp_blocker.c` 로드
- 인터페이스에 XDP 프로그램 부착
- blocklist map 갱신
- IP 차단 및 해제

중요한 운영 주의:

- BCC 설치가 필요합니다.
- root 권한이 필요합니다.
- 운영체제와 NIC 드라이버 제약을 강하게 받습니다.

### 11.3 차단 실행 순서

```text
Policy says block
    -> XDP block attempt
    -> iptables rule insert
    -> Suricata rule rewrite
    -> Suricata live reload
```

## 12. 저장 계층

`OpenSearchEventStore`는 탐지 결과를 OpenSearch 문서로 저장합니다.

저장되는 주요 필드:

- timestamp
- label
- confidence
- risk_score
- action
- policy_reason
- matched_rules
- matched_signatures
- matched_behaviors
- src/dst IP, port, protocol
- HTTP / DNS metadata
- probabilities

이를 통해 OpenSearch Dashboards에서 검색, 필터링, 시각화를 수행할 수 있습니다.

## 13. 실행 흐름

### 13.1 샘플 실행

`service/scripts/run_detect_only.py`

동작:

1. 샘플 `FlowRecord` 생성
2. Predictor 로드
3. Policy 적용
4. 결과 로그 출력

### 13.2 실시간 실행

`service/scripts/run_live_detect.py`

동작:

1. 런타임 아티팩트 존재 여부 검사
2. Predictor / Policy / SuricataUpdater 초기화
3. Suricata 구동
4. 루프 내에서 종료 플로우 수집
5. 추론, 정책 적용, 로그 출력
6. 필요 시 차단 및 OpenSearch 저장
7. 종료 시 잔여 플로우 flush

## 14. 설정 체계

핵심 설정은 `RuntimeConfig`에서 관리되며, `service/configs/.env`를 통해 덮어쓸 수 있습니다.

주요 설정 범주:

- 라벨 허용/차단 기준
- 민감 포트 점수
- 액션 threshold
- 시그니처 활성화 및 점수
- TI 활성화
- 행동 기반 탐지 파라미터
- OpenSearch 연결 정보
- 기본 모델 이름
- 캡처 인터페이스
- 루프 주기
- 차단 TTL

## 15. 디렉터리 구조

```text
DeepFence/
├── docs/
│   └── ARCHITECTURE.md
├── infra/
│   └── opensearch/
├── service/
│   ├── blocker/
│   ├── common/
│   ├── configs/
│   ├── inference/
│   ├── scripts/
│   ├── sensor/
│   └── tests/
├── training/
│   ├── artifacts/
│   ├── notebooks/
│   └── results/
└── requirements.txt
```
