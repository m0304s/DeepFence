# 딥러닝 기반 IPS 시스템

## 프로젝트 개요
- **목표**: 1D-CNN 기반 네트워크 침입 탐지 및 차단 시스템
- **데이터셋**: CIC-IDS-2018 (UNB)
- **모델**: PyTorch 1D-CNN 다중 분류 (7개 클래스)

---

## 분류 클래스
| 번호 | 클래스 | 원본 레이블 |
|------|--------|------------|
| 0 | Benign | Benign |
| 1 | Bot | Bot |
| 2 | Brute Force | FTP-BruteForce, SSH-Bruteforce, Brute Force -Web, Brute Force -XSS |
| 3 | DDoS | DDoS attacks-LOIC-HTTP, DDOS attack-LOIC-UDP, DDOS attack-HOIC |
| 4 | DoS | DoS attacks-Hulk, GoldenEye, Slowloris, SlowHTTPTest |
| 5 | Infiltration | Infilteration |
| 6 | SQL Injection | SQL Injection |

---

## 데이터 전처리 결과
- **원본 샘플**: 약 1,600만개
- **전처리 후**: 2,330,915개 / 70개 피처
- **클래스 불균형 처리**:
  - 다수 클래스 (Benign, DDoS, DoS): 최대 500,000개로 언더샘플링
  - SQL Injection (87개 → 1,000개): SMOTE 오버샘플링
- **스케일링**: StandardScaler
- **저장 위치**: `processed/X.npy`, `processed/y.npy`

---

## 모델 아키텍처 (CNN1D)
```
입력: (Batch, 1, 70)
 ↓ Conv1d(1→64,  k=3) + BN + ReLU + MaxPool(2)
 ↓ Conv1d(64→128, k=3) + BN + ReLU + MaxPool(2)
 ↓ Conv1d(128→256, k=3) + BN + ReLU + AdaptiveAvgPool(1)
 ↓ Flatten
 ↓ FC(256→128) + ReLU + Dropout(0.3)
 ↓ FC(128→7)
```
- **Optimizer**: Adam (lr=1e-3)
- **Scheduler**: ReduceLROnPlateau (factor=0.5, patience=3)
- **Early Stopping**: patience=5
- **체크포인트**: `models/checkpoint.pt` (매 epoch), `models/best_model.pt` (best val_loss)

---

## 전체 시스템 아키텍처

### 네트워크 배치
```
[인터넷]
    ↓
[라우터]
    ↓
[IPS 서버 - Ubuntu VM]
  ├── XDP/eBPF (커널) : 즉시 차단
  └── Python AI (유저): 정밀 분석
    ↓
[내부 네트워크]
```

### 처리 파이프라인
```
패킷 수신
    ↓
[1차: XDP/eBPF - 커널]
  • 블랙리스트 IP 즉시 DROP
  • 패킷 임계값 초과 → DROP
  • SYN Flood → DROP
    ↓ 통과
[2차: 플로우 집계 - Python]
  • 5-tuple 기준 패킷 묶음
  • FIN/RST 또는 타임아웃 시 종료
    ↓ 플로우 완성
[3차: 피처 추출]
  • CICFlowMeter 동일 70개 피처 계산
  • StandardScaler 정규화
    ↓
[4차: AI 추론 - PyTorch CNN1D]
  • 공격 유형 예측
    ↓ 공격 탐지 시
[대응: eBPF Map 업데이트]
  • IP 블랙리스트 등록
  • 로그 기록 / 알림
```

---

## 기술 스택
| 레이어 | 기술 | 언어 |
|--------|------|------|
| 패킷 필터링 | XDP + eBPF | C |
| eBPF 제어 | bcc | Python |
| 패킷 캡처 | scapy | Python |
| 플로우 집계 | 직접 구현 | Python |
| 피처 추출 | 직접 구현 | Python |
| AI 추론 | PyTorch | Python |
| 차단 실행 | eBPF Map 업데이트 | Python |

---

## 개발 환경
- **모델 학습**: Windows 11, Python 3.14, CPU only
- **IPS 구동**: Ubuntu 24.04 VM (VirtualBox)
- **테스트 환경**: VM2대 (Kali Linux 공격자 + Ubuntu 방어자)

---

## 개발 로드맵
```
Phase 1 (진행 중)
  ✅ 데이터 전처리 (preprocess.ipynb)
  🔄 CNN1D 모델 학습 (model.ipynb)
  ⬜ 모델 평가

Phase 2
  ⬜ VM 환경 구성 (Ubuntu 24.04 + bcc + clang + scapy)
  ⬜ inference.py 모듈화

Phase 3
  ⬜ XDP 프로그램 작성 (C/eBPF)
  ⬜ bcc Python 바인딩

Phase 4
  ⬜ flow_table.py        플로우 집계
  ⬜ feature_extractor.py 피처 70개 추출
  ⬜ rule_engine.py       임계값 기반 탐지
  ⬜ blocker.py           eBPF Map 차단 연동

Phase 5
  ⬜ main.py              전체 파이프라인 통합
  ⬜ 공격 시나리오 테스트 (nmap, hping3, hydra)

Phase 6 (선택)
  ⬜ 실시간 대시보드 (Flask / Grafana)
  ⬜ 알림 연동 (이메일 / Slack)
```

---

## 파일 구조
```
IPS/
├── dataset/              # CIC-IDS-2018 원본 CSV (10개 파일)
├── processed/            # 전처리 결과
│   ├── X.npy             # 피처 (2,330,915 × 70)
│   ├── y.npy             # 레이블
│   ├── scaler.pkl        # StandardScaler
│   ├── label_mapping.json
│   └── feature_names.json
├── models/               # 학습된 모델
│   ├── best_model.pt
│   ├── checkpoint.pt
│   └── model_meta.json
├── venv/                 # Python 가상환경
├── preprocess.ipynb      # 데이터 전처리
├── model.ipynb           # 모델 학습 및 평가
└── ARCHITECTURE.md       # 이 문서
```
