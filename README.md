# Argus: AI 기반 통합 보안 자동 진단 시스템 (Backend)

본 프로젝트는 중소기업 및 스타트업을 위한 범용 웹 취약점 진단 플랫폼 **Argus**의 백엔드 시스템입니다.

## 🛠️ 기술 스택
- **API & Control Plane:** Python (FastAPI), SQLModel, PostgreSQL, Redis, Celery
- **Scan Engine:** OWASP ZAP (Docker REST API), Semgrep (SAST), SSL Labs API, Selenium Headless (증적 Replay)
- **AI & Report:** OpenAI API (Reachability 분석 및 맞춤형 가이드), WeasyPrint (한글 PDF 생성)

---

## 📂 폴더 구조 및 팀별 역할 분담

단일 루트 패키지인 `argus/` 구조 아래에서 협업을 진행합니다.

```text
argus/ (프로젝트 루트)
├── pyproject.toml
├── README.md
├── .env
└── argus/                      # 전체 소스코드를 담는 단일 루트 패키지
    ├── core/                   # [공통] 설정, 데이터베이스, 공통 유틸리티
    │   ├── config.py           # 환경 변수 및 설정 (Pydantic Settings)
    │   ├── database.py         # SQLModel 엔진 및 Session 설정
    │   ├── models.py           # 공통 DB 테이블 스키마 선언
    │   └── celery_app.py       # Celery 인스턴스 초기화 및 공통 설정
    │
    ├── api/                    # [공통] API Control Plane (FastAPI)
    │   ├── main.py             # FastAPI 엔트리포인트
    │   └── v1/                 # 버전별 라우터 분리
    │       ├── api.py          # 라우터들을 통합하는 엔트리포인트
    │       └── endpoints/
    │           ├── scan.py      # 스캔 요청 엔드포인트
    │
    ├── worker/                 # [공통] Celery 비동기 태스크
    │   └── tasks.py            # 각 엔진의 서비스 기능을 호출하는 Celery Task 정의
    │
    └── services/               # [A, B, C팀 각각의 핵심 비즈니스 로직]
        ├── scan/               # A팀: 스캔 엔진 핵심 로직
        │   ├── zap.py
        │   ├── semgrep.py
        │   ├── ssl.py
        │   └── ai_advisor.py
        ├── capture/            # B팀: Selenium 증적 캡처 로직
        │   └── selenium.py
        └── report/             # C팀: 도달성 검증 및 리포트 생성 로직
            ├── reachability.py
            └── generator.py
```

### 팀별 역할 분담
1. **[공통] `argus/core/`**: 프로젝트 설정, 데이터베이스 연결 객체, 데이터 모델(SQLModel), Celery 초기화 등 공통 리소스를 한곳에서 관리합니다.
2. **[공통] `argus/api/`**: 플랫폼의 전체적인 진입점 역할을 수행하며, 사용자 요청을 받아 비동기 큐에 할당하고 이력을 기록하는 제어 레이어(Control Plane)입니다.
3. **[공통] `argus/worker/`**: Celery 비동기 태스크들의 진입점입니다. `services/` 모듈에 작성된 비즈니스 로직들을 호출하여 실행시킵니다.
4. **[A팀 - 3명] `argus/services/scan/`**: 3가지 핵심 스캐너 도구를 구동하고 결과를 파싱하며, AI(LLM) API를 연동하여 위험도 우선순위를 산정하고 가이드를 생성합니다.
5. **[B팀 - 2명] `argus/services/capture/`**: Selenium Headless 브라우저를 구동하여 취약점을 검증하고 증적 화면을 캡처합니다.
6. **[C팀 - 2명] `argus/services/report/`**: Reachability 검증 및 WeasyPrint를 활용한 최종 한글 PDF 리포트를 생성합니다.

---

## 🔄 플랫폼 전체 진단 파이프라인 흐름 (Workflow Sequence)

```mermaid
graph TD
    A["1. 스캔 단계: services/scan"] -->|진단 결과 도출| B["2. 캡처 단계: services/capture"]
    B -->|공격 재현 스크린샷 확보| C["3. 보고서 단계: services/report"]
    C -->|AI 오탐 교차검증 & PDF 렌더링| D[4. 최종 진단 보고서 완료]
```

1. **스캔 및 AI 우선순위 단계 (`argus/services/scan`):**
   - ZAP(동적), Semgrep(정적), SSL Labs를 통해 취약점 진단을 수행한 후, AI(LLM) API를 사용하여 각 취약점의 위험도 우선순위를 지정하고 한글 설명 가이드를 생성합니다.
2. **캡처 단계 (`argus/services/capture`):**
   - 검출된 취약점들을 바탕으로 Selenium Headless 브라우저를 구동하여 실제 공격 시나리오를 Replay하고 증적 스크린샷 화면을 캡처합니다.
3. **보고서 및 검증 단계 (`argus/services/report`):**
   - Reachability 교차 검증을 통해 오탐을 필터링하고, WeasyPrint를 활용해 최종 한글 PDF 리포트를 생성합니다.

---

## 🚀 개발 환경 세팅 방법 (Poetry)

### 사전 준비물

| 항목 | 버전/비고 |
|------|-----------|
| Python | ^3.10 |
| Poetry | 최신 (`pip install poetry`) |
| Node.js | 프론트엔드 개발 시 필요 |
| OWASP ZAP | **2.17.x** 권장 |
| Chrome | **필수** — AJAX Spider 가 `chrome-headless` 로 하드코딩되어 있음 |

### 1. 의존성 설치

```bash
# 백엔드
git clone <repo>
cd ARGUS_Backend
poetry install

# 프론트엔드 (별도 레포)
cd ../ARGUS_Frontend
npm install   # 또는 pnpm install
```

### 2. 환경 변수 설정

`.env.example` 을 `.env` 로 복사한 뒤 값을 채웁니다:

```bash
cp .env.example .env
```

```env
# ZAP — 포트를 8090 으로 변경한 상태 (기본값 8080 과 다름)
ZAP_API_URL=http://127.0.0.1:8090
ZAP_API_KEY=             # ZAP GUI: Tools > Options > API > API Key

# DB / Redis
DATABASE_URL=postgresql://user:password@localhost:5432/argus
REDIS_URL=redis://localhost:6379/0

# AI
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
```

---

## ⚙️ ZAP 설정 (필수)

### 1. API 포트 변경 (8080 → 8090)

`Tools > Options > API`  
- **Port**: `8090`  
- **API Key**: 키 복사 → `.env` 의 `ZAP_API_KEY` 에 붙여넣기  

**변경 후 ZAP 을 완전히 재시작해야 적용됩니다.**

### 2. 한글 인코딩 설정 (.ZAP_JVM.properties)

ZAP 결과 JSON 에서 한글이 깨지는 경우, ZAP 설치 경로의 `ZAP_JVM.properties` 파일을 열어 다음 줄을 추가합니다:

```
-Dfile.encoding=UTF-8
```

파일 위치 예시 (Windows):
```
C:\Program Files\ZAP\Zed Attack Proxy\ZAP_JVM.properties
```

> **⚠️ 반드시 ZAP 을 재시작해야 적용됩니다.** 저장 후 ZAP 을 완전히 종료 후 다시 시작하세요.

### 3. AJAX Spider 브라우저 설정

`Tools > Options > Ajax Spider > Browser`: **Chrome Headless** 선택  
(코드에서 `chrome-headless` 로 하드코딩되어 있으므로 Firefox 는 동작 안 함)

---

## 🔬 스캔 실행 — 두 가지 경로

### 경로 A: 독립 검증 스크립트 (Postgres/Redis/Celery 불필요)

`scanners.param_manipulation.engine.run_scan` (Phase 1~4 파이프라인)을 직접 호출한다.
외부 서비스 없이 ZAP 만 있으면 바로 검증 가능.

```bash
# 기본 실행
poetry run python verify_scan.py --url https://target.com

# 인증이 필요한 경우
poetry run python verify_scan.py \
  --url https://target.com \
  --auth "Bearer YOUR_TOKEN" \
  --verbose

# SPA 와 백엔드 API 가 분리된 경우 (Swagger/OpenAPI 스펙 스캔 모드)
poetry run python verify_scan.py \
  --url https://frontend.com \
  --api-base https://api.backend.com \
  --auth "Bearer YOUR_TOKEN"
```

스크립트가 자동으로 수행하는 사전 체크:
- ZAP REST API 접근 가능 여부 (Phase 1 크롤링이 이 ZAP 데몬을 사용)
- AJAX Spider 브라우저 (chrome-headless) 확인

### 경로 B: 전체 FastAPI + Celery 파이프라인

```bash
# 1. FastAPI 서버
poetry run uvicorn argus.api.main:app --reload

# 2. Celery Worker (별도 터미널)
poetry run celery -A argus.core.celery_app worker --loglevel=info

# 3. API 호출로 스캔 요청
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://target.com"}'
```

---

## ✅ 결과 확인 체크리스트

### GENERIC_ERROR 만 나오는 경우

| 증상 | 확인 사항 |
|------|-----------|
| Alert 가 모두 `GENERIC_ERROR` | ZAP Scripts 탭 → `ArgusParamDiff` 가 `enabled=true` 인지 확인 |
| `ArgusParamDiff` 가 목록에 없음 | `zap.py` 의 `setup_parameter_tampering_policy()` 가 호출됐는지 로그 확인 |
| `CATEGORY_CONFIG = null` | `parameter_diff_scan.generated.js` 에 `__ARGUS_PAYLOAD_DIR__` 가 그대로 남아있는지 확인 |

### 한글 깨짐 재확인

1. `ZAP_JVM.properties` 에 `-Dfile.encoding=UTF-8` 추가 여부 확인
2. ZAP 완전 재시작 여부 확인 (단순 설정 저장 → 재시작 아님)
3. `results/` 폴더의 JSON 파일을 UTF-8 로 열어서 한글 확인

### High Risk 0건일 때 의심 포인트

| 경우 | 원인 |
|------|------|
| 사이트 트리가 비어 있음 | 대상 URL 자체에 접근 실패 (방화벽/프록시 문제) |
| Spider 결과가 1~2건 | SPA 이므로 OpenAPI 스펙 경로 직접 확인 후 `--api-base` 사용 |
| Alert 은 있지만 pluginId `40008` 없음 | 스캔 정책에서 40008 이 꺼져 있음 → `setup_parameter_tampering_policy()` 재실행 |
| 파라미터가 있는데 silent 알림도 없음 | 파라미터명이 FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW 패턴과 불일치 → `payloads/*.yaml` 의 `field_name_patterns` 확인 |

---

## 🔄 플랫폼 전체 진단 파이프라인 흐름 (Workflow Sequence)
