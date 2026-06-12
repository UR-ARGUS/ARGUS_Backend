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

### 1. 의존성 설치
```bash
poetry install
```

### 2. 환경 변수 설정
루트 디렉토리에 `.env` 파일을 생성하고 필요한 설정값을 입력합니다:
```env
DATABASE_URL=postgresql://user:password@localhost:5432/argus
REDIS_URL=redis://localhost:6379/0
OPENAI_API_KEY=your_openai_api_key_here
```

### 3. 서비스 실행

**FastAPI 웹 서버 실행:**
```bash
poetry run uvicorn argus.api.main:app --reload
```

**Celery Worker 실행:**
```bash
poetry run celery -A argus.core.celery_app worker --loglevel=info
```
