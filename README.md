# Argus: AI 기반 통합 보안 자동 진단 시스템 (Backend)

본 프로젝트는 중소기업 및 스타트업을 위한 범용 웹 취약점 진단 플랫폼 **Argus**의 백엔드 시스템입니다.

## 🛠️ 기술 스택
- **API & Control Plane:** Python (FastAPI), SQLModel, PostgreSQL, Redis, Celery
- **Scan Engine:** OWASP ZAP (Docker REST API), Semgrep (SAST), SSL Labs API, Selenium Headless (증적 Replay)
- **AI & Report:** OpenAI API (Reachability 분석 및 맞춤형 가이드), WeasyPrint (한글 PDF 생성)

---

## 📂 폴더 구조 및 팀별 역할 분담

### 1. [공통/공유] `api_control/` (전체 팀 공동 사용)
- 플랫폼의 전체적인 진입점 역할을 수행하며, 사용자 요청을 받아 비동기 큐에 할당하고 이력을 기록하는 제어 레이어(Control Plane)입니다. 모든 팀이 공동으로 관리하고 참조합니다.
  - `main.py`: FastAPI 엔트리포인트
  - `models.py`: PostgreSQL DB 테이블 모델링
  - `queue.py`: Celery 비동기 작업 큐 발행기

### 2. [A팀 - 3명] `scan_engines/` (Core Scan & AI Priority Engines)
- Celery Worker 환경에서 3가지 핵심 스캐너 도구를 실제로 구동하고 결과를 파싱하며, AI(LLM) API를 연동하여 스캔한 취약점의 위험도 우선순위를 산정하고 한글 설명 가이드를 생성합니다.
  - `tasks.py`: Celery 비동기 태스크 모음
  - `zap_engine.py` / `semgrep_engine.py` / `ssl_engine.py`: 스캐너 모듈
  - `ai_advisor.py`: AI 조치 가이드 및 우선순위 생성 모듈

### 3. [B팀 - 2명] `selenium_capture/` (Evidence Capturer)
- 진단 결과에 대하여 Selenium Headless를 통해 스캔 및 Replay하여 화면에 대한 자동 증적을 캡처하는 전담 팀 모듈입니다.
  - `selenium_engine.py`: Replay - Headless Browser를 이용한 공격 재현 및 스크린샷 캡처

### 4. [C팀 - 2명] `intelligence_report/` (AI Analysis & PDF Report Builder)
- 오탐률을 줄이기 위한 Reachability 교차 검증을 수행하고, 축적된 데이터를 모아 WeasyPrint로 최종 한글 PDF 보고서를 만듭니다.
  - `check_reachability.py`: 코드(SAST)와 주소(DAST) 매핑으로 오탐 교차 검증
  - `report_generator.py`: WeasyPrint 기반 PDF/HTML 레포트 빌더

---

## 🔄 플랫폼 전체 진단 파이프라인 흐름 (Workflow Sequence)

플랫폼의 전체적인 취약점 진단 및 리포트 생성 프로세스는 다음과 같은 순서로 유기적으로 수행됩니다.

```mermaid
graph TD
    A[1. 스캔 단계: scan_engines] -->|진단 결과 도출| B[2. 캡처 단계: selenium_capture]
    B -->|공격 재현 스크린샷 확보| C[3. 보고서 단계: intelligence_report]
    C -->|AI 오탐 교차검증 & PDF 렌더링| D[4. 최종 진단 보고서 완료]
```

1. **스캔 및 AI 우선순위 단계 (`scan_engines` - A팀):**
   - 사용자가 요청한 웹 사이트에 대하여 ZAP(동적), Semgrep(정적), SSL Labs를 통해 취약점 진단을 수행한 후, **AI(LLM) API를 사용하여 각 취약점의 위험도 우선순위를 지정하고 한글 설명 가이드를 생성**합니다.
2. **캡처 단계 (`selenium_capture` - B팀):**
   - 1단계 결과에서 검출된 주요 취약점들을 바탕으로 Selenium Headless 브라우저를 구동하여 실제 공격 시나리오를 Replay하고 증적 스크린샷 화면을 캡처합니다.
3. **보고서 및 검증 단계 (`intelligence_report` - C팀):**
   - 앞서 확보한 진단 데이터와 캡처된 증적 화면들을 종합하여 Reachability 교차 검증을 통해 오탐을 걸러내고, 최종적으로 WeasyPrint를 활용해 한글 PDF 리포트를 빌드합니다.

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

**FastAPI 웹 서버 (C팀):**
```bash
poetry run uvicorn api_control.main:app --reload
```

**Celery Worker 실행 (A팀/B팀):**
```bash
poetry run celery -A scan_engines.tasks worker --loglevel=info
```
