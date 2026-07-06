# 1-5 검증되지 않은 리다이렉트와 포워드 — Reflected 전용 스캔 엔진

> SK Shieldus 2022 Web/API 개발보안 Guideline v3.0.0 / 항목 1-5
> 범위: **Reflected 케이스만.** 파라미터 값이 같은 요청/응답 왕복 안에서 검증 없이
> 그대로 Location 헤더 또는 클라이언트 사이드 리다이렉트 코드에 반영되는 경우만 자동 진단한다.
> Stored 케이스(가입/설정 등으로 저장된 리다이렉트 대상이 이후 다른 요청에서 실행되는 경우)는
> 별도의 생성→저장 확인→트리거 흐름이 필요해 범위 밖 (1-3의 `verifier.py`류 후속 검증 모듈로 확장 가능).
>
> 가이드 예제: `http://ooo.com/redirect.jsp?returl=evil.com`

---

## 1. 디렉토리 구조

```
ARGUS_Backend/
└── scanners/
    └── redirect_forward/            # 1-5 전용 스캔 엔진 패키지
        ├── __init__.py
        ├── models.py                 # RedirectCandidate, RedirectFinding
        ├── candidates.py              # Phase 2: 이름 규칙 기반 후보 파라미터 선별
        ├── payloads.py                # 외부 목적지 + 화이트리스트 우회 페이로드
        ├── detector.py                # Phase 3: 페이로드 주입 + Reflected 판별
        └── engine.py                  # run_redirect_scan() 오케스트레이터

argus/
├── worker/tasks.py                   # run_redirect_scan_task (Celery)
└── api/v1/
    ├── api.py                        # /api/v1/scan-redirect 라우터 등록
    └── endpoints/redirect_scan.py     # 트리거(POST) / 조회(GET) 엔드포인트
```

Phase 1(파라미터 수집)은 1-3 스캔 엔진(`scanners.param_manipulation.collector.collect_params`)이
이미 구현한 ZAP Ajax Spider + Swagger Spec 파싱 자산을 그대로 재사용한다 — 별도 크롤러를
새로 만들지 않는다.

---

## 2. 파이프라인

| Phase | 파일 | 역할 |
|---|---|---|
| 1 | `param_manipulation/collector.py` (재사용) | ZAP Ajax Spider + Swagger Spec으로 전체 파라미터 수집 |
| 2 | `candidates.py` | `return/redirect/next/forward/callback/goto` 등 이름 규칙으로 리다이렉트 후보만 선별 (LLM 미사용) |
| 3 | `detector.py` | 후보마다 `payloads.py`의 외부 목적지를 주입 → `allow_redirects=False`로 요청 → 같은 응답 안에서 반영 여부 판정 |

판정은 결정적 규칙(문자열 반영 여부)만으로 이뤄지므로 1-3과 달리 LLM 해석(Phase 4) 단계가 없다.

### 판별 기준 (`detector.py`)

| detection_type | 조건 | severity |
|---|---|---|
| `LOCATION_HEADER` | 3xx 응답의 `Location` 헤더에 payload host가 그대로 노출 (서버 사이드) | HIGH |
| `META_REFRESH` | 200 응답 본문의 `<meta http-equiv="refresh" ... url=...>`에 노출 | MEDIUM |
| `JS_REDIRECT` | 200 응답 본문의 `location.href` / `location.replace()` / `.assign()` 대입문에 노출 | MEDIUM |

---

## 3. CLI 실행 방법

### 사전 준비

1-3과 동일한 ZAP 데몬을 Phase 1에서 그대로 사용한다 (README의 "ZAP 설정" 항목 참고).

```bash
# ZAP이 8090 포트로 떠 있는지 확인
curl -s "http://127.0.0.1:8090/JSON/core/view/version/" | head
```

### 경로 A — 독립 실행 (Postgres/Redis/Celery 불필요)

`scanners.redirect_forward.engine.run_redirect_scan`을 직접 호출해 빠르게 검증한다.

```bash
poetry run python - <<'EOF'
from scanners.redirect_forward.engine import run_redirect_scan

def progress(phase, pct):
    print(f"[{phase}] {pct}%", end="\r", flush=True)

findings = run_redirect_scan(
    target_url="https://target.com",          # 진단 대상 (필수)
    custom_header="Authorization: Bearer YOUR_TOKEN",  # 인증 필요 시, 없으면 None
    # api_base_url="https://api.target.com",  # SPA/API 서버 분리 시 Swagger 병행 수집
    # payload_host="argus-unvalidated-redirect-poc.invalid",  # 오탐 시 다른 값으로 변경
    progress_callback=progress,
)
print()

print(f"\n확정 Reflected findings: {len(findings)}건 "
      f"(HIGH: {sum(1 for f in findings if f.severity == 'HIGH')})")
for f in findings:
    print(f"\n[{f.severity}] {f.detection_type}")
    print(f"  {f.method} {f.url}")
    print(f"  param: {f.param_name} = {f.payload_used!r}")
    print(f"  evidence: {f.evidence[:200]}")
EOF
```

### 경로 B — 전체 FastAPI + Celery 파이프라인

```bash
# 1. FastAPI 서버 (기본 8085 포트, run.py 기준)
poetry run python run.py
# 또는: poetry run uvicorn argus.api.main:app --host 0.0.0.0 --port 8085 --reload

# 2. Celery Worker (별도 터미널)
poetry run celery -A argus.core.celery_app worker --loglevel=info

# 3. 스캔 트리거
curl -X POST http://localhost:8085/api/v1/scan-redirect/ \
  -H "Content-Type: application/json" \
  -d '{
        "target_url": "https://target.com",
        "custom_header": "Authorization: Bearer YOUR_TOKEN"
      }'
# → {"message": "...", "task_id": "<TASK_ID>"}

# 4. 결과 폴링 (task_id는 위 응답에서 받은 값으로 치환)
curl http://localhost:8085/api/v1/scan-redirect/<TASK_ID>
```

`state`가 `SUCCESS`가 되면 응답의 `result.results.findings`에서 확정 항목을,
`result.result_json_path`에서 저장된 JSON 파일 경로를 확인한다.

---

## 4. 결과 파일

Celery 경로(B) 실행 시 `results/` 아래에 저장된다 (`.env`의 `SCAN_RESULTS_DIR` 기준).

| 파일 | 내용 |
|---|---|
| `results/{task_id}_redirect.json` | 확정 Reflected findings 전체 |
| `results/{task_id}_redirect_coverage.json` | 후보로 선정돼 Phase 3까지 넘어간 파라미터 전체 목록 (이상 유무 무관 — "시도됐지만 없음"과 "애초에 후보로도 안 잡힘"을 구분) |

---

## 5. 주의사항 / 한계

- `payload_host`(기본값 `argus-unvalidated-redirect-poc.invalid`)가 대상 서비스의 실제 도메인과
  우연히 겹치면 오탐이 생기므로, 사내망 등 특수한 환경에서는 다른 값으로 지정할 것.
- `candidates.py`의 `host`, `out`, `ref` 같은 느슨한 이름 패턴은 리다이렉트와 무관한 파라미터도
  후보로 잡을 수 있다 — 대상 서비스의 실제 파라미터 목록을 보고 필요하면 정규식을 좁힐 것.
- `META_REFRESH` / `JS_REDIRECT`는 정적 문자열 매칭이라 실제 브라우저 렌더링/실행 여부까지는
  보장하지 않는다 — HIGH(`LOCATION_HEADER`)보다 신뢰도가 낮아 severity를 MEDIUM으로 낮춰뒀다.
  최종 확인은 Selenium 재현 단계에서 권장.
- Stored 케이스(마이페이지 리다이렉트 설정, 이메일 인증 링크 등)는 이 모듈이 다루지 않는다.
