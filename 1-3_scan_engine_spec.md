# 1-3 파라미터 값 및 히든 필드 조작 가능성 — 스캔 엔진 구현 명세

> SK Shieldus 2022 Web/API 개발보안 Guideline v3.0.0 / 항목 1-3  
> 범위: 스캔 엔진 단계 (ZAP 수집 → Claude 분류 → 조작 테스트 → 이상 탐지)  
> 다음 단계: Selenium 증적 캡처 → 보고서 생성 (별도 모듈)

---

## 1. 디렉토리 구조

```
ARGUS_Backend/
└── scanners/
    └── param_manipulation/          # 1-3 전용 스캔 엔진 패키지
        ├── __init__.py
        ├── collector.py             # Phase 1: ZAP Ajax Spider 수집
        ├── classifier.py            # Phase 2: Claude API 파라미터 분류
        ├── manipulator.py           # Phase 3: 카테고리별 페이로드 주입
        ├── comparator.py            # Phase 4: 응답 이상 탐지
        ├── engine.py                # 전체 파이프라인 오케스트레이터
        ├── models.py                # 공유 데이터 모델 (dataclass)
        └── payloads.py              # 카테고리별 페이로드 상수 정의
```

---

## 2. 공유 데이터 모델 (`models.py`)

파이프라인 전 단계가 공유하는 데이터 구조를 먼저 정의합니다.

```python
# models.py
from dataclasses import dataclass, field
from typing import Any

@dataclass
class CollectedParam:
    """ZAP이 수집한 파라미터 단위"""
    url: str
    method: str           # GET / POST / PUT / PATCH / DELETE
    param_name: str
    param_value: str
    param_type: str       # "query" | "body" | "hidden"
    content_type: str     # application/json, application/x-www-form-urlencoded 등

@dataclass
class ClassifiedParam:
    """Claude API가 분류한 파라미터"""
    collected: CollectedParam
    category: str         # PRICE | PRIVILEGE | IDOR | HIDDEN | SAFE
    reason: str           # 분류 근거 (Claude 응답)

@dataclass
class Finding:
    """이상 탐지 결과 단위 — 다음 단계(Selenium)로 전달"""
    url: str
    method: str
    param_name: str
    category: str
    payload_used: str
    payload_description: str
    baseline_status: int
    test_status: int
    anomaly_type: str     # PRIVILEGE_BYPASS | POTENTIAL_IDOR | DATA_EXPOSURE | ERROR_SUPPRESSED
    anomaly_detail: str
    baseline_body: str    # Selenium 재현용 원본 응답 보존
    test_body: str        # Selenium 재현용 조작 응답 보존
    severity: str         # HIGH | MEDIUM
```

---

## 3. Phase 1 — ZAP Ajax Spider 수집 (`collector.py`)

### 역할
- ZAP Docker 컨테이너에 Ajax Spider를 실행해 대상 URL을 크롤링
- 수집된 모든 HTTP 메시지에서 파라미터를 추출
- `<input type="hidden">` 포함 (ZAP이 HTML 파싱 시 자동 수집)

### 구현 포인트

```python
# collector.py
import time
from zapv2 import ZAPv2
from urllib.parse import urlparse, parse_qs
import json
from .models import CollectedParam

ZAP_API_KEY = "argus-zap-key"   # docker-compose 환경변수로 주입
ZAP_PROXY  = "http://localhost:8090"

def collect_params(target_url: str) -> list[CollectedParam]:
    zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

    # ── Ajax Spider 실행 ──────────────────────────────────────────
    scan_id = zap.ajaxSpider.scan(target_url)
    while zap.ajaxSpider.status == "running":
        time.sleep(2)

    # ── 수집된 메시지에서 파라미터 추출 ──────────────────────────
    results: list[CollectedParam] = []
    for msg in zap.core.messages(baseurl=target_url, start=0, count=500):
        req_header = msg.get("requestHeader", "")
        req_body   = msg.get("requestBody", "")
        method     = req_header.split(" ")[0] if req_header else "GET"
        raw_url    = req_header.split(" ")[1] if len(req_header.split(" ")) > 1 else target_url
        content_type = _extract_content_type(req_header)

        # Query string 파라미터
        parsed = urlparse(raw_url)
        for key, values in parse_qs(parsed.query).items():
            results.append(CollectedParam(
                url=raw_url, method=method,
                param_name=key, param_value=values[0],
                param_type="query", content_type=content_type,
            ))

        # Body 파라미터 (JSON / form-urlencoded)
        results.extend(_parse_body_params(raw_url, method, req_body, content_type))

    return results


def _parse_body_params(url, method, body, content_type) -> list[CollectedParam]:
    params = []
    if not body:
        return params

    if "application/json" in content_type:
        try:
            data = json.loads(body)
            for key, val in _flatten_json(data):
                params.append(CollectedParam(
                    url=url, method=method,
                    param_name=key, param_value=str(val),
                    param_type="body", content_type=content_type,
                ))
        except json.JSONDecodeError:
            pass

    elif "application/x-www-form-urlencoded" in content_type:
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.append(CollectedParam(
                    url=url, method=method,
                    param_name=k, param_value=v,
                    param_type="body", content_type=content_type,
                ))

    return params


def _flatten_json(obj, prefix="") -> list[tuple[str, Any]]:
    """중첩 JSON을 dot-notation 키로 평탄화"""
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            items.extend(_flatten_json(v, full_key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_flatten_json(v, f"{prefix}[{i}]"))
    else:
        items.append((prefix, obj))
    return items


def _extract_content_type(header: str) -> str:
    for line in header.splitlines():
        if line.lower().startswith("content-type:"):
            return line.split(":", 1)[1].strip().lower()
    return ""
```

### 주의사항
- ZAP이 로그인 벽 뒤 페이지를 크롤링하려면 세션 쿠키를 Context에 주입해야 함
  - 인증이 필요한 경우: `zap.context` API로 Context 생성 후 세션 추가
  - 현재 단계에서는 인증 없는 공개 파라미터만 수집 (범용 플랫폼 기본 동작)
- hidden 필드는 ZAP Ajax Spider가 HTML 렌더링 시 자동 포함됨 — 별도 처리 불필요

---

## 4. Phase 2 — Claude API 파라미터 분류 (`classifier.py`)

### 역할
- Phase 1에서 수집된 파라미터 목록을 Claude API에 전달
- 파라미터 이름/값/엔드포인트를 종합해 위험 카테고리 분류
- SAFE 파라미터는 이후 단계에서 제외

### 카테고리 정의

| 카테고리 | 탐지 대상 | 파라미터 예시 |
|---|---|---|
| `PRICE` | 금액/가격 조작 | price, amount, cost, fee, total, discount |
| `PRIVILEGE` | 권한 조작 | role, isAdmin, grade, permission, type, level |
| `IDOR` | 타인 자원 접근 | id, userId, memberId, orderId, boardId, no |
| `HIDDEN` | 히든 필드 전달 중요값 | hidden input의 모든 필드 |
| `SAFE` | 위험 없음 | keyword, page, sort, lang 등 |

### 구현 포인트

```python
# classifier.py
import anthropic
import json
from .models import CollectedParam, ClassifiedParam

def classify_params(params: list[CollectedParam]) -> list[ClassifiedParam]:
    if not params:
        return []

    # hidden 타입은 Claude 판단 없이 바로 HIDDEN으로 태깅
    classified = []
    to_classify = []
    for p in params:
        if p.param_type == "hidden":
            classified.append(ClassifiedParam(
                collected=p, category="HIDDEN",
                reason="HTML hidden input 필드로 전송되는 값",
            ))
        else:
            to_classify.append(p)

    if not to_classify:
        return classified

    # Claude API 호출 — 배치로 전달
    client = anthropic.Anthropic()

    param_list = [
        {"index": i, "url": p.url, "method": p.method,
         "param_name": p.param_name, "param_value": p.param_value,
         "param_type": p.param_type}
        for i, p in enumerate(to_classify)
    ]

    prompt = f"""
다음은 웹 애플리케이션에서 수집된 HTTP 파라미터 목록입니다.
각 항목을 SK Shieldus 1-3 기준(파라미터 값 및 히든 필드 조작 가능성)으로 분류하세요.

카테고리:
- PRICE: 금액·가격 조작 가능성 (price, amount, cost, fee, total, discount, point 등)
- PRIVILEGE: 권한 조작 가능성 (role, isAdmin, grade, permission, type, level, authority 등)
- IDOR: 타인 자원 접근 가능성 (id, userId, memberId, orderId, boardId, no, seq 등)
- SAFE: 위험도 낮음 (keyword, page, sort, lang, locale, theme 등)

규칙:
- param_name 기준으로 판단하되, param_value와 url도 참고
- 동일 파라미터라도 엔드포인트 맥락에 따라 다르게 분류 가능
- 반드시 JSON 배열로만 응답. 다른 텍스트 없이.

출력 형식:
[{{"index": 0, "category": "IDOR", "reason": "분류 근거"}}, ...]

입력:
{json.dumps(param_list, ensure_ascii=False)}
"""

    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    try:
        results = json.loads(resp.content[0].text)
        result_map = {r["index"]: r for r in results}
    except (json.JSONDecodeError, KeyError):
        # Claude 응답 파싱 실패 시 전부 SAFE 처리
        result_map = {}

    for i, p in enumerate(to_classify):
        r = result_map.get(i, {"category": "SAFE", "reason": "분류 실패 — SAFE 기본값"})
        classified.append(ClassifiedParam(
            collected=p,
            category=r.get("category", "SAFE"),
            reason=r.get("reason", ""),
        ))

    return classified
```

### 주의사항
- SAFE 파라미터는 `engine.py`에서 필터링해 Phase 3에 전달하지 않음
- Claude API 호출 비용 최적화를 위해 동일 엔드포인트 + 동일 param_name 중복 제거 후 배치 전달
- `to_classify` 리스트가 클 경우 50개 단위로 청크 분할 권장

---

## 5. Phase 3 — 페이로드 주입 (`manipulator.py` + `payloads.py`)

### 역할
- 분류된 카테고리별로 정해진 조작 페이로드를 파라미터에 주입
- 원본 요청을 재현한 뒤 파라미터 값만 교체해서 요청 전송
- 원본 응답(baseline)과 조작 응답을 함께 반환

### 페이로드 정의 (`payloads.py`)

```python
# payloads.py
# (payload_value, description) 튜플 리스트

PAYLOADS = {
    "PRICE": [
        ("1",          "1원으로 변조"),
        ("0",          "0원 변조"),
        ("-1",         "음수 금액 변조"),
        ("-9999",      "극소 음수 변조"),
        ("99999999",   "극대값 변조"),
        ("0.001",      "소수점 극소값"),
    ],
    "PRIVILEGE": [
        ("ADMIN",       "ADMIN 권한 주입"),
        ("SUPER_ADMIN", "SUPER_ADMIN 권한 주입"),
        ("admin",       "소문자 admin 주입"),
        ("true",        "boolean true 권한 플래그"),
        ("1",           "숫자형 권한 플래그"),
        ("0",           "권한 비활성화 시도"),
    ],
    "IDOR": [
        # 원본 ID 값을 기준으로 engine.py에서 동적 생성
        # ±1, ±10, 0, 9999999 등
    ],
    "HIDDEN": [
        ("1",          "hidden 금액 1원 변조"),
        ("ADMIN",      "hidden 권한 변조"),
        ("true",       "hidden 플래그 변조"),
        ("../etc",     "hidden 경로 변조 시도"),
        ("0",          "hidden 0값 변조"),
    ],
}
```

### 구현 포인트 (`manipulator.py`)

```python
# manipulator.py
import requests
import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from .models import ClassifiedParam
from .payloads import PAYLOADS

TIMEOUT = 10  # 초

def run_manipulation(param: ClassifiedParam) -> list[dict]:
    """
    단일 ClassifiedParam에 대해 페이로드를 주입하고
    (baseline_resp, test_resp, payload_info) 튜플 리스트 반환
    """
    c = param.collected
    payloads = _get_payloads(param)
    if not payloads:
        return []

    baseline_resp = _send_request(c.url, c.method, c.param_name,
                                   c.param_value, c.content_type)
    results = []
    for payload_val, payload_desc in payloads:
        test_resp = _send_request(c.url, c.method, c.param_name,
                                   payload_val, c.content_type)
        results.append({
            "param": param,
            "payload_value": payload_val,
            "payload_description": payload_desc,
            "baseline": baseline_resp,
            "test": test_resp,
        })

    return results


def _get_payloads(param: ClassifiedParam) -> list[tuple]:
    if param.category == "IDOR":
        # 원본 ID 값 기준으로 동적 생성
        try:
            base_id = int(param.collected.param_value)
            return [
                (str(base_id - 1), f"ID {base_id-1} (원본-1)"),
                (str(base_id + 1), f"ID {base_id+1} (원본+1)"),
                (str(base_id + 10), f"ID {base_id+10} (원본+10)"),
                ("0",              "ID 0 (경계값)"),
                ("9999999",        "ID 극대값"),
            ]
        except (ValueError, TypeError):
            return []
    return PAYLOADS.get(param.category, [])


def _send_request(url: str, method: str, param_name: str,
                   param_value: str, content_type: str) -> dict:
    """파라미터 값을 교체한 요청을 전송하고 응답 반환"""
    try:
        if "json" in content_type:
            body = {param_name: param_value}
            resp = requests.request(
                method, url, json=body, timeout=TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
        elif "x-www-form-urlencoded" in content_type:
            resp = requests.request(
                method, url, data={param_name: param_value}, timeout=TIMEOUT,
            )
        else:
            # Query string
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param_name] = [param_value]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            resp = requests.request(method, new_url, timeout=TIMEOUT)

        return {
            "status": resp.status_code,
            "body": resp.text,
            "headers": dict(resp.headers),
        }
    except requests.RequestException as e:
        return {"status": -1, "body": str(e), "headers": {}}
```

### 주의사항
- 실제 서비스에 영향을 줄 수 있는 POST/PUT/DELETE는 페이로드 주입 전 사용자 확인 필요
- IDOR 탐지 시 `param_value`가 정수형이 아닐 경우 페이로드 생성 건너뜀

---

## 6. Phase 4 — 응답 이상 탐지 (`comparator.py`)

### 역할
- baseline(원본 응답)과 test(조작 응답)를 비교
- 4가지 이상 패턴 탐지 후 `Finding` 생성
- 이상 없으면 `None` 반환 (engine.py에서 필터링)

### 이상 탐지 패턴

| anomaly_type | 판단 기준 | 의미 |
|---|---|---|
| `PRIVILEGE_BYPASS` | baseline 401/403 → test 200 | 권한 없는 요청이 조작 후 성공 |
| `POTENTIAL_IDOR` | test 200 + body 크기 500byte 이상 증가 | 타인 데이터가 응답에 포함된 것으로 추정 |
| `DATA_EXPOSURE` | test 응답에 baseline에 없던 JSON 키 출현 | 노출되면 안 되는 필드가 새로 반환 |
| `ERROR_SUPPRESSED` | baseline 에러 키워드 있음 → test 없음 | 서버가 조작값을 정상으로 수용 |

### 구현 포인트

```python
# comparator.py
import json
from .models import Finding, ClassifiedParam

ERROR_KEYWORDS = ["error", "invalid", "denied", "forbidden",
                   "unauthorized", "exception", "fail"]

def detect_anomaly(
    param: ClassifiedParam,
    payload_value: str,
    payload_desc: str,
    baseline: dict,
    test: dict,
) -> Finding | None:

    c = param.collected
    anomaly_type = None
    anomaly_detail = None

    # 패턴 1: 권한 우회
    if baseline["status"] in (401, 403) and test["status"] == 200:
        anomaly_type = "PRIVILEGE_BYPASS"
        anomaly_detail = (f"원본 응답 {baseline['status']} → "
                          f"조작 후 200 OK (권한 검증 우회 가능성)")

    # 패턴 2: IDOR — 응답 크기 급증
    elif (test["status"] == 200
          and len(test["body"]) - len(baseline["body"]) > 500):
        anomaly_type = "POTENTIAL_IDOR"
        diff = len(test["body"]) - len(baseline["body"])
        anomaly_detail = f"응답 크기 {diff}byte 증가 — 타인 자원 노출 가능성"

    # 패턴 3: 새로운 JSON 키 출현
    else:
        new_keys = _detect_new_json_keys(baseline["body"], test["body"])
        if new_keys and test["status"] == 200:
            anomaly_type = "DATA_EXPOSURE"
            anomaly_detail = f"조작 후 신규 응답 필드 출현: {new_keys}"

    # 패턴 4: 에러 사라짐
    if anomaly_type is None:
        baseline_has_error = _has_error(baseline["body"])
        test_has_error = _has_error(test["body"])
        if baseline_has_error and not test_has_error and test["status"] == 200:
            anomaly_type = "ERROR_SUPPRESSED"
            anomaly_detail = "에러 응답이 조작 후 사라짐 — 서버가 조작값을 수용한 것으로 추정"

    if anomaly_type is None:
        return None

    return Finding(
        url=c.url,
        method=c.method,
        param_name=c.param_name,
        category=param.category,
        payload_used=payload_value,
        payload_description=payload_desc,
        baseline_status=baseline["status"],
        test_status=test["status"],
        anomaly_type=anomaly_type,
        anomaly_detail=anomaly_detail,
        baseline_body=baseline["body"],
        test_body=test["body"],
        severity="HIGH",
    )


def _detect_new_json_keys(baseline_body: str, test_body: str) -> list[str]:
    try:
        base_keys = set(_extract_all_keys(json.loads(baseline_body)))
        test_keys = set(_extract_all_keys(json.loads(test_body)))
        return list(test_keys - base_keys)
    except (json.JSONDecodeError, TypeError):
        return []


def _extract_all_keys(obj, prefix="") -> list[str]:
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.append(full)
            keys.extend(_extract_all_keys(v, full))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_extract_all_keys(item, prefix))
    return keys


def _has_error(body: str) -> bool:
    body_lower = body.lower()
    return any(kw in body_lower for kw in ERROR_KEYWORDS)
```

---

## 7. 파이프라인 오케스트레이터 (`engine.py`)

### 역할
- Phase 1~4를 순서대로 실행
- 각 단계 결과를 다음 단계로 전달
- 최종 `findings[]` 리스트를 반환 → Selenium 모듈로 전달

```python
# engine.py
import logging
from .collector   import collect_params
from .classifier  import classify_params
from .manipulator import run_manipulation
from .comparator  import detect_anomaly
from .models      import Finding

logger = logging.getLogger(__name__)


def run_scan(target_url: str) -> list[Finding]:
    """
    1-3 스캔 엔진 진입점.
    target_url만 받아 findings[]를 반환.
    """
    findings: list[Finding] = []

    # ── Phase 1: ZAP 수집 ───────────────────────────────────────
    logger.info(f"[Phase 1] ZAP Ajax Spider 시작: {target_url}")
    collected = collect_params(target_url)
    logger.info(f"[Phase 1] 수집된 파라미터 수: {len(collected)}")

    if not collected:
        logger.warning("[Phase 1] 수집된 파라미터 없음 — 종료")
        return findings

    # ── Phase 2: Claude 분류 ────────────────────────────────────
    logger.info("[Phase 2] Claude API 파라미터 분류 시작")
    classified = classify_params(collected)

    # SAFE 제외
    candidates = [p for p in classified if p.category != "SAFE"]
    logger.info(f"[Phase 2] 위험 파라미터 수 (SAFE 제외): {len(candidates)}")

    if not candidates:
        logger.info("[Phase 2] 위험 파라미터 없음 — 종료")
        return findings

    # ── Phase 3 + 4: 조작 테스트 & 이상 탐지 ───────────────────
    logger.info("[Phase 3/4] 페이로드 주입 및 이상 탐지 시작")
    for param in candidates:
        manipulation_results = run_manipulation(param)
        for result in manipulation_results:
            finding = detect_anomaly(
                param=result["param"],
                payload_value=result["payload_value"],
                payload_desc=result["payload_description"],
                baseline=result["baseline"],
                test=result["test"],
            )
            if finding:
                findings.append(finding)
                logger.info(
                    f"[Finding] {finding.anomaly_type} | "
                    f"{finding.url} | {finding.param_name}={finding.payload_used}"
                )

    logger.info(f"[완료] 총 findings: {len(findings)}건")
    return findings
```

---

## 8. 외부 연동 인터페이스

### Selenium 모듈로 전달되는 데이터 형식

`engine.run_scan(target_url)` 반환값인 `list[Finding]`을 그대로 Selenium 모듈에 전달합니다.

```python
# 호출 예시 (FastAPI 엔드포인트 또는 Celery task에서)
from scanners.param_manipulation.engine import run_scan

findings = run_scan("https://target.example.com")

# Selenium으로 전달
for f in findings:
    selenium_capture(
        url=f.url,
        method=f.method,
        param_name=f.param_name,
        payload=f.payload_used,
        anomaly_type=f.anomaly_type,
        evidence_body=f.test_body,   # 응답 재현용
    )
```

### Finding → 보고서 매핑

| Finding 필드 | 보고서 항목 |
|---|---|
| `anomaly_type` | 취약점 유형 |
| `url` + `method` | 관련 URL / 엔드포인트 |
| `param_name` | 파라미터 |
| `payload_used` | 공격 페이로드 |
| `anomaly_detail` | 현황 설명 |
| `baseline_status` / `test_status` | HTTP 상태코드 비교 증거 |
| `severity` | 중요도 |

---

## 9. 구현 순서 권장

1. `models.py` — 데이터 클래스 정의
2. `payloads.py` — 페이로드 상수 정의
3. `collector.py` — ZAP 연동 테스트 (DVWA 대상)
4. `classifier.py` — Claude API 분류 테스트 (Mock 파라미터 목록으로)
5. `comparator.py` — 이상 탐지 로직 단위 테스트
6. `manipulator.py` — 페이로드 주입 + comparator 연동
7. `engine.py` — 전체 파이프라인 통합 테스트

---

## 10. 환경 설정

```bash
# 의존성
pip install zapv2 anthropic requests

# ZAP Docker 실행
docker run -d --name zap \
  -p 8090:8090 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.key=argus-zap-key

# 환경변수
ZAP_API_KEY=argus-zap-key
ZAP_PROXY=http://localhost:8090
ANTHROPIC_API_KEY=sk-ant-...
```
