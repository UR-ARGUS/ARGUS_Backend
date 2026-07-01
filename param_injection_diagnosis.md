# 파라미터 값 및 히든 필드 조작 자동 진단 모듈 (1-3)

> SK Shieldus Web/API 개발보안 Guideline v3.0.0 — 1-3 항목 대응  
> 자동화 플랫폼 DAST 모듈 구현 명세서

---

## 개요

본 모듈은 진단 대상 URL 하나만 입력받아 아래 흐름을 자동으로 수행한다.

```
진단 대상 URL 입력
    ↓
ZAP AJAX Spider → 파라미터 / 히든 필드 자동 수집
    ↓
시그니처 분류기 → 필드를 위험 카테고리로 분류
    ↓
카테고리별 공통 페이로드 템플릿 자동 매핑
    ↓
인젝터 실행 → 응답 차이 수집
    ↓
Claude API → 비즈니스 로직 취약 여부 판단
    ↓
결과 반환 (JSON)
```

---

## 디렉토리 구조

```
param_injection/
├── main.py                  # 진단 실행 진입점
├── zap_crawler.py           # ZAP 크롤링 및 파라미터 수집
├── signature_classifier.py  # 시그니처 기반 필드 분류기
├── injector.py              # 페이로드 인젝터
├── analyzer.py              # Claude API 응답 분석기
├── payloads/
│   ├── FINANCIAL.yaml       # 금액/가격 관련 페이로드
│   ├── AUTHORIZATION.yaml   # 권한/역할 관련 페이로드
│   ├── IDOR.yaml            # 객체 직접 참조 관련 페이로드
│   ├── LOGIC_FLOW.yaml      # 상태값/플로우 관련 페이로드
│   └── DEFAULT.yaml         # 분류 불가 필드용 기본 페이로드
└── results/
    └── {timestamp}_result.json
```

---

## Step 1. ZAP 크롤링 — `zap_crawler.py`

ZAP AJAX Spider로 대상 URL을 크롤링하여 모든 파라미터와 히든 필드를 수집한다.

### 구현 명세

```python
"""
zap_crawler.py

역할:
    - ZAP AJAX Spider로 대상 URL 크롤링
    - 수집된 모든 요청에서 파라미터 및 히든 필드 추출
    - 반환 형식: List[FieldInfo]

의존성:
    - zapv2 (pip install python-owasp-zap-v2.4)
    - ZAP 데몬이 localhost:8080에서 실행 중이어야 함

반환 타입:
    List[FieldInfo] = [
        {
            "url": "https://target.com/api/v1/auth/signup",
            "method": "POST",
            "field_name": "role",
            "field_type": "body_param",   # body_param | query_param | hidden_field | cookie
            "original_value": "USER",
            "source": "zap_spider"
        },
        ...
    ]
"""

from zapv2 import ZAPv2
import time

ZAP_API_KEY = "your-zap-api-key"
ZAP_PROXY  = "http://localhost:8080"

def crawl_and_collect(target_url: str, wait_seconds: int = 30) -> list[dict]:
    """
    대상 URL을 ZAP AJAX Spider로 크롤링하고
    발견된 모든 파라미터/히든 필드 목록을 반환한다.

    Args:
        target_url:    진단 대상 URL
        wait_seconds:  크롤링 완료 대기 시간 (초)

    Returns:
        List[FieldInfo]
    """
    zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

    # 1. AJAX Spider 실행
    zap.ajaxSpider.scan(target_url)
    time.sleep(wait_seconds)
    zap.ajaxSpider.stop()

    # 2. 수집된 요청에서 파라미터 추출
    fields = []
    messages = zap.core.messages(baseurl=target_url)

    for msg in messages:
        request_header = msg.get("requestHeader", "")
        request_body   = msg.get("requestBody", "")
        url            = extract_url(request_header)
        method         = extract_method(request_header)

        # Query string 파라미터
        for name, value in parse_query_params(url):
            fields.append(build_field(url, method, name, value, "query_param"))

        # Body 파라미터 (JSON / form-data)
        for name, value in parse_body_params(request_body):
            fields.append(build_field(url, method, name, value, "body_param"))

        # Hidden 필드 (HTML 응답 파싱)
        response_body = msg.get("responseBody", "")
        for name, value in parse_hidden_fields(response_body):
            fields.append(build_field(url, method, name, value, "hidden_field"))

    return fields


# --- 헬퍼 함수 (구현 필요) ---
def extract_url(header: str) -> str: ...
def extract_method(header: str) -> str: ...
def parse_query_params(url: str) -> list[tuple]: ...
def parse_body_params(body: str) -> list[tuple]: ...
def parse_hidden_fields(html: str) -> list[tuple]: ...
def build_field(url, method, name, value, field_type) -> dict: ...
```

---

## Step 2. 시그니처 분류기 — `signature_classifier.py`

수집된 필드를 위험 카테고리로 분류한다. 패턴 매칭 기반으로 동작하며 템플릿 매핑의 키가 된다.

### 카테고리 정의

| 카테고리 | 설명 | 예시 필드명 |
|----------|------|------------|
| `FINANCIAL` | 금액/가격 조작 가능성 | price, amount, cost, total, fee, discount |
| `AUTHORIZATION` | 권한/역할 상승 가능성 | role, permission, admin, privilege, grade |
| `IDOR` | 타 사용자 객체 직접 참조 | userId, memberId, accountId, orderId |
| `LOGIC_FLOW` | 상태값/플로우 조작 | status, state, type, flag, step, phase |
| `DEFAULT` | 분류 불가 — 기본 페이로드 적용 | 위 패턴 미해당 |

### 구현 명세

```python
"""
signature_classifier.py

역할:
    - FieldInfo 목록을 받아 각 필드에 카테고리를 부여
    - 반환 형식: List[ClassifiedField]

반환 타입:
    ClassifiedField = FieldInfo + {"category": "FINANCIAL" | "AUTHORIZATION" | ...}
"""

import re

SIGNATURES = {
    "FINANCIAL":     r"(price|amount|cost|total|fee|discount|pay|charge|balance)",
    "AUTHORIZATION": r"(role|permission|admin|privilege|grade|authority|access)",
    "IDOR":          r"(userid|memberid|accountid|orderid|bookingid|sellerid|targetid)",
    "LOGIC_FLOW":    r"(status|state|type|flag|step|phase|stage|mode)",
}

def classify(fields: list[dict]) -> list[dict]:
    """
    각 필드의 field_name을 시그니처 패턴과 매칭하여
    카테고리를 부여한 ClassifiedField 목록을 반환한다.

    매칭 우선순위: FINANCIAL > AUTHORIZATION > IDOR > LOGIC_FLOW > DEFAULT
    """
    result = []
    for field in fields:
        category = _match_category(field["field_name"].lower())
        result.append({**field, "category": category})
    return result

def _match_category(field_name: str) -> str:
    for category, pattern in SIGNATURES.items():
        if re.search(pattern, field_name):
            return category
    return "DEFAULT"
```

---

## Step 3. 페이로드 템플릿 — `payloads/*.yaml`

카테고리별로 공통 페이로드를 정의한다. **한 번 작성 후 재사용**한다.

### AUTHORIZATION.yaml

```yaml
# payloads/AUTHORIZATION.yaml
category: AUTHORIZATION
description: "권한/역할 파라미터 조작 페이로드"

payloads:
  - "ADMIN"
  - "SUPER_ADMIN"
  - "ROOT"
  - "MANAGER"
  - "SELLER"
  - "MODERATOR"
  - "true"
  - "1"
  - "999"

mutation_strategies:
  - type: "replace"         # 원래 값을 페이로드로 교체
  - type: "append_suffix"   # 원래 값 뒤에 붙이기 (e.g. USER_ADMIN)
```

### FINANCIAL.yaml

```yaml
# payloads/FINANCIAL.yaml
category: FINANCIAL
description: "금액/가격 파라미터 조작 페이로드"

payloads:
  - "1"
  - "0"
  - "-1"
  - "-9999"
  - "0.001"
  - "99999999"
  - "NaN"
  - "null"

mutation_strategies:
  - type: "replace"
  - type: "negate"          # 원래 값에 음수 부호 적용
```

### IDOR.yaml

```yaml
# payloads/IDOR.yaml
category: IDOR
description: "타 사용자 객체 직접 참조 페이로드"

payloads:
  - "{original_value - 1}"  # 원래 ID에서 1 감소
  - "{original_value + 1}"  # 원래 ID에서 1 증가
  - "1"
  - "2"
  - "100"
  - "0"
  - "99999"

mutation_strategies:
  - type: "replace"
  - type: "increment"
  - type: "decrement"
```

### LOGIC_FLOW.yaml

```yaml
# payloads/LOGIC_FLOW.yaml
category: LOGIC_FLOW
description: "상태값/플로우 조작 페이로드"

payloads:
  - "ACTIVE"
  - "APPROVED"
  - "COMPLETED"
  - "DELETED"
  - "ADMIN"
  - "PAID"
  - "CONFIRMED"
  - "true"
  - "false"
  - "1"
  - "0"

mutation_strategies:
  - type: "replace"
```

### DEFAULT.yaml

```yaml
# payloads/DEFAULT.yaml
category: DEFAULT
description: "분류 불가 필드 기본 페이로드"

payloads:
  - "1"
  - "0"
  - "-1"
  - "true"
  - "false"
  - "null"
  - "admin"
  - "test"
  - "' OR '1'='1"

mutation_strategies:
  - type: "replace"
```

---

## Step 4. 인젝터 — `injector.py`

분류된 필드에 페이로드를 주입하고 원본 응답과 비교한다.

### 구현 명세

```python
"""
injector.py

역할:
    - ClassifiedField 목록을 받아 페이로드 템플릿을 로드
    - 각 필드에 페이로드를 주입하여 HTTP 요청 전송
    - 원본 응답과 조작 응답의 차이(diff)를 수집
    - 반환 형식: List[InjectionResult]

반환 타입:
    InjectionResult = {
        "field": ClassifiedField,
        "payload": str,
        "original_response": {"status": int, "body": str},
        "injected_response": {"status": int, "body": str},
        "diff": {
            "status_changed": bool,
            "body_length_delta": int,
            "keywords_found": list[str]   # 에러 메시지, 권한 관련 키워드 등
        }
    }
"""

import yaml
import requests
from pathlib import Path

PAYLOAD_DIR = Path("payloads")

def load_payloads(category: str) -> list[str]:
    """카테고리에 맞는 페이로드 템플릿 로드."""
    template_path = PAYLOAD_DIR / f"{category}.yaml"
    if not template_path.exists():
        template_path = PAYLOAD_DIR / "DEFAULT.yaml"
    with open(template_path) as f:
        return yaml.safe_load(f)["payloads"]

def inject(classified_fields: list[dict], session: requests.Session) -> list[dict]:
    """
    분류된 필드 목록에 페이로드를 주입하고 결과를 반환한다.

    Args:
        classified_fields: Step 2에서 분류된 필드 목록
        session:           인증 세션 (로그인 상태 유지용)

    Returns:
        List[InjectionResult]
    """
    results = []

    for field in classified_fields:
        payloads  = load_payloads(field["category"])
        orig_resp = send_original(field, session)

        for payload in payloads:
            inj_resp = send_injected(field, payload, session)
            diff     = compute_diff(orig_resp, inj_resp)

            results.append({
                "field":             field,
                "payload":           payload,
                "original_response": orig_resp,
                "injected_response": inj_resp,
                "diff":              diff,
            })

    return results


# --- 헬퍼 함수 (구현 필요) ---
def send_original(field: dict, session: requests.Session) -> dict: ...
def send_injected(field: dict, payload: str, session: requests.Session) -> dict: ...
def compute_diff(orig: dict, injected: dict) -> dict: ...
```

---

## Step 5. Claude API 분석기 — `analyzer.py`

인젝션 결과의 응답 차이를 Claude API에 전달하여 비즈니스 로직 취약 여부를 판단한다.

### 구현 명세

```python
"""
analyzer.py

역할:
    - InjectionResult 목록을 Claude API에 전달
    - 비즈니스 로직 관점에서 취약 여부 판단
    - 반환 형식: List[DiagnosisResult]

프롬프트 전략:
    - 서비스 유형(service_context)을 함께 주입하여 맥락 기반 판단
    - JSON 구조화 응답 강제
    - is_vulnerable / severity / reason / recommendation 반환

반환 타입:
    DiagnosisResult = {
        "field_name": str,
        "category": str,
        "payload": str,
        "is_vulnerable": bool,
        "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
        "reason": str,
        "recommendation": str,
        "sk_shieldus_item": "1-3"
    }
"""

import anthropic
import json

client = anthropic.Anthropic()

SYSTEM_PROMPT = """
당신은 웹 애플리케이션 취약점 진단 전문가입니다.
파라미터 조작 실험 결과를 분석하여 비즈니스 로직 취약점 여부를 판단합니다.
반드시 아래 JSON 형식으로만 응답하십시오. 다른 텍스트는 포함하지 마십시오.

{
  "is_vulnerable": true | false,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "reason": "판단 근거 (한국어)",
  "recommendation": "대응 방안 (한국어)",
  "sk_shieldus_item": "1-3"
}
"""

def analyze(injection_results: list[dict], service_context: str) -> list[dict]:
    """
    인젝션 결과를 Claude API로 분석하여 진단 결과를 반환한다.

    Args:
        injection_results: Step 4의 InjectionResult 목록
        service_context:   서비스 유형 설명 (e.g. "항공권 예약 플랫폼")

    Returns:
        List[DiagnosisResult]
    """
    diagnosis_results = []

    for result in injection_results:
        # 응답 차이가 없으면 스킵 (오탐 방지)
        if not result["diff"]["status_changed"] and result["diff"]["body_length_delta"] == 0:
            continue

        prompt = build_prompt(result, service_context)
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text
        parsed = json.loads(raw)
        parsed["field_name"] = result["field"]["field_name"]
        parsed["category"]   = result["field"]["category"]
        parsed["payload"]    = result["payload"]
        diagnosis_results.append(parsed)

    return diagnosis_results


def build_prompt(result: dict, service_context: str) -> str:
    return f"""
서비스 유형: {service_context}

[ 실험 정보 ]
- 필드명: {result['field']['field_name']}
- 카테고리: {result['field']['category']}
- 원래 값: {result['field']['original_value']}
- 주입 페이로드: {result['payload']}
- 엔드포인트: {result['field']['url']}
- HTTP Method: {result['field']['method']}

[ 응답 비교 ]
- 원본 상태코드: {result['original_response']['status']}
- 조작 후 상태코드: {result['injected_response']['status']}
- 응답 길이 변화: {result['diff']['body_length_delta']} bytes
- 감지된 키워드: {result['diff']['keywords_found']}

위 실험 결과를 바탕으로 파라미터 값 조작을 통한 비즈니스 로직 취약점 여부를 판단하십시오.
"""
```

---

## Step 6. 진단 실행 진입점 — `main.py`

```python
"""
main.py

사용법:
    python main.py --url https://target.com --context "항공권 예약 플랫폼" --auth-token "Bearer xxx"
"""

import argparse
import json
from datetime import datetime

from zap_crawler        import crawl_and_collect
from signature_classifier import classify
from injector           import inject
from analyzer           import analyze
import requests

def run(target_url: str, service_context: str, auth_token: str):
    session = requests.Session()
    session.headers.update({"Authorization": auth_token})

    print(f"[1/5] 크롤링 시작: {target_url}")
    fields = crawl_and_collect(target_url)
    print(f"      → {len(fields)}개 필드 수집 완료")

    print("[2/5] 시그니처 분류 중...")
    classified = classify(fields)
    for c in classified:
        print(f"      {c['field_name']} → {c['category']}")

    print("[3/5] 페이로드 템플릿 매핑 및 인젝션 실행 중...")
    injection_results = inject(classified, session)
    print(f"      → {len(injection_results)}건 인젝션 완료")

    print("[4/5] Claude API 분석 중...")
    diagnosis = analyze(injection_results, service_context)
    print(f"      → {len(diagnosis)}건 취약점 후보 분석 완료")

    print("[5/5] 결과 저장 중...")
    output = {
        "target_url":      target_url,
        "service_context": service_context,
        "timestamp":       datetime.now().isoformat(),
        "total_fields":    len(fields),
        "total_injections": len(injection_results),
        "findings":        diagnosis,
    }
    filename = f"results/{datetime.now().strftime('%Y%m%d_%H%M%S')}_result.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    print(f"      → 결과 저장: {filename}")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",        required=True)
    parser.add_argument("--context",    required=True)
    parser.add_argument("--auth-token", default="")
    args = parser.parse_args()

    run(args.url, args.context, args.auth_token)
```

---

## 결과 JSON 형식

```json
{
  "target_url": "https://onde.click",
  "service_context": "항공권 예약 플랫폼",
  "timestamp": "2025-07-01T10:30:00",
  "total_fields": 42,
  "total_injections": 187,
  "findings": [
    {
      "field_name": "role",
      "category": "AUTHORIZATION",
      "payload": "SUPER_ADMIN",
      "is_vulnerable": true,
      "severity": "CRITICAL",
      "reason": "role 파라미터에 SUPER_ADMIN 주입 시 201 Created 반환 — 서버가 클라이언트 입력값을 검증 없이 신뢰함",
      "recommendation": "서버 측에서 role 값을 USER로 강제 고정, 클라이언트 입력 무시",
      "sk_shieldus_item": "1-3"
    }
  ]
}
```

---

## 구현 시 주의사항

### Post-login 페이지 처리
인증이 필요한 페이지의 파라미터는 ZAP Context에 로그인 정보를 설정해야 수집된다.

```python
# zap_crawler.py 내 Context 설정 예시
zap.context.new_context("auth_context")
zap.authentication.set_authentication_method(
    context_id,
    auth_method_name="formBasedAuthentication",
    auth_method_config_params="loginUrl=https://target.com/login&loginRequestData=email%3D{%25username%25}%26password%3D{%25password%25}"
)
```

### 오탐 방지 기준
아래 경우는 Claude API 분석 전에 필터링한다.

- 상태코드 변화 없음 + 응답 길이 변화 50bytes 미만 → 스킵
- 상태코드 400/422 반환 → 서버가 정상적으로 거부한 것으로 판단, 스킵
- 상태코드 500 반환 → 별도 6-1 항목(오류 처리)으로 분류

### 페이로드 템플릿 확장
신규 서비스 도메인의 특화 필드가 있으면 해당 카테고리 yaml에 추가한다.

```yaml
# IDOR.yaml에 Onde 특화 필드 추가 예시
custom_field_patterns:
  - "flightSegmentId"
  - "accommodationId"
  - "settlementId"
```
