"""
test_mock.py — 외부 API(ZAP / Claude) 없이 파이프라인 전체를 로컬 테스트하는 스크립트

실행:
    python test_mock.py

Mock 범위:
    - collector.py  : ZAP Ajax Spider 호출        → 미리 정의한 가짜 파라미터 목록 반환
    - classifier.py : Phase 2 분류(원래도 규칙 기반)와 Phase 4 LLM 해석 모두 목킹
                      → 실제 Ollama/Claude를 호출하지 않고 규칙 기반으로 즉시 처리

실제 코드(comparator.py, engine.py, models.py, payloads.py)는 수정 없이 그대로 실행됨.
테스트 시나리오(MOCK_PARAMS / MOCK_RESPONSES)를 바꿔서 다양한 케이스를 검증할 수 있음.
"""

import json
import sys
import types
import unittest.mock as mock
from unittest.mock import MagicMock, patch

# ─────────────────────────────────────────────────────────────────────────────
# 1. MOCK 파라미터 목록 (collector.collect_params 반환값)
#    실제 ZAP이 크롤링하면 이런 파라미터들이 수집된다고 가정
# ─────────────────────────────────────────────────────────────────────────────
from scanners.param_manipulation.models import CollectedParam

MOCK_PARAMS: list[CollectedParam] = [
    # IDOR 후보 — 정수형 ID
    CollectedParam(
        url="http://localhost:8000/api/v1/orders/detail",
        method="GET",
        param_name="orderId",
        param_value="1042",
        param_type="query",
        content_type="",
    ),
    # PRIVILEGE 후보 — 권한 관련
    CollectedParam(
        url="http://localhost:8000/api/v1/users/signup",
        method="POST",
        param_name="role",
        param_value="USER",
        param_type="body",
        content_type="application/json",
    ),
    # PRICE 후보 — 금액 관련
    CollectedParam(
        url="http://localhost:8000/api/v1/payment",
        method="POST",
        param_name="amount",
        param_value="15000",
        param_type="body",
        content_type="application/json",
    ),
    # HIDDEN 후보 — hidden 필드
    CollectedParam(
        url="http://localhost:8000/checkout",
        method="POST",
        param_name="csrf_token_hidden",
        param_value="abc123",
        param_type="hidden",
        content_type="application/x-www-form-urlencoded",
    ),
    # SAFE — 검색 키워드, 스킵 대상
    CollectedParam(
        url="http://localhost:8000/api/v1/search",
        method="GET",
        param_name="keyword",
        param_value="shoes",
        param_type="query",
        content_type="",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# 2. MOCK 응답 시나리오
#    (url, param_name, payload_value) → (status, body)
#    정의되지 않은 조합은 default_response 반환
# ─────────────────────────────────────────────────────────────────────────────
MOCK_RESPONSES: dict[tuple, dict] = {

    # ── orderId: IDOR 시나리오 ───────────────────────────────────
    # baseline: 내 주문 → 200
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1042"): {
        "status": 200,
        "body": json.dumps({"orderId": 1042, "userId": 99, "total": 15000}),
        "headers": {"Content-Type": "application/json"},
    },
    # orderId=1041 (원본-1) → 200 + 타인 민감 정보 포함 (POTENTIAL_IDOR + DATA_EXPOSURE)
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1041"): {
        "status": 200,
        "body": json.dumps({
            "orderId": 1041,
            "userId": 77,
            "total": 99000,
            "personalInfo": {"name": "홍길동", "phone": "010-1234-5678"},
            "items": [{"id": 1, "name": "노트북", "price": 99000}],
        }),
        "headers": {"Content-Type": "application/json"},
    },
    # orderId=1043, 1052, 0, 9999999 → 404 (정상적으로 거부)
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1043"): {
        "status": 404,
        "body": json.dumps({"error": "not found"}),
        "headers": {},
    },
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1052"): {
        "status": 404,
        "body": json.dumps({"error": "not found"}),
        "headers": {},
    },
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "0"): {
        "status": 400,
        "body": json.dumps({"error": "invalid id"}),
        "headers": {},
    },
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "9999999"): {
        "status": 404,
        "body": json.dumps({"error": "not found"}),
        "headers": {},
    },

    # ── role: PRIVILEGE / DATA_EXPOSURE 시나리오 ─────────────────
    # baseline: role=USER → 201
    ("http://localhost:8000/api/v1/users/signup", "role", "USER"): {
        "status": 201,
        "body": json.dumps({"userId": 200, "role": "USER"}),
        "headers": {"Content-Type": "application/json"},
    },
    # role=ADMIN → 201 + adminDashboard 노출 → DATA_EXPOSURE 탐지
    ("http://localhost:8000/api/v1/users/signup", "role", "ADMIN"): {
        "status": 201,
        "body": json.dumps({"userId": 201, "role": "ADMIN", "adminDashboard": "/admin"}),
        "headers": {"Content-Type": "application/json"},
    },
    # role=SUPER_ADMIN, admin, true, 1, 0 → 403 (정상 거부)
    ("http://localhost:8000/api/v1/users/signup", "role", "SUPER_ADMIN"): {
        "status": 403, "body": json.dumps({"error": "forbidden"}), "headers": {},
    },
    ("http://localhost:8000/api/v1/users/signup", "role", "admin"): {
        "status": 403, "body": json.dumps({"error": "forbidden"}), "headers": {},
    },
    ("http://localhost:8000/api/v1/users/signup", "role", "true"): {
        "status": 201, "body": json.dumps({"userId": 202, "role": "USER"}), "headers": {},
    },
    ("http://localhost:8000/api/v1/users/signup", "role", "1"): {
        "status": 201, "body": json.dumps({"userId": 203, "role": "USER"}), "headers": {},
    },
    ("http://localhost:8000/api/v1/users/signup", "role", "0"): {
        "status": 400, "body": json.dumps({"error": "invalid role"}), "headers": {},
    },

    # ── amount: ERROR_SUPPRESSED 시나리오 ───────────────────────
    # baseline: amount=15000 → 200
    ("http://localhost:8000/api/v1/payment", "amount", "15000"): {
        "status": 200,
        "body": json.dumps({"result": "payment_pending", "amount": 15000}),
        "headers": {"Content-Type": "application/json"},
    },
    # amount=1, 99999999, 0.001 → 400 (정상 거부)
    ("http://localhost:8000/api/v1/payment", "amount", "1"): {
        "status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {},
    },
    ("http://localhost:8000/api/v1/payment", "amount", "99999999"): {
        "status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {},
    },
    ("http://localhost:8000/api/v1/payment", "amount", "0.001"): {
        "status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {},
    },
    # amount=-1, -9999 → 200 (음수인데도 성공!) → ERROR_SUPPRESSED 탐지
    ("http://localhost:8000/api/v1/payment", "amount", "-1"): {
        "status": 200,
        "body": json.dumps({"result": "payment_pending", "amount": -1}),
        "headers": {"Content-Type": "application/json"},
    },
    ("http://localhost:8000/api/v1/payment", "amount", "-9999"): {
        "status": 200,
        "body": json.dumps({"result": "payment_pending", "amount": -9999}),
        "headers": {"Content-Type": "application/json"},
    },
    # amount=0 → 400
    ("http://localhost:8000/api/v1/payment", "amount", "0"): {
        "status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {},
    },
}


def _default_response() -> dict:
    """MOCK_RESPONSES에 정의되지 않은 조합 — 정상 거부(400)를 기본으로 반환해 오탐 방지."""
    return {"status": 400, "body": json.dumps({"error": "bad request"}), "headers": {}}



# ─────────────────────────────────────────────────────────────────────────────
# 3. Mock 함수 정의
# ─────────────────────────────────────────────────────────────────────────────

def mock_collect_params(target_url: str, max_wait_seconds: int = 120, login_config: dict = None, custom_header: str = None):
    """ZAP Ajax Spider를 호출하지 않고 MOCK_PARAMS를 바로 반환한다."""
    print(f"  [MOCK] collect_params({target_url}) — login_config: {login_config is not None}, custom_header: {custom_header is not None} → {len(MOCK_PARAMS)}개 파라미터")
    return MOCK_PARAMS


def mock_classify_params(params):
    """
    Claude API를 호출하지 않고 파라미터명 키워드 규칙으로 즉시 분류한다.
    hidden 타입은 원래 로직대로 HIDDEN으로 처리.
    """
    import re
    from scanners.param_manipulation.models import ClassifiedParam

    RULES = {
        "PRICE":     re.compile(r"price|amount|cost|fee|total|discount|point|pay|money", re.I),
        "PRIVILEGE": re.compile(r"role|admin|perm|level|grade|authority|access|isadmin", re.I),
        "IDOR":      re.compile(r"(^|_)(id|uid|no)$|userid|memberid|orderid|boardid|seq", re.I),
        "SAFE":      re.compile(r"keyword|page|sort|lang|locale|theme|q|query", re.I),
    }

    classified = []
    for p in params:
        if p.param_type == "hidden":
            classified.append(ClassifiedParam(
                collected=p,
                category="HIDDEN",
                reason="[MOCK] HTML hidden input 필드",
            ))
            continue

        category = "SAFE"
        reason   = "[MOCK] 키워드 미매칭 → SAFE"
        for cat, pattern in RULES.items():
            if pattern.search(p.param_name):
                category = cat
                reason   = f"[MOCK] '{p.param_name}'이 {cat} 패턴에 매칭"
                break

        classified.append(ClassifiedParam(collected=p, category=category, reason=reason))

    print(f"  [MOCK] classify_params() 완료:")
    from collections import Counter
    for cat, cnt in Counter(c.category for c in classified).items():
        print(f"         {cat}: {cnt}개")
    return classified


def mock_interpret_findings(raw_findings):
    """
    Phase 4 LLM 해석을 호출하지 않고 RawFinding을 그대로 Finding으로 승격한다.
    실제 classifier.py의 _fallback_promote와 동일한 severity 매핑을 사용.
    """
    from scanners.param_manipulation.models import Finding

    SEVERITY = {
        "PRIVILEGE_BYPASS": "HIGH",
        "DATA_EXPOSURE":    "HIGH",
        "POTENTIAL_IDOR":   "MEDIUM",
        "ERROR_SUPPRESSED": "MEDIUM",
    }
    findings = [
        Finding(
            url=rf.url,
            method=rf.method,
            param_name=rf.param_name,
            category=rf.category,
            payload_used=rf.payload_used,
            payload_description=rf.payload_description,
            baseline_status=rf.baseline_status,
            test_status=rf.test_status,
            anomaly_type=rf.anomaly_type,
            anomaly_detail=rf.anomaly_detail,
            baseline_body=rf.baseline_body,
            test_body=rf.test_body,
            severity=SEVERITY.get(rf.anomaly_type, "MEDIUM"),
            llm_description="[MOCK] LLM 해석 생략",
            llm_recommendation="[MOCK] 수동 검토 권장",
        )
        for rf in raw_findings
    ]
    print(f"  [MOCK] interpret_findings() 완료: {len(findings)}건")
    return findings


def mock_send_request(url, method, param_name, param_value, content_type, custom_header=None, raw_body="", binary_fields=""):
    """실제 HTTP 요청 대신 MOCK_RESPONSES 테이블에서 응답을 찾아 반환한다."""
    key = (url, param_name, param_value)
    resp = MOCK_RESPONSES.get(key, _default_response())
    print(f"    [MOCK] {method} {url} [{param_name}={param_value!r}] (custom_header: {custom_header is not None}) → {resp['status']}")
    return resp


# ─────────────────────────────────────────────────────────────────────────────
# 4. 파이프라인 실행 (mock 패치 적용)
# ─────────────────────────────────────────────────────────────────────────────

def run_mock_test(target_url: str = "http://localhost:8000"):
    print("=" * 62)
    print(" 1-3 파이프라인 MOCK 테스트 (ZAP / Claude API 없음)")
    print("=" * 62)
    print(f"  대상 URL: {target_url}\n")

    # 모의 로그인 정보 및 커스텀 헤더 정의
    mock_login = {
        "login_url": "http://localhost:8000/api/v1/auth/login",
        "username": "testuser",
        "password": "testpassword"
    }
    mock_header = "Authorization: Bearer mock-token-12345"

    with (
        patch("scanners.param_manipulation.collector.collect_params",
              side_effect=mock_collect_params),
        patch("scanners.param_manipulation.classifier.classify_params",
              side_effect=mock_classify_params),
        patch("scanners.param_manipulation.classifier.interpret_findings",
              side_effect=mock_interpret_findings),
        patch("scanners.param_manipulation.manipulator._send_request",
              side_effect=mock_send_request),
    ):
        from scanners.param_manipulation.engine import run_scan
        findings = run_scan(target_url, login_config=mock_login, custom_header=mock_header)

    # ── 결과 출력 ─────────────────────────────────────────────
    print()
    print("=" * 62)
    print(f" 결과: {len(findings)}건 Finding")
    print("=" * 62)

    if not findings:
        print("  Finding 없음")
        return findings

    for i, f in enumerate(findings, 1):
        print(f"\n  [{i}] [{f.severity}] {f.anomaly_type}")
        print(f"      URL      : {f.url}")
        print(f"      Param    : {f.param_name} = {f.payload_used!r}")
        print(f"      Category : {f.category}")
        print(f"      Detail   : {f.anomaly_detail}")
        print(f"      Status   : {f.baseline_status} → {f.test_status}")

    print()
    high_cnt   = sum(1 for f in findings if f.severity == "HIGH")
    medium_cnt = sum(1 for f in findings if f.severity == "MEDIUM")
    print(f"  HIGH: {high_cnt}건  MEDIUM: {medium_cnt}건")
    print()
    return findings


if __name__ == "__main__":
    findings = run_mock_test()
    sys.exit(0 if findings is not None else 1)
