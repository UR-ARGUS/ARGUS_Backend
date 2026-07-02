"""
test_ollama_classify.py — Ollama가 실제로 이상 징후를 해석하는 버전

collect_params(ZAP)와 _send_request(HTTP)만 Mock 처리하고,
Phase 4 classifier.interpret_findings는 실제 Ollama를 호출해 해석 결과를 확인한다.
(v2: LLM 호출이 Phase 2 사전분류 → Phase 4 diff 해석으로 이동함에 따라 갱신됨.
 이 스크립트로 Ollama 응답이 timeout 없이 정상적으로 돌아오는지 확인할 수 있다.)

실행:
    $env:PYTHONIOENCODING="utf-8"
    .\\venv\\Scripts\\python test_ollama_classify.py
"""

import json
from unittest.mock import patch

from scanners.param_manipulation.models import CollectedParam

# ── Mock 파라미터 (ZAP 수집 대체) ─────────────────────────────────
MOCK_PARAMS = [
    CollectedParam(
        url="http://localhost:8000/api/v1/orders/detail",
        method="GET", param_name="orderId", param_value="1042",
        param_type="query", content_type="",
    ),
    CollectedParam(
        url="http://localhost:8000/api/v1/users/signup",
        method="POST", param_name="role", param_value="USER",
        param_type="body", content_type="application/json",
    ),
    CollectedParam(
        url="http://localhost:8000/api/v1/payment",
        method="POST", param_name="amount", param_value="15000",
        param_type="body", content_type="application/json",
    ),
    CollectedParam(
        url="http://localhost:8000/checkout",
        method="POST", param_name="csrf_token_hidden", param_value="abc123",
        param_type="hidden", content_type="application/x-www-form-urlencoded",
    ),
    CollectedParam(
        url="http://localhost:8000/api/v1/search",
        method="GET", param_name="keyword", param_value="shoes",
        param_type="query", content_type="",
    ),
]

# ── Mock HTTP 응답 ─────────────────────────────────────────────────
MOCK_RESPONSES = {
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1042"): {"status": 200, "body": json.dumps({"orderId": 1042, "userId": 99, "total": 15000}), "headers": {}},
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1041"): {"status": 200, "body": json.dumps({"orderId": 1041, "userId": 77, "total": 99000, "personalInfo": {"name": "홍길동", "phone": "010-1234-5678"}, "items": [{"id": 1, "name": "노트북", "price": 99000}]}), "headers": {}},
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1043"): {"status": 404, "body": json.dumps({"error": "not found"}), "headers": {}},
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "1052"): {"status": 404, "body": json.dumps({"error": "not found"}), "headers": {}},
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "0"):    {"status": 400, "body": json.dumps({"error": "invalid id"}), "headers": {}},
    ("http://localhost:8000/api/v1/orders/detail", "orderId", "9999999"): {"status": 404, "body": json.dumps({"error": "not found"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "USER"):       {"status": 201, "body": json.dumps({"userId": 200, "role": "USER"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "ADMIN"):      {"status": 201, "body": json.dumps({"userId": 201, "role": "ADMIN", "adminDashboard": "/admin"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "SUPER_ADMIN"):{"status": 403, "body": json.dumps({"error": "forbidden"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "admin"):      {"status": 403, "body": json.dumps({"error": "forbidden"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "true"):       {"status": 201, "body": json.dumps({"userId": 202, "role": "USER"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "1"):          {"status": 201, "body": json.dumps({"userId": 203, "role": "USER"}), "headers": {}},
    ("http://localhost:8000/api/v1/users/signup", "role", "0"):          {"status": 400, "body": json.dumps({"error": "invalid role"}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "15000"):  {"status": 200, "body": json.dumps({"result": "payment_pending", "amount": 15000}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "1"):      {"status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "99999999"): {"status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "0.001"):  {"status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "-1"):     {"status": 200, "body": json.dumps({"result": "payment_pending", "amount": -1}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "-9999"):  {"status": 200, "body": json.dumps({"result": "payment_pending", "amount": -9999}), "headers": {}},
    ("http://localhost:8000/api/v1/payment", "amount", "0"):      {"status": 400, "body": json.dumps({"error": "invalid amount"}), "headers": {}},
}

def mock_collect(target_url, max_wait_seconds=120, login_config=None, custom_header=None):
    print(f"  [MOCK] collect_params → {len(MOCK_PARAMS)}개 파라미터")
    return MOCK_PARAMS

def mock_send(url, method, param_name, param_value, content_type, custom_header=None, raw_body="", binary_fields=""):
    key  = (url, param_name, param_value)
    resp = MOCK_RESPONSES.get(key, {"status": 400, "body": json.dumps({"error": "bad request"}), "headers": {}})
    print(f"    [MOCK] {method} {url} [{param_name}={param_value!r}] → {resp['status']}")
    return resp


def run():
    print("=" * 62)
    print(" Ollama 실제 해석 테스트 (ZAP / HTTP만 Mock, Phase 4는 실제 Ollama 호출)")
    print("=" * 62)
    print("  Phase 2 분류: 규칙 기반 (실제 로직 그대로)")
    print("  Phase 4 해석: Ollama 실제 호출 (timeout 동작 확인 목적)\n")

    with (
        patch("scanners.param_manipulation.collector.collect_params", side_effect=mock_collect),
        patch("scanners.param_manipulation.manipulator._send_request", side_effect=mock_send),
    ):
        from scanners.param_manipulation.engine import run_scan

        import logging
        logging.basicConfig(level=logging.INFO, format="  %(name)s — %(message)s")

        findings = run_scan("http://localhost:8000")

    print("\n" + "=" * 62)
    print(f" 결과: {len(findings)}건 Finding")
    print("=" * 62)

    for i, f in enumerate(findings, 1):
        print(f"\n  [{i}] [{f.severity}] {f.anomaly_type}")
        print(f"      URL      : {f.url}")
        print(f"      Param    : {f.param_name} = {f.payload_used!r}")
        print(f"      Category : {f.category}")
        print(f"      Detail   : {f.anomaly_detail}")
        print(f"      Status   : {f.baseline_status} → {f.test_status}")
        print(f"      LLM 설명 : {f.llm_description}")
        print(f"      LLM 조치 : {f.llm_recommendation}")

    high   = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    print(f"\n  HIGH: {high}건  MEDIUM: {medium}건")


if __name__ == "__main__":
    run()
