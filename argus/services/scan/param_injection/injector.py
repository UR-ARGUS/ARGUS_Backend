"""
injector.py

역할:
    - ClassifiedField 목록을 받아 페이로드 템플릿을 로드
    - 각 필드에 페이로드를 주입하여 HTTP 요청 전송
    - 원본 응답과 조작 응답의 차이(diff)를 수집
    - 반환 형식: List[InjectionResult]

InjectionResult = {
    "field": ClassifiedField,
    "payload": str,
    "original_response": {"status": int, "body": str},
    "injected_response": {"status": int, "body": str},
    "diff": {
        "status_changed": bool,
        "body_length_delta": int,
        "keywords_found": list[str],
    },
}

주의: payloads/*.yaml이 카테고리별 주입 값의 단일 소스다. argus/services/scan/zap_scripts/
parameter_diff_scan.js도 SnakeYAML로 같은 YAML 파일을 읽으므로, 페이로드를 바꿀 땐 YAML만
고치면 된다(JS 쪽 SnakeYAML 로딩이 실패했을 때 쓰는 하드코딩 폴백만 별도로 봐야 함).
"{original_value - 1}" 같은 템플릿 토큰을 추가하면 이 파일의 _TEMPLATE_RESOLVERS와
parameter_diff_scan.js의 resolvePayloadTemplate()도 함께 추가해야 한다.

이 파일 자체는 ZAP을 거치지 않는다 - zap_crawler.py가 수집한 필드를 requests.Session으로
직접 재전송한다. 그래서 ZAP의 Replacer 헤더/Forced User 인증 세션(로그인 폼 기반 세션 포함)을
물려받지 못하고, main.py가 넘기는 auth_token 헤더 하나에만 의존한다.
"""

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import yaml

PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"

# 에러 메시지/권한 관련 키워드 - 응답 본문에서 발견되면 diff에 함께 보고한다.
KEYWORDS = [
    "error", "exception", "unauthorized", "forbidden", "denied",
    "admin", "success", "granted", "invalid", "stack trace", "traceback",
]


def load_payloads(category: str) -> list:
    """카테고리에 맞는 페이로드 템플릿 로드."""
    template_path = PAYLOAD_DIR / f"{category}.yaml"
    if not template_path.exists():
        template_path = PAYLOAD_DIR / "DEFAULT.yaml"
    with open(template_path, encoding="utf-8") as f:
        return yaml.safe_load(f)["payloads"]


def _rebuild_url(raw_url: str, field_name: str, value) -> str:
    parts = urlsplit(raw_url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    new_pairs = []
    for k, v in pairs:
        if k == field_name:
            new_pairs.append((k, str(value)))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((field_name, str(value)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_pairs), parts.fragment))


def _rebuild_body(raw_body: str, content_type: str, field_name: str, value) -> str:
    if "json" in (content_type or ""):
        try:
            data = json.loads(raw_body) if raw_body else {}
        except (ValueError, TypeError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        data = dict(data)
        data[field_name] = value
        return json.dumps(data)

    pairs = parse_qsl(raw_body or "", keep_blank_values=True)
    replaced = False
    new_pairs = []
    for k, v in pairs:
        if k == field_name:
            new_pairs.append((k, str(value)))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((field_name, str(value)))
    return urlencode(new_pairs)


def _send(field: dict, value, session: requests.Session) -> dict:
    method = (field.get("method") or "GET").upper()

    if field["field_type"] == "query_param":
        url = _rebuild_url(field["raw_url"], field["field_name"], value)
        body = field.get("raw_body") or None
    else:
        # body_param / hidden_field는 동일하게 요청 바디 안의 값으로 취급한다.
        # (히든 필드의 실제 제출 대상이 다른 엔드포인트일 수 있다는 한계는 zap_crawler.py 참고)
        url = field["raw_url"]
        body = _rebuild_body(field.get("raw_body") or "", field.get("content_type", ""), field["field_name"], value)

    headers = {"Content-Type": field["content_type"]} if field.get("content_type") else None
    resp = session.request(method, url, data=body, headers=headers, timeout=15, allow_redirects=False)
    return {"status": resp.status_code, "body": resp.text}


def send_original(field: dict, session: requests.Session) -> dict:
    return _send(field, field["original_value"], session)


def _format_number(n: float) -> str:
    return str(int(n)) if n == int(n) else str(n)


# 페이로드 YAML에 등장하는 동적 템플릿 토큰 - 실행 시점의 원본 값을 기준으로 계산한다.
# 새 토큰을 추가하면 zap_scripts/parameter_diff_scan.js의 resolvePayloadTemplate()도
# 함께 추가해야 한다.
_TEMPLATE_RESOLVERS = {
    "{original_value - 1}": lambda n: _format_number(n - 1),
    "{original_value + 1}": lambda n: _format_number(n + 1),
    "{original_value * -1}": lambda n: _format_number(n * -1),
}


def _resolve_template(payload: str, original_value) -> str:
    resolver = _TEMPLATE_RESOLVERS.get(payload)
    if resolver is None:
        return payload
    try:
        n = float(original_value)
    except (TypeError, ValueError):
        return None  # 원본 값이 숫자가 아니면 이 템플릿 페이로드는 적용할 수 없음
    return resolver(n)


def send_injected(field: dict, payload: str, session: requests.Session):
    resolved = _resolve_template(payload, field["original_value"])
    if resolved is None:
        return None
    return _send(field, resolved, session)


def compute_diff(orig: dict, injected: dict) -> dict:
    status_changed = orig["status"] != injected["status"]
    body_length_delta = len(injected["body"]) - len(orig["body"])
    lower_body = injected["body"].lower()
    keywords_found = [kw for kw in KEYWORDS if kw in lower_body]
    return {
        "status_changed": status_changed,
        "body_length_delta": body_length_delta,
        "keywords_found": keywords_found,
    }


def inject(classified_fields: list, session: requests.Session) -> list:
    """
    분류된 필드 목록에 페이로드를 주입하고 결과를 반환한다.
    """
    results = []

    for field in classified_fields:
        payloads = load_payloads(field["category"])
        orig_resp = send_original(field, session)

        for payload in payloads:
            inj_resp = send_injected(field, payload, session)
            if inj_resp is None:
                continue
            diff = compute_diff(orig_resp, inj_resp)

            results.append({
                "field": field,
                "payload": payload,
                "original_response": orig_resp,
                "injected_response": inj_resp,
                "diff": diff,
            })

    return results
