"""
zap_crawler.py

역할:
    - ZAP AJAX Spider로 대상 URL 크롤링
    - 수집된 모든 요청에서 파라미터 및 히든 필드 추출
    - 반환 형식: List[FieldInfo]

FieldInfo = {
    "url": str,                # 요청 경로(쿼리 포함)
    "method": str,
    "field_name": str,
    "field_type": str,         # body_param | query_param | hidden_field
    "original_value": str,
    "source": "zap_spider",
    "raw_url": str,            # injector가 이 필드 하나만 바꾼 요청을 재구성하기 위한 원본 URL
    "raw_body": str,           # 위와 동일한 목적의 원본 요청 바디
    "content_type": str,
}

명세서에는 없지만 raw_url/raw_body/content_type을 추가했다: 인젝터가 나머지 파라미터는
그대로 둔 채 필드 하나만 변조한 요청을 재전송하려면 원본 요청 전체(쿼리/바디)가 있어야 한다.

한계: 히든 필드는 이 필드가 노출된 GET 응답의 URL을 그대로 재사용해서 기록한다. 실제 제출
(POST) 대상이 폼의 action 속성으로 다른 경로를 가리키는 경우 injector의 재전송이 부정확할
수 있다 (폼 action 파싱은 이번 구현 범위에 포함하지 않음).
"""

import json
import re
import time
from urllib.parse import parse_qsl, urlsplit

from zapv2 import ZAPv2

_HIDDEN_FIELD_RE = re.compile(r'<input\b[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
_NAME_ATTR_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
_VALUE_ATTR_RE = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
_CONTENT_TYPE_RE = re.compile(r"Content-Type:\s*([^\r\n;]+)", re.IGNORECASE)


def extract_url(request_header: str) -> str:
    first_line = request_header.split("\r\n", 1)[0]
    parts = first_line.split(" ")
    return parts[1] if len(parts) > 1 else ""


def extract_method(request_header: str) -> str:
    first_line = request_header.split("\r\n", 1)[0]
    parts = first_line.split(" ")
    return parts[0] if parts else "GET"


def extract_content_type(request_header: str) -> str:
    match = _CONTENT_TYPE_RE.search(request_header or "")
    return match.group(1).strip() if match else ""


def parse_query_params(url: str) -> list:
    query = urlsplit(url).query
    return parse_qsl(query, keep_blank_values=True)


def parse_body_params(body: str, content_type: str = "") -> list:
    if not body:
        return []
    if "json" in content_type:
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return []
        if isinstance(data, dict):
            return [(k, v) for k, v in data.items() if not isinstance(v, (dict, list))]
        return []
    # 기본값: application/x-www-form-urlencoded로 취급
    return parse_qsl(body, keep_blank_values=True)


def parse_hidden_fields(html: str) -> list:
    fields = []
    for tag in _HIDDEN_FIELD_RE.findall(html or ""):
        name_match = _NAME_ATTR_RE.search(tag)
        if not name_match:
            continue
        value_match = _VALUE_ATTR_RE.search(tag)
        fields.append((name_match.group(1), value_match.group(1) if value_match else ""))
    return fields


def build_field(url, method, name, value, field_type, raw_url, raw_body, content_type) -> dict:
    return {
        "url": url,
        "method": method,
        "field_name": name,
        "field_type": field_type,
        "original_value": value,
        "source": "zap_spider",
        "raw_url": raw_url,
        "raw_body": raw_body,
        "content_type": content_type,
    }


def crawl_and_collect(target_url: str, zap_api_url: str, api_key: str = None, wait_seconds: int = 30) -> list:
    """
    대상 URL을 ZAP AJAX Spider로 크롤링하고 발견된 모든 파라미터/히든 필드 목록을 반환한다.
    """
    zap = ZAPv2(apikey=api_key, proxies={"http": zap_api_url, "https": zap_api_url})

    zap.ajaxSpider.scan(target_url)
    elapsed = 0
    while zap.ajaxSpider.status == "running" and elapsed < wait_seconds:
        time.sleep(2)
        elapsed += 2
    zap.ajaxSpider.stop()

    fields = []
    messages = zap.core.messages(baseurl=target_url)

    for msg in messages:
        request_header = msg.get("requestHeader") or ""
        request_body = msg.get("requestBody") or ""
        response_body = msg.get("responseBody") or ""
        if not request_header:
            continue

        url = extract_url(request_header)
        method = extract_method(request_header)
        content_type = extract_content_type(request_header)

        for name, value in parse_query_params(url):
            fields.append(build_field(url, method, name, value, "query_param", url, request_body, content_type))

        for name, value in parse_body_params(request_body, content_type):
            fields.append(build_field(url, method, name, value, "body_param", url, request_body, content_type))

        for name, value in parse_hidden_fields(response_body):
            fields.append(build_field(url, method, name, value, "hidden_field", url, request_body, content_type))

    return fields
