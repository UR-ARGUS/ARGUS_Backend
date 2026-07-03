"""
manipulator.py — Phase 3: 카테고리별 페이로드 주입

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 5

역할:
    - 분류된 카테고리별로 정해진 조작 페이로드를 파라미터에 주입
    - 원본 요청을 재현한 뒤 파라미터 값만 교체해서 요청 전송
    - baseline(원본 응답)과 test(조작 응답)를 함께 반환

주의:
    - IDOR는 원본 param_value가 정수형이 아닌 경우 페이로드 생성 건너뜀
    - 실제 서비스에 부작용을 줄 수 있는 POST/PUT/DELETE는 대상 서비스 확인 후 사용
    - 요청 타임아웃: TIMEOUT 상수 (기본 10초)
    - JSON/form body 파라미터는 collector.py가 넘겨준 raw_body(전체 필드 baseline)를
      템플릿으로 삼아 대상 필드 하나만 교체한다. raw_body가 없으면(예: hidden 필드)
      해당 필드 하나만 담은 body로 폴백 — 이 경우 필수 필드 누락으로 서버가
      baseline/test 둘 다 동일하게 거절해 이상 탐지가 안 될 수 있다.
"""

import json
import logging
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

from .models import ClassifiedParam
from .payloads import PAYLOADS

logger  = logging.getLogger(__name__)
TIMEOUT = 10  # 초


def run_manipulation(param: ClassifiedParam, custom_header: str = None) -> list[dict]:
    """
    단일 ClassifiedParam에 대해 페이로드를 주입하고 결과 목록을 반환한다.

    Returns:
        list of {
            "param":               ClassifiedParam,
            "payload_value":       str,
            "payload_description": str,
            "baseline":            {"status": int, "body": str, "headers": dict},
            "test":                {"status": int, "body": str, "headers": dict},
        }
    """
    c        = param.collected
    payloads = _get_payloads(param)
    if not payloads:
        logger.debug(f"페이로드 없음 — 건너뜀: {c.param_name} ({param.category})")
        return []

    baseline_resp = _send_request(
        c.url, c.method, c.param_name, c.param_value, c.content_type, custom_header, c.raw_body, c.binary_fields,
    )

    results = []
    for payload_val, payload_desc in payloads:
        test_resp = _send_request(
            c.url, c.method, c.param_name, payload_val, c.content_type, custom_header, c.raw_body, c.binary_fields,
        )
        results.append({
            "param":               param,
            "payload_value":       payload_val,
            "payload_description": payload_desc,
            "baseline":            baseline_resp,
            "test":                test_resp,
        })

    return results


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _get_payloads(param: ClassifiedParam) -> list[tuple[str, str]]:
    """
    카테고리에 맞는 페이로드 리스트를 반환한다.
    IDOR는 원본 ID 값 기준으로 동적 생성한다.
    """
    if param.category == "IDOR":
        try:
            base_id = int(param.collected.param_value)
            return [
                (str(base_id - 1),  f"ID {base_id - 1} (원본-1)"),
                (str(base_id + 1),  f"ID {base_id + 1} (원본+1)"),
                (str(base_id + 10), f"ID {base_id + 10} (원본+10)"),
                ("0",               "ID 0 (경계값)"),
                ("9999999",         "ID 극대값"),
            ]
        except (ValueError, TypeError):
            logger.debug(
                f"IDOR 페이로드 생성 건너뜀: {param.collected.param_name}="
                f"{param.collected.param_value!r} (정수 변환 불가)"
            )
            return []

    hardcoded = PAYLOADS.get(param.category, [])

    # Swagger 스펙에 enum이 정의된 필드(예: status)는 서비스마다 실제 값 이름이 다르다
    # (PAID/CONFIRMED는 특정 도메인 추측일 뿐, 다른 서비스는 PENDING/DONE 등을 쓸 수 있음).
    # 스펙이 선언한 실제 enum 값을 우선 페이로드로 써서 하드코딩된 값에 의존하지 않고
    # 어떤 서비스에도 통하는 범용적인 상태 전이 테스트가 가능하게 한다. baseline과 동일한
    # 값은 비교 무의미하므로 제외하고, 하드코딩 목록(ADMIN 등 명백한 악성값 포함)도
    # 이어붙여 스펙 밖 조작 시도는 그대로 유지한다.
    if param.collected.enum_values:
        baseline_val = str(param.collected.param_value).strip().lower()
        enum_payloads = [
            (v, f"스펙 enum 값으로 변조: {v}")
            for v in param.collected.enum_values.split(",")
            if v.strip().lower() != baseline_val
        ]
        return enum_payloads + hardcoded

    return hardcoded


def _apply_mutation_to_json(raw_body: str, param_name: str, value: str) -> dict:
    """
    raw_body(JSON)를 파싱해 param_name 위치의 값만 교체하고 다른 필드는 보존한다.
    param_name은 collector._flatten_json이 만든 dot-notation 경로일 수 있다
    (예: "personalInfo.name"). 배열 경로("items[0].id")는 지원하지 않고
    안전하게 해당 필드 하나만 담은 body로 폴백한다.
    """
    try:
        data = json.loads(raw_body) if raw_body else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}

    if not raw_body or "[" in param_name:
        return {param_name: value}

    keys = param_name.split(".")
    cur = data
    for key in keys[:-1]:
        nxt = cur.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[key] = nxt
        cur = nxt
    cur[keys[-1]] = value
    return data


def _apply_mutation_to_form(raw_body: str, param_name: str, value: str) -> dict:
    """raw_body(form-urlencoded)를 파싱해 param_name 값만 교체하고 나머지 필드는 보존한다."""
    if not raw_body:
        return {param_name: value}
    qs = parse_qs(raw_body, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param_name] = value
    return flat


def _apply_mutation_to_multipart(
    raw_body: str, param_name: str, value: str, binary_fields: str,
) -> tuple[dict, dict]:
    """
    raw_body(전체 필드 baseline)에 param_name만 교체 반영한 뒤,
    binary_fields에 해당하는 필드는 files=(더미 파일)로, 나머지는 data=로 분리한다.
    (파일 필드 자체를 변조 대상으로 삼는 페이로드는 의미가 없으므로 항상 더미로 채움)
    """
    merged = _apply_mutation_to_json(raw_body, param_name, value)
    binary_names = {n for n in binary_fields.split(",") if n}
    data, files = {}, {}
    for key, val in merged.items():
        if key in binary_names:
            files[key] = (f"{key}.bin", b"\x00", "application/octet-stream")
        else:
            data[key] = val
    return data, files


def _send_request(
    url:          str,
    method:       str,
    param_name:   str,
    param_value:  str,
    content_type: str,
    custom_header: str = None,
    raw_body:     str = "",
    binary_fields: str = "",
) -> dict:
    """
    파라미터 값을 교체한 요청을 전송하고
    {"status": int, "body": str, "headers": dict} 형태로 반환한다.
    요청 실패 시 status=-1, body=오류 메시지.
    """
    # 기본 헤더 구성
    req_headers = {}
    if "application/json" in content_type:
        req_headers["Content-Type"] = "application/json"

    # 사용자 정의 헤더 파싱 및 적용
    if custom_header:
        custom_header = custom_header.strip()
        if ":" in custom_header:
            h_name, h_val = custom_header.split(":", 1)
            req_headers[h_name.strip()] = h_val.strip()
        elif custom_header.startswith("Bearer "):
            req_headers["Authorization"] = custom_header
        elif custom_header.startswith("eyJ"):
            req_headers["Authorization"] = f"Bearer {custom_header}"
        else:
            req_headers["Authorization"] = custom_header

    # 실제로 전송할 바디를 먼저 구성 — 요청에 쓰는 것과 증적으로 남기는 것을 같은
    # 값으로 보장하기 위해 한 번만 계산한다 (기존엔 요청 인자에서 즉석으로 만들고
    # 버려서 실제 전송된 변조 바디가 어디에도 남지 않았음).
    request_body_repr = ""
    try:
        if "application/json" in content_type:
            body_obj = _apply_mutation_to_json(raw_body, param_name, param_value)
            request_body_repr = json.dumps(body_obj, ensure_ascii=False)
            resp = requests.request(
                method, url, timeout=TIMEOUT, json=body_obj, headers=req_headers,
            )
        elif "application/x-www-form-urlencoded" in content_type:
            body_obj = _apply_mutation_to_form(raw_body, param_name, param_value)
            request_body_repr = urlencode(body_obj)
            resp = requests.request(
                method, url, timeout=TIMEOUT, data=body_obj, headers=req_headers,
            )
        elif "multipart/form-data" in content_type:
            # Content-Type은 requests가 files= 사용 시 boundary 포함해서 자동 설정 —
            # 여기서 직접 지정하면 boundary가 빠져 서버가 파싱을 못 한다.
            data, files = _apply_mutation_to_multipart(raw_body, param_name, param_value, binary_fields)
            request_body_repr = json.dumps(
                {**data, **{k: f"<binary:{k}>" for k in files}}, ensure_ascii=False
            )
            resp = requests.request(
                method, url, timeout=TIMEOUT,
                data=data, files=files or None,
                headers=req_headers,
            )
        else:
            # Query string 교체
            parsed  = urlparse(url)
            qs      = parse_qs(parsed.query, keep_blank_values=True)
            qs[param_name] = [param_value]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            request_body_repr = f"(query string) {new_url}"
            resp    = requests.request(method, new_url, timeout=TIMEOUT, headers=req_headers)

        return {
            "status":       resp.status_code,
            "body":         resp.text,
            "headers":      dict(resp.headers),
            "request_body": request_body_repr,
        }

    except requests.RequestException as e:
        logger.warning(f"요청 실패 ({method} {url} [{param_name}={param_value!r}]): {e}")
        return {"status": -1, "body": str(e), "headers": {}, "request_body": request_body_repr}
