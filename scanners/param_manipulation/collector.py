"""
collector.py — Phase 1: ZAP Ajax Spider 수집

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 3

역할:
    - ZAP에 Ajax Spider를 실행해 대상 URL을 크롤링
    - 수집된 모든 HTTP 메시지에서 파라미터(query / body / hidden)를 추출
    - <input type="hidden">은 ZAP Ajax Spider의 HTML 렌더링에서 자동 수집됨

주의:
    - ZAP_API_URL / ZAP_API_KEY는 argus.core.config.settings에서 읽음 (하드코딩 없음)
    - 인증이 필요한 페이지는 zap.context + 세션 쿠키 주입이 별도로 필요함
      (현재는 인증 없는 공개 파라미터만 수집하는 기본 동작)
    - Ajax Spider 최대 대기 시간: max_wait_seconds (기본 120초)
"""

import json
import logging
import time
from typing import Any
from urllib.parse import urlparse, parse_qs

from zapv2 import ZAPv2

from argus.core.config import settings
from .models import CollectedParam

logger = logging.getLogger(__name__)


def collect_params(
    target_url: str,
    max_wait_seconds: int = 120,
    login_config: dict = None,
    custom_header: str = None,
) -> list[CollectedParam]:
    """
    ZAP Ajax Spider 또는 Swagger Spec URL로부터 파라미터 목록을 수집한다.

    Args:
        target_url:        크롤링 대상 URL 혹은 Swagger/OpenAPI Spec JSON URL
        max_wait_seconds:  Ajax Spider 완료 대기 최대 시간 (초)
        login_config:      자동 로그인 설정 정보
        custom_header:     사용자 정의 헤더/쿠키 문자열

    Returns:
        List[CollectedParam]
    """
    # ── Swagger / OpenAPI Spec URL인 경우 직접 파싱 ──────────────────
    if (
        "swagger_scan=true" in target_url 
        or target_url.endswith(".json") 
        or "swagger" in target_url.lower() 
        or "openapi" in target_url.lower()
    ):
        logger.info(f"Swagger/OpenAPI Spec 연동 진단을 감지했습니다: {target_url}")
        try:
            return _parse_swagger_spec(target_url, custom_header)
        except Exception as e:
            logger.error(f"Swagger 파싱 실패: {e}. 일반 ZAP 크롤링으로 폴백합니다.")

    zap = ZAPv2(
        apikey=settings.ZAP_API_KEY or None,
        proxies={
            "http":  settings.ZAP_API_URL,
            "https": settings.ZAP_API_URL,
        },
    )

    # Vite 개발 서버는 node_modules 의존성 번들(react-dom 등 수백KB~1MB+)을 그대로
    # 서빙하는데, ZAP이 이걸 Ajax Spider로 수집해 매번 passive scan 큐에 넣으면
    # 힙/CPU가 고갈되어 프록시 자체가 응답 불능에 빠진다 (실측: 힙 512MB 환경에서
    # netty event loop가 종료돼 이후 모든 ZAP API 호출이 ConnectionReset로 실패함).
    # 진단 대상이 아닌 서드파티 번들이므로 프록시 단계에서 아예 제외한다.
    try:
        zap.core.exclude_from_proxy(regex=".*/node_modules/.*")
    except Exception as e:
        logger.warning(f"ZAP node_modules 제외 설정 실패 (무시하고 진행): {e}")

    # ── 1. 인증(로그인) 처리 ──────────────────────────────────────────
    context_id = None
    if login_config:
        logger.info("자동 로그인 설정 시작...")
        try:
            # 기본 컨텍스트 획득 또는 신규 생성
            context_name = "argus_context"
            try:
                context_id = zap.context.new_context(context_name)
            except Exception:
                context_id = zap.context.context(context_name)["id"]

            # 대상 URL을 컨텍스트에 포함
            zap.context.include_in_context(context_name, f"{target_url.rstrip('/')}/.*")

            # 로그인 파라미터 파싱
            login_url = login_config.get("login_url")
            username_field = login_config.get("username_field", "username")
            password_field = login_config.get("password_field", "password")
            username = login_config.get("username")
            password = login_config.get("password")

            if login_url and username and password:
                # Form-based 인증 방식 설정
                login_request_data = f"{username_field}={username}&{password_field}={password}"
                zap.authentication.set_authentication_method(
                    contextid=context_id,
                    authmethodname="formBasedAuthentication",
                    authmethodconfigparams=f"loginUrl={login_url}&loginRequestData={login_request_data}"
                )
                
                # 유저 생성 및 활성화
                user_id = zap.users.new_user(contextid=context_id, name="argus_user")
                zap.users.set_authentication_credentials(
                    contextid=context_id,
                    userid=user_id,
                    credentialsConfigParams=f"username={username}&password={password}"
                )
                zap.users.set_user_enabled(contextid=context_id, userid=user_id, enabled="true")
                zap.forcedUser.set_forced_user(contextid=context_id, userid=user_id)
                zap.forcedUser.set_forced_user_mode_enabled(enabled="true")
                logger.info(f"ZAP Forced User 설정 완료 (User ID: {user_id})")
        except Exception as e:
            logger.error(f"ZAP 인증 설정 중 오류 발생: {e}")

    # ── 2. 사용자 정의 헤더/쿠키 설정 ──────────────────────────────────
    if custom_header:
        logger.info(f"사용자 정의 헤더/쿠키 치환 설정 적용: {custom_header}")
        try:
            # 기존 replacer 룰 초기화
            rules = zap.replacer.rules
            for rule in rules:
                if rule.get("description") == "argus_custom_header":
                    zap.replacer.remove_rule(description="argus_custom_header")
            
            # 새 헤더 주입 룰 추가
            if ":" in custom_header:
                header_name, header_value = custom_header.split(":", 1)
                zap.replacer.add_rule(
                    description="argus_custom_header",
                    enabled="true",
                    matchtype="REQ_HEADER",
                    matchregex="false",
                    matchstring=header_name.strip(),
                    replacement=header_value.strip(),
                    initiators=""
                )
        except Exception as e:
            logger.error(f"ZAP Replacer 설정 중 오류 발생: {e}")

    # ── Ajax Spider 실행 ──────────────────────────────────────────
    logger.info(f"Ajax Spider 시작: {target_url}")
    zap.ajaxSpider.scan(target_url)

    elapsed = 0
    while zap.ajaxSpider.status == "running":
        if elapsed >= max_wait_seconds:
            logger.warning(f"Ajax Spider 최대 대기시간({max_wait_seconds}s) 초과 — 강제 중단")
            zap.ajaxSpider.stop()
            break
        time.sleep(2)
        elapsed += 2

    found = zap.ajaxSpider.number_of_results
    logger.info(f"Ajax Spider 완료 — 발견된 리소스: {found}건")

    # ── 수집된 메시지에서 파라미터 추출 ──────────────────────────
    results: list[CollectedParam] = []

    messages = zap.core.messages(baseurl=target_url, start=0, count=500)
    for msg in messages:
        req_header   = msg.get("requestHeader", "")
        req_body     = msg.get("requestBody", "")
        resp_body    = msg.get("responseBody", "")

        if not req_header:
            continue

        parts        = req_header.split(" ")
        method       = parts[0] if parts else "GET"
        raw_url      = parts[1] if len(parts) > 1 else target_url
        content_type = _extract_content_type(req_header)

        # Query string 파라미터
        parsed = urlparse(raw_url)
        for key, values in parse_qs(parsed.query).items():
            results.append(CollectedParam(
                url=raw_url,
                method=method,
                param_name=key,
                param_value=values[0],
                param_type="query",
                content_type=content_type,
            ))

        # Body 파라미터 (JSON / form-urlencoded)
        results.extend(_parse_body_params(raw_url, method, req_body, content_type))

        # Hidden 필드 — Ajax Spider가 HTML을 렌더링한 응답 바디에서 추출
        results.extend(_parse_hidden_fields(raw_url, method, resp_body, content_type))

    logger.info(f"총 수집된 파라미터: {len(results)}개")
    return results


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _parse_body_params(
    url: str,
    method: str,
    body: str,
    content_type: str,
) -> list[CollectedParam]:
    """
    요청 바디에서 파라미터를 추출한다 (JSON / form-urlencoded).

    raw_body에 원본 body 전체를 담아둔다 — manipulator.py가 이 값을 baseline
    템플릿으로 삼아 변조 대상 필드 하나만 교체하고 나머지 필드는 보존한다.
    (예전에는 {param_name: value} 하나만 담아 보내서 다른 필수 필드가 빠져
    baseline/test 둘 다 400으로 거절되는 바람에 이상 탐지가 안 되는 문제가 있었음)
    """
    params: list[CollectedParam] = []
    if not body:
        return params

    if "application/json" in content_type:
        try:
            data = json.loads(body)
            for key, val in _flatten_json(data):
                params.append(CollectedParam(
                    url=url,
                    method=method,
                    param_name=key,
                    param_value=str(val),
                    param_type="body",
                    content_type=content_type,
                    raw_body=body,
                ))
        except json.JSONDecodeError:
            pass

    elif "application/x-www-form-urlencoded" in content_type:
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.append(CollectedParam(
                    url=url,
                    method=method,
                    param_name=k,
                    param_value=v,
                    param_type="body",
                    content_type=content_type,
                    raw_body=body,
                ))

    return params


def _parse_hidden_fields(
    url: str,
    method: str,
    html: str,
    content_type: str,
) -> list[CollectedParam]:
    """
    응답 HTML에서 <input type="hidden"> 필드를 추출한다.
    ZAP Ajax Spider가 HTML을 렌더링할 때 hidden 필드도 수집하지만,
    확실성을 위해 응답 바디에서 직접 한 번 더 파싱한다.
    """
    import re
    params: list[CollectedParam] = []
    if not html:
        return params

    pattern = re.compile(
        r'<input\b[^>]*type=["\']hidden["\'][^>]*>',
        re.IGNORECASE,
    )
    name_re  = re.compile(r'name=["\']([^"\']+)["\']',  re.IGNORECASE)
    value_re = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)

    for tag in pattern.findall(html):
        name_m = name_re.search(tag)
        if not name_m:
            continue
        value_m = value_re.search(tag)
        params.append(CollectedParam(
            url=url,
            method=method,
            param_name=name_m.group(1),
            param_value=value_m.group(1) if value_m else "",
            param_type="hidden",
            content_type=content_type,
        ))

    return params


def _flatten_json(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """중첩 JSON을 dot-notation 키로 평탄화한다."""
    items: list[tuple[str, Any]] = []
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
    """요청 헤더 문자열에서 Content-Type 값을 추출한다."""
    for line in header.splitlines():
        if line.lower().startswith("content-type:"):
            return line.split(":", 1)[1].strip().lower()
    return ""


def _resolve_path_params(path: str, *param_lists: list[dict]) -> str:
    """
    Swagger 경로의 `{name}` placeholder를 파라미터 스키마의 default/example 값으로 치환한다.

    치환하지 않으면 서버가 `{commentId}` 문자열 그대로 받아 타입 변환에 실패해
    baseline/test 요청이 항상 동일한 500 에러로 응답 — 이상 탐지가 무의미해진다.
    스키마에 값이 없으면 흔한 숫자 ID 패턴인 "1"로 폴백한다.
    """
    import re

    resolved = path
    for params in param_lists:
        for p in params:
            if p.get("in") != "path":
                continue
            name = p.get("name", "")
            placeholder = f"{{{name}}}"
            if not name or placeholder not in resolved:
                continue
            schema = p.get("schema", {})
            value = schema.get("default", schema.get("example", p.get("default", p.get("example", "1"))))
            resolved = resolved.replace(placeholder, str(value))

    # 스키마에 정의되지 않은 나머지 {placeholder}도 안전하게 "1"로 폴백
    return re.sub(r"\{[^{}]+\}", "1", resolved)


def _is_binary_schema(schema: dict) -> bool:
    """스키마(또는 array의 items)가 파일 업로드(format: binary)인지 확인한다."""
    if not isinstance(schema, dict):
        return False
    if schema.get("format") == "binary":
        return True
    items = schema.get("items")
    return isinstance(items, dict) and items.get("format") == "binary"


def _parse_swagger_spec(spec_url: str, custom_header: str = None) -> list[CollectedParam]:
    """
    Swagger/OpenAPI JSON 스키마 명세를 요청하여 파싱한 뒤 파라미터들을 수집한다.
    """
    import requests
    from urllib.parse import urljoin, urlparse

    headers = {}
    if custom_header:
        custom_header = custom_header.strip()
        if ":" in custom_header:
            h_name, h_val = custom_header.split(":", 1)
            headers[h_name.strip()] = h_val.strip()
        elif custom_header.startswith("Bearer "):
            headers["Authorization"] = custom_header
        elif custom_header.startswith("eyJ"):  # JWT 토큰 형태 직접 입력
            headers["Authorization"] = f"Bearer {custom_header}"
        else:
            # 기본적으로 Authorization 헤더로 매핑 시도
            headers["Authorization"] = custom_header

    # 쿼리스트링 제거하여 순수 Base URL 추출
    parsed_spec_url = urlparse(spec_url)
    clean_base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}{parsed_spec_url.path}".rstrip("/")

    # 스웨거 명세가 위치할 수 있는 경로 후보들 정의
    candidates = []
    # 사용자가 이미 .json이나 특정 스웨거 파일 경로를 직접 입력한 경우 최우선 시도
    if spec_url.endswith(".json") or "api-docs" in spec_url:
        candidates.append(spec_url)
    
    # 쿼리스트링을 제거한 주소 자체도 추가
    candidates.append(clean_base_url)
    # 대표적인 프레임워크별 스웨거 JSON 엔드포인트 후보 추가
    candidates.extend([
        f"{clean_base_url}/v3/api-docs",        # Spring Boot 3.x / springdoc
        f"{clean_base_url}/openapi.json",        # FastAPI / Python
        f"{clean_base_url}/swagger.json",        # Swagger 2.0 표준
        f"{clean_base_url}/api/openapi.json",    # 접두어가 들어간 경우
    ])

    spec = None
    actual_used_url = None
    for url in candidates:
        logger.debug(f"Swagger 후보 주소 시도 중: {url}")
        try:
            resp = requests.get(url, headers=headers, timeout=3)
            if resp.status_code == 200:
                # json 형식인지 검증
                spec = resp.json()
                # 최상위 키에 swagger, openapi, paths 등의 명세 포맷 확인
                if "paths" in spec or "openapi" in spec or "swagger" in spec:
                    actual_used_url = url
                    logger.info(f"사용 가능한 Swagger Spec을 발견했습니다: {url}")
                    break
        except Exception:
            continue

    if not spec:
        raise ValueError(f"제공된 URL({spec_url}) 또는 관련 후보 경로에서 유효한 Swagger OpenAPI Spec JSON을 찾을 수 없습니다.")

    # Base URL 해석
    # OpenAPI 3.0: servers[0].url
    # Swagger 2.0: host + basePath
    base_url = f"{parsed_spec_url.scheme}://{parsed_spec_url.netloc}"

    if "servers" in spec and spec["servers"]:
        server_url = spec["servers"][0].get("url", "")
        if server_url.startswith("http"):
            base_url = server_url
        else:
            base_url = urljoin(base_url, server_url)
    elif "host" in spec:
        host = spec["host"]
        base_path = spec.get("basePath", "")
        base_url = f"{parsed_spec_url.scheme}://{host}{base_path}"

    results: list[CollectedParam] = []
    paths = spec.get("paths", {})

    for path, path_obj in paths.items():
        # OpenAPI는 path 레벨에 공용 parameters를 둘 수 있음 (예: {commentId}가
        # 모든 method에 공통). "parameters"는 HTTP method 이름이 아니라서
        # 아래 method 필터에 걸러지므로 method loop와 안전하게 공존한다.
        path_level_params = path_obj.get("parameters", []) if isinstance(path_obj, dict) else []

        for method, method_obj in path_obj.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue

            params_list = method_obj.get("parameters", [])
            # {commentId} 같은 경로 파라미터를 실제 값으로 치환하지 않으면 서버가
            # 타입 변환에 실패해 baseline/test 둘 다 500이 나서 비교가 무의미해짐.
            resolved_path = _resolve_path_params(path, path_level_params, params_list)
            full_url = urljoin(base_url.rstrip("/") + "/", resolved_path.lstrip("/"))
            method = method.upper()

            # 1. parameters 파싱 (OpenAPI 2.0/3.0 공통 - query, path 등)
            #    파일(binary) 필드가 섞여 있으면 springdoc이 종종 이를 전부 "query"로
            #    잘못 문서화하지만(예: @ModelAttribute 업로드 DTO), 실제 서버는
            #    multipart/form-data를 기대한다. 이걸 개별 query 파라미터로 보내면
            #    Content-Type 불일치로 baseline/test가 항상 동일하게 500이 나서
            #    비교가 무의미해지므로, 이런 엔드포인트는 전체 필드를 하나의
            #    multipart body로 묶어서 보낸다.
            non_path_params = [p for p in params_list if p.get("in") != "path"]
            binary_names = {
                p.get("name", "") for p in non_path_params
                if p.get("name") and _is_binary_schema(p.get("schema", {}))
            }

            if binary_names:
                field_defaults = {
                    p.get("name", ""): str(p.get("schema", {}).get("default", p.get("default", "1")))
                    for p in non_path_params if p.get("name")
                }
                multipart_raw_body = json.dumps(field_defaults, ensure_ascii=False)
                multipart_binary_fields = ",".join(sorted(binary_names))
                for name, default_val in field_defaults.items():
                    results.append(CollectedParam(
                        url=full_url,
                        method=method,
                        param_name=name,
                        param_value=default_val,
                        param_type="body",
                        content_type="multipart/form-data",
                        raw_body=multipart_raw_body,
                        binary_fields=multipart_binary_fields,
                    ))
            else:
                # body/formData 파라미터는 baseline 전체 필드를 먼저 모아서
                # raw_body로 넘긴다 — manipulator.py가 변조 시 다른 필수 필드를
                # 지우지 않고 해당 필드만 교체할 수 있도록 하기 위함.
                body_defaults: dict[str, str] = {}
                for param in params_list:
                    if param.get("in") in ("formData", "body"):
                        schema = param.get("schema", {})
                        body_defaults[param.get("name", "")] = str(schema.get("default", param.get("default", "1")))
                body_defaults.pop("", None)
                legacy_raw_body = json.dumps(body_defaults, ensure_ascii=False) if body_defaults else ""

                for param in params_list:
                    in_type = param.get("in", "")
                    name = param.get("name", "")
                    # path 파라미터는 URL 변조 형태로 주입하거나 건너뜀 (여기서는 query와 body 우선)
                    param_type = "query" if in_type == "query" else "body" if in_type in ("formData", "body") else None

                    if param_type and name:
                        schema = param.get("schema", {})
                        default_val = str(schema.get("default", param.get("default", "1")))
                        results.append(CollectedParam(
                            url=full_url,
                            method=method,
                            param_name=name,
                            param_value=default_val,
                            param_type=param_type,
                            content_type="application/json" if in_type == "body" else "application/x-www-form-urlencoded" if in_type == "formData" else "",
                            raw_body=legacy_raw_body if param_type == "body" else "",
                        ))

            # 2. requestBody 파싱 (OpenAPI 3.0 구조)
            #    동일한 이유로, 스키마의 모든 property 기본값을 먼저 모아 하나의
            #    baseline body(raw_body)를 만든 뒤 각 property의 CollectedParam에 붙인다.
            #    binary(format=binary) 프로퍼티가 있으면 multipart/form-data로 처리한다.
            req_body = method_obj.get("requestBody", {})
            content_dict = req_body.get("content", {})
            for content_type, media_type_obj in content_dict.items():
                schema = media_type_obj.get("schema", {})

                # $ref 참조 해결
                if "$ref" in schema:
                    schema = _resolve_ref(schema["$ref"], spec)

                if schema.get("type") == "object":
                    properties = schema.get("properties", {})
                    full_body = {name: str(prop.get("default", "1")) for name, prop in properties.items()}
                    raw_body = json.dumps(full_body, ensure_ascii=False) if full_body else ""
                    body_binary_names = {name for name, prop in properties.items() if _is_binary_schema(prop)}
                    effective_content_type = "multipart/form-data" if body_binary_names else content_type
                    binary_fields_str = ",".join(sorted(body_binary_names))

                    for prop_name, prop_obj in properties.items():
                        default_val = str(prop_obj.get("default", "1"))
                        results.append(CollectedParam(
                            url=full_url,
                            method=method,
                            param_name=prop_name,
                            param_value=default_val,
                            param_type="body",
                            content_type=effective_content_type,
                            raw_body=raw_body,
                            binary_fields=binary_fields_str,
                        ))

    logger.info(f"Swagger 파싱 완료: {len(results)}개 파라미터 수집")
    return results


def _resolve_ref(ref_path: str, spec: dict) -> dict:
    """Swagger $ref 참조 패스를 해석하여 실제 객체를 찾아 반환한다."""
    if not ref_path.startswith("#/"):
        return {}
    parts = ref_path.lstrip("#/").split("/")
    cur = spec
    for part in parts:
        cur = cur.get(part, {})
    return cur

