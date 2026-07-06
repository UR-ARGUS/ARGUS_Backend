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
import uuid
from typing import Any
from urllib.parse import urlparse, parse_qs, urljoin

import requests
from zapv2 import ZAPv2

from argus.core.config import settings
from .models import CollectedParam

logger = logging.getLogger(__name__)


def collect_params(
    target_url: str,
    max_wait_seconds: int = 120,
    login_config: dict = None,
    custom_header: str = None,
    progress_callback=None,
    api_base_url: str = None,
) -> list[CollectedParam]:
    """
    Swagger Spec과 ZAP Ajax Spider를 상호보완적으로 병행해 파라미터 목록을 수집한다.

    Args:
        target_url:        크롤링 대상 URL (SPA 프론트엔드) 혹은 Swagger/OpenAPI Spec JSON URL
        max_wait_seconds:  Ajax Spider 완료 대기 최대 시간 (초)
        login_config:      자동 로그인 설정 정보
        custom_header:     사용자 정의 헤더/쿠키 문자열
        progress_callback: Callable[[int], None] — Ajax Spider 대기 중 진행률(0~100)을 보고
        api_base_url:      백엔드 API 서버 URL. 주어지면 Swagger Spec에서 비즈니스 파라미터를
                            먼저 확보하고, target_url은 별도로 ZAP Ajax Spider로 크롤링해
                            Swagger에 없는 파라미터만 보완한다 (중복 제거).

    Returns:
        List[CollectedParam]
    """
    # ── Swagger / OpenAPI Spec 파싱 ──────────────────────────────────
    # api_base_url이 주어지면 target_url(프론트엔드)과 별도로 Swagger를 우선 확보하고
    # 아래에서 ZAP 크롤링도 이어서 수행해 보완한다 (하위 dedupe 로직 참고).
    # api_base_url이 없고 target_url 자체가 spec URL 패턴이면 기존처럼 Swagger 단독 처리.
    swagger_params: list[CollectedParam] = []
    swagger_spec_url = api_base_url
    if not swagger_spec_url and (
        "swagger_scan=true" in target_url
        or target_url.endswith(".json")
        or "swagger" in target_url.lower()
        or "openapi" in target_url.lower()
    ):
        swagger_spec_url = target_url

    if swagger_spec_url:
        logger.info(f"Swagger/OpenAPI Spec 연동 진단을 감지했습니다: {swagger_spec_url}")
        try:
            swagger_params = _parse_swagger_spec(swagger_spec_url, custom_header)
        except Exception as e:
            logger.error(f"Swagger 파싱 실패: {e}. ZAP 크롤링만으로 진행합니다.")

        if not api_base_url:
            # target_url 자체가 spec URL인 레거시 경로 — 별도로 크롤링할 프론트엔드
            # URL이 없으므로 Swagger 결과만 반환한다.
            return swagger_params

    zap = ZAPv2(
        apikey=settings.ZAP_API_KEY or None,
        proxies={
            "http":  settings.ZAP_API_URL,
            "https": settings.ZAP_API_URL,
        },
    )

    # ZAP은 데몬으로 계속 떠 있어 세션(사이트 트리/HTTP 히스토리)이 스캔 간에
    # 그대로 유지된다. 세션을 초기화하지 않으면 아래 zap.core.messages()가
    # 이번 스캔이 아니라 과거 스캔들에서 누적된 메시지까지 그대로 돌려줘서,
    # 크롤링이 사실상 새로 일어나지 않았는데도 이전 스캔과 동일한 결과가
    # 반복되는 문제가 있었다 (실측: 서로 다른 두 스캔의 파라미터 985건이
    # 완전히 동일하게 나옴). 매 스캔마다 새 세션으로 초기화해 이전 히스토리를
    # 제거한다.
    try:
        zap.core.new_session(name=f"argus_session_{uuid.uuid4().hex[:8]}", overwrite=True)
    except Exception as e:
        logger.warning(f"ZAP 세션 초기화 실패 (무시하고 진행 — 이전 스캔 히스토리가 섞일 수 있음): {e}")

    # Vite 개발 서버는 node_modules 의존성 번들(react-dom 1MB+ 등)을 그대로 서빙하는데,
    # ZAP의 passive scan이 이런 대용량 서드파티 파일을 반복적으로 스캔하다가 힙/CPU가
    # 고갈되어 프록시 자체가 응답 불능/크래시에 빠진다 (실측: 힙 2GB에서도 300초 크롤링
    # 중 crash). exclude_from_proxy(URL 정규식 제외)는 Ajax Spider 트래픽엔 적용되지
    # 않아 효과가 없었음 — 이 도구는 애초에 zap.core.messages()로 원본 요청/응답만
    # 읽고 zap.core.alerts() 등 ZAP 자체 분석 결과는 전혀 쓰지 않으므로,
    # passive scan을 통째로 꺼서 리소스 경합의 근본 원인을 없앤다.
    try:
        zap.pscan.set_enabled(enabled="false")
    except Exception as e:
        logger.warning(f"ZAP passive scan 비활성화 실패 (무시하고 진행): {e}")

    # Ajax Spider(Crawljax)는 기본값이 CPU 코어 수만큼 브라우저를 병렬로 띄우는데
    # (실측 16~19개), 이 머신처럼 여유 메모리가 빠듯하면 GC가 API 서버 스레드를
    # 순간적으로 멈춰 세워 프록시 연결이 끊기고 힙이 부족하면 크래시까지 간다.
    # 크롤링은 느려지지만 안정성을 위해 병렬 브라우저 수를 낮게 고정한다.
    #
    # (한때 1로 낮춰 Vite HMR WebSocket 핸드셰이크 경합으로 인한
    # ZAP WebSocketException("Already created")을 줄여봤으나, 크롤링 커버리지
    # 트레이드오프 때문에 롤백 — 필요하면 다시 1로 낮추는 것을 검토할 것.)
    try:
        zap.ajaxSpider.set_option_number_of_browsers(2)
    except Exception as e:
        logger.warning(f"ZAP Ajax Spider 동시성 설정 실패 (무시하고 진행): {e}")

    # ── 1. 인증(로그인) 처리 ──────────────────────────────────────────
    context_id = None
    login_context_name = None
    login_user_name = None
    if login_config:
        logger.info("자동 로그인 설정 시작...")
        try:
            # ZAP은 데몬으로 계속 떠 있어 스캔마다 이름이 겹치면 동일 이름의 context/user가
            # 계속 누적되어 이름 기반 조회(zap.context.context(name) 등)가 어느 걸 가리키는지
            # 모호해진다 (실측: 반복 실행 후 유저 생성이 알 수 없는 오류로 실패하는 현상 발생).
            # 매 스캔마다 고유한 이름을 써서 이 문제를 원천 차단한다.
            run_suffix = uuid.uuid4().hex[:8]
            context_name = f"argus_context_{run_suffix}"
            context_id = zap.context.new_context(context_name)

            # 대상 URL을 컨텍스트에 포함
            # 뒤에 "/.*"만 붙이면 target_url 자체(트레일링 슬래시 없는 루트, 예: http://host:5173)는
            # 이 정규식에 매치되지 않아 컨텍스트 밖으로 취급된다 — scan_as_user가
            # "url_not_in_context"를 반환하며 크롤링 자체를 거부하는 문제가 있었다.
            # 루트 URL 자체와 그 하위 경로를 모두 포함하도록 옵셔널 그룹으로 감싼다.
            zap.context.include_in_context(context_name, f"{target_url.rstrip('/')}(/.*)?")

            # 로그인 파라미터 파싱
            login_url = login_config.get("login_url")
            username_field = login_config.get("username_field", "username")
            password_field = login_config.get("password_field", "password")
            username = login_config.get("username")
            password = login_config.get("password")
            # 로그인 API가 JSON body를 받는 경우("content_type": "json") jsonBasedAuthentication을
            # 사용한다 — formBasedAuthentication은 x-www-form-urlencoded로만 보내서
            # JSON 전용 로그인 API(예: {"email": "...", "password": "..."})에는 안 먹힘.
            login_content_type = login_config.get("content_type", "form")

            if login_url and username and password:
                from urllib.parse import quote

                if login_content_type == "json":
                    # ZAP 플레이스홀더({%username%}/{%password%})는 인증 시점에 실제 자격증명으로 치환됨
                    json_template = json.dumps({username_field: "{%username%}", password_field: "{%password%}"})
                    auth_method_name = "jsonBasedAuthentication"
                    login_request_data = quote(json_template, safe="")
                else:
                    login_request_data = f"{username_field}={username}&{password_field}={password}"
                    auth_method_name = "formBasedAuthentication"

                zap.authentication.set_authentication_method(
                    contextid=context_id,
                    authmethodname=auth_method_name,
                    authmethodconfigparams=f"loginUrl={quote(login_url, safe='')}&loginRequestData={login_request_data}"
                )

                # 유저 생성 및 활성화
                # 주의: zapv2 라이브러리의 실제 키워드 인자명은 authcredentialsconfigparams
                # (소문자) — credentialsConfigParams로 호출하면 TypeError가 나서
                # 이 인증 설정 전체가 예외로 삼켜져 조용히 무시되고 있었음.
                user_id = zap.users.new_user(contextid=context_id, name=f"argus_user_{run_suffix}")
                if not str(user_id).isdigit():
                    # ZAP API가 에러 메시지를 응답 본문에 담아 200으로 돌려주는 경우가 있어
                    # 여기서 명시적으로 걸러내지 않으면 이후 인증 설정이 전부 무의미해진다.
                    raise RuntimeError(f"zap.users.new_user 실패 — 유효하지 않은 user_id: {user_id!r}")
                zap.users.set_authentication_credentials(
                    contextid=context_id,
                    userid=user_id,
                    authcredentialsconfigparams=f"username={quote(username, safe='')}&password={quote(password, safe='')}"
                )
                zap.users.set_user_enabled(contextid=context_id, userid=user_id, enabled="true")
                zap.forcedUser.set_forced_user(contextid=context_id, userid=user_id)
                # 이 메서드는 위치 인자 이름이 boolean이라 enabled= 로 호출하면 TypeError
                zap.forcedUser.set_forced_user_mode_enabled("true")
                # Ajax Spider를 scan_as_user로 명시적으로 이 사용자로 돌리기 위해 이름을 남겨둔다
                # (Forced User Mode만 켜두는 것보다 명시적 지정이 더 확실하게 적용됨)
                login_context_name = context_name
                login_user_name = f"argus_user_{run_suffix}"
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
    if login_context_name and login_user_name:
        # Forced User Mode만 켜두는 것보다 특정 사용자로 명시 지정하는 쪽이 더 확실하게 적용된다
        zap.ajaxSpider.scan_as_user(contextname=login_context_name, username=login_user_name, url=target_url)
    else:
        zap.ajaxSpider.scan(target_url)

    # scan()/scan_as_user()는 비동기로 크롤을 시작시키지만 zap.ajaxSpider.status가
    # "running"으로 전환되기까지 짧은 지연이 있다. 이 지연 중에 곧바로 아래
    # while문에서 상태를 확인하면 직전 스캔의 잔여 상태("stopped")가 그대로
    # 읽혀 루프가 한 번도 돌지 않고 즉시 빠져나가 크롤링이 전혀 일어나지
    # 않은 채 "완료" 처리되는 문제가 있었다 (실측: 시작 244ms 만에 완료 로그
    # 찍힘). 상태가 실제로 "running"으로 전환될 때까지 최대 10초 대기한다.
    warmup_elapsed = 0
    while zap.ajaxSpider.status != "running" and warmup_elapsed < 10:
        time.sleep(1)
        warmup_elapsed += 1
    if zap.ajaxSpider.status != "running":
        logger.warning(
            "Ajax Spider가 시작 신호(running)를 받지 못했습니다 — "
            "크롤링 결과가 비어있거나 불완전할 수 있습니다."
        )

    elapsed = 0
    if progress_callback:
        progress_callback(0)
    while zap.ajaxSpider.status == "running":
        if elapsed >= max_wait_seconds:
            logger.warning(f"Ajax Spider 최대 대기시간({max_wait_seconds}s) 초과 — 강제 중단")
            zap.ajaxSpider.stop()
            break
        time.sleep(2)
        elapsed += 2
        if progress_callback:
            # 크롤링 자체의 실제 완료율은 알 수 없으므로(AjaxSpider는 퍼센트를
            # 제공하지 않음) 최대 대기시간 대비 경과 시간으로 근사한다.
            progress_callback(min(99, int(elapsed / max_wait_seconds * 100)))

    if progress_callback:
        progress_callback(100)

    found = zap.ajaxSpider.number_of_results
    logger.info(f"Ajax Spider 완료 — 발견된 리소스: {found}건")

    # ── 수집된 메시지에서 파라미터 추출 ──────────────────────────
    results: list[CollectedParam] = []

    # count=500을 한 번에 요청하면 요청/응답 바디가 큰 메시지(대용량 JS 번들 등)가
    # 섞여있을 때 ZAP이 응답 JSON을 직렬화하다가 힙이 고갈되어 OutOfMemoryError로
    # 커넥션이 끊기는 문제가 있었다 (실측: zap.log에 JSONArray.toString 중 OOM).
    # 페이지 단위로 나눠 받아 한 번에 직렬화되는 응답 크기를 줄인다.
    page_size = 100
    messages: list[dict] = []
    start = 0
    while True:
        page = zap.core.messages(baseurl=target_url, start=start, count=page_size)
        if not page:
            break
        messages.extend(page)
        if len(page) < page_size:
            break
        start += page_size

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

    logger.info(f"ZAP 크롤링으로 수집된 파라미터: {len(results)}개")

    # 실시간 재계산 위젯(예: 보험료 계산기)처럼 Ajax Spider가 같은 요청을 페이지
    # 탐색 중 여러 번 캡처하는 엔드포인트가 있다 — 중복 제거 없이 그대로 두면
    # 그 엔드포인트 하나의 파라미터가 캡처 횟수만큼 부풀려져 커버리지/페이로드
    # 요청량을 왜곡한다 (실측: 보험료 계산 API 하나가 동일 payload로 10건 이상
    # 중복 집계됨). collect_params 마지막에 한 번만 적용해 이후 로직(Swagger
    # 병합 등)은 이미 중복 제거된 목록을 기준으로 동작하게 한다.
    before_dedupe = len(results)
    results = _dedupe_collected(results)
    if before_dedupe != len(results):
        logger.info(f"ZAP 중복 캡처 제거: {before_dedupe}개 → {len(results)}개")

    if swagger_params:
        # Swagger가 이미 다루는 (method, path, param_name) 조합은 ZAP 쪽에서 제외한다 —
        # 같은 API를 두 경로가 중복 수집하면 Phase 3 페이로드 주입 요청량이 배로 늘어남.
        # 쿼리스트링/호스트 차이는 무시하고 path만 비교 (Swagger의 resolved_path 값과
        # ZAP이 실제로 크롤링 중 관측한 URL의 path가 같은 엔드포인트를 가리키기 때문).
        swagger_keys = {(p.method, urlparse(p.url).path, p.param_name) for p in swagger_params}
        deduped_zap = [
            p for p in results
            if (p.method, urlparse(p.url).path, p.param_name) not in swagger_keys
        ]
        logger.info(
            f"Swagger {len(swagger_params)}건 + ZAP 보완 {len(deduped_zap)}건 "
            f"(중복 제외 {len(results) - len(deduped_zap)}건) — 총 {len(swagger_params) + len(deduped_zap)}개"
        )
        return swagger_params + deduped_zap

    return results


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _dedupe_collected(params: list[CollectedParam]) -> list[CollectedParam]:
    """
    (url, method, param_name, param_type, raw_body)가 완전히 같은 CollectedParam은
    ZAP Ajax Spider가 크롤링 중 동일한 요청을 여러 번 캡처했을 때 생기는 순수 중복이다.
    이걸 그대로 두면 Phase 3가 같은 요청을 여러 번 재전송하고, 결과적으로 같은
    취약점 하나가 findings에 N번 찍혀 실제보다 부풀려진 개수로 보고된다
    (실측: 보험료 계산 API 하나가 동일 payload로 10건씩 중복 집계됨).
    각 조합의 첫 번째 항목만 남긴다.
    """
    seen: set[tuple] = set()
    deduped: list[CollectedParam] = []
    for p in params:
        key = (p.url, p.method, p.param_name, p.param_type, p.raw_body)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)
    return deduped


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


def _pick_default_value(schema: dict, param: dict = None) -> str:
    """
    스키마/파라미터에서 baseline으로 쓸 값을 고른다.
    우선순위: 명시된 default → enum 첫 값 → example → 타입별 제네릭 폴백("1"/"true").

    enum이 정의된 필드(예: status)에 default가 없다고 무조건 "1"을 쓰면, 서버가 그 값을
    무시하거나 거부해 baseline 응답 자체가 비정상이 되고, 이후 정상적인 enum 값으로 만든
    test 요청과 비교할 때 실제로는 없는 차이가 이상 탐지로 잘못 잡히는 문제가 있었다.
    enum 첫 값을 baseline으로 쓰면 최소한 "그 서비스가 실제로 받아들이는 값"에서
    출발하므로 이 오탐이 크게 줄어든다.
    """
    if "default" in schema:
        return str(schema["default"])
    if param and "default" in param:
        return str(param["default"])
    enum_vals = schema.get("enum")
    if enum_vals:
        return str(enum_vals[0])
    if param and "example" in param:
        return str(param["example"])
    if "example" in schema:
        return str(schema["example"])
    return {"boolean": "true"}.get(schema.get("type", ""), "1")


def _extract_enum_values(schema: dict) -> str:
    """스키마에 정의된 enum 후보값을 콤마 구분 문자열로 반환한다 (없으면 빈 문자열)."""
    enum_vals = schema.get("enum")
    return ",".join(str(v) for v in enum_vals) if enum_vals else ""


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
            value = _pick_default_value(schema, p)
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

    # 게이트웨이 뒤에 여러 마이크로서비스/모듈이 그룹별 문서로 나뉜 경우
    # (예: user-api, booking-api 등), 아래 고정 4개 후보만으로는 게이트웨이 루트의
    # 그룹 "목록" 문서만 보이고 각 그룹이 실제로 소유한 엔드포인트(스키마)는 전혀
    # 수집되지 않는다. 그룹 목록 엔드포인트가 있으면 우선 그걸로 그룹별 spec을
    # 전부 가져와 병합하고, 없으면(단일 모듈 서비스) 기존 고정 후보 방식으로 폴백한다.
    grouped_specs = _discover_grouped_specs(clean_base_url, headers)
    if grouped_specs:
        results: list[CollectedParam] = []
        for group_spec_url, group_spec in grouped_specs:
            results.extend(_extract_params_from_spec(group_spec, group_spec_url))
        logger.info(f"Swagger 그룹 스펙 {len(grouped_specs)}개 병합 파싱 완료: {len(results)}개 파라미터 수집")
        return results

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

    results = _extract_params_from_spec(spec, actual_used_url)
    logger.info(f"Swagger 파싱 완료: {len(results)}개 파라미터 수집")
    return results


def _discover_grouped_specs(clean_base_url: str, headers: dict) -> list[tuple[str, dict]]:
    """
    springdoc(`/v3/api-docs/swagger-config`) 또는 springfox(`/swagger-resources`)의
    그룹형 멀티 모듈 API 문서 목록 엔드포인트를 조회해, 그룹별 (spec_url, spec) 목록을
    반환한다. 게이트웨이 하나에 여러 마이크로서비스가 물려 있는 서비스는 API 문서도
    그룹별로 나뉘어 있는 경우가 흔한데, 이 목록 엔드포인트를 거치지 않으면 게이트웨이
    루트에서 고정 경로(`/v3/api-docs` 등)로는 그룹 목록 문서만 보이고 각 그룹이 실제로
    소유한 엔드포인트(스키마)는 전혀 수집되지 않는다.

    그룹 목록 자체가 없는(= 단일 모듈 서비스) 경우 빈 리스트를 반환해 호출부가
    기존 고정 후보 방식으로 폴백하게 한다.
    """
    group_list_candidates = [
        (f"{clean_base_url}/v3/api-docs/swagger-config", "springdoc"),
        (f"{clean_base_url}/swagger-resources", "springfox"),
    ]

    for list_url, kind in group_list_candidates:
        try:
            resp = requests.get(list_url, headers=headers, timeout=3)
            if resp.status_code != 200:
                continue
            data = resp.json()
        except Exception:
            continue

        # springdoc: {"urls": [{"url": "/v3/api-docs/user-api", "name": "user-api"}, ...]}
        # springfox: [{"url": "/v2/api-docs?group=user-api", "name": "user-api"}, ...]
        entries = data.get("urls") if isinstance(data, dict) else data
        if not isinstance(entries, list) or not entries:
            continue

        grouped: list[tuple[str, dict]] = []
        for entry in entries:
            group_path = entry.get("url") if isinstance(entry, dict) else None
            if not group_path:
                continue
            group_spec_url = (
                group_path if group_path.startswith("http")
                else urljoin(clean_base_url + "/", group_path.lstrip("/"))
            )
            try:
                spec_resp = requests.get(group_spec_url, headers=headers, timeout=3)
                if spec_resp.status_code != 200:
                    continue
                group_spec = spec_resp.json()
                if "paths" in group_spec or "openapi" in group_spec or "swagger" in group_spec:
                    grouped.append((group_spec_url, group_spec))
            except Exception:
                continue

        if grouped:
            logger.info(
                f"{kind} 그룹형 API 문서 발견 — {len(grouped)}개 그룹: "
                f"{[u for u, _ in grouped]}"
            )
            return grouped

    return []


def _extract_params_from_spec(spec: dict, spec_url: str) -> list[CollectedParam]:
    """파싱된 단일 OpenAPI/Swagger spec 딕셔너리에서 CollectedParam 목록을 추출한다."""
    parsed_spec_url = urlparse(spec_url)

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
                    p.get("name", ""): _pick_default_value(p.get("schema", {}), p)
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
                        body_defaults[param.get("name", "")] = _pick_default_value(schema, param)
                body_defaults.pop("", None)
                legacy_raw_body = json.dumps(body_defaults, ensure_ascii=False) if body_defaults else ""

                for param in params_list:
                    in_type = param.get("in", "")
                    name = param.get("name", "")
                    # path 파라미터는 URL 변조 형태로 주입하거나 건너뜀 (여기서는 query와 body 우선)
                    param_type = "query" if in_type == "query" else "body" if in_type in ("formData", "body") else None

                    if param_type and name:
                        schema = param.get("schema", {})
                        default_val = _pick_default_value(schema, param)
                        results.append(CollectedParam(
                            url=full_url,
                            method=method,
                            param_name=name,
                            param_value=default_val,
                            param_type=param_type,
                            content_type="application/json" if in_type == "body" else "application/x-www-form-urlencoded" if in_type == "formData" else "",
                            raw_body=legacy_raw_body if param_type == "body" else "",
                            enum_values=_extract_enum_values(schema),
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
                    full_body = {name: _pick_default_value(prop) for name, prop in properties.items()}
                    raw_body = json.dumps(full_body, ensure_ascii=False) if full_body else ""
                    body_binary_names = {name for name, prop in properties.items() if _is_binary_schema(prop)}
                    effective_content_type = "multipart/form-data" if body_binary_names else content_type
                    binary_fields_str = ",".join(sorted(body_binary_names))

                    for prop_name, prop_obj in properties.items():
                        default_val = _pick_default_value(prop_obj)
                        results.append(CollectedParam(
                            url=full_url,
                            method=method,
                            param_name=prop_name,
                            param_value=default_val,
                            param_type="body",
                            content_type=effective_content_type,
                            raw_body=raw_body,
                            binary_fields=binary_fields_str,
                            enum_values=_extract_enum_values(prop_obj),
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

