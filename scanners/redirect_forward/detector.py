"""
detector.py — Phase 3: 페이로드 주입 + Reflected 리다이렉트/포워드 판별

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-5

역할:
    - candidates.py(Phase 2)가 골라낸 후보 파라미터마다 payloads.py의 외부 목적지
      페이로드를 주입해 요청을 전송한다.
    - "같은 요청/응답 왕복" 안에서 그 값이 검증 없이 그대로 반영되는지만 판별한다
      (Reflected 전용). 응답을 저장했다가 다른 요청에서 실행되는 Stored 케이스는
      별도의 생성→저장 확인→트리거 흐름이 필요해 범위 밖 — 1-3의 verifier.py 같은
      후속 검증 단계는 이 모듈에 없다.
    - 반영 여부는 결정적 규칙(Location 헤더 / meta refresh / JS location 대입 /
      응답 본문 내 단순 반사에 payload_host 문자열 노출)로만 판단한다 — 1-3과 달리
      이 항목은 판단이 모호하지 않아 LLM 해석 단계(Phase 4)가 필요 없다.

주의:
    - allow_redirects=False로 요청해 Location 헤더를 직접 확인한다. requests가
      자동으로 리다이렉트를 따라가 버리면 Location 헤더 자체가 사라져 판별이 불가능해진다.
    - 요청 타임아웃: TIMEOUT 상수 (기본 10초)
"""

import json
import logging
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

from scanners.param_manipulation.models import CollectedParam
from .models import RedirectCandidate, RedirectFinding
from .payloads import build_payloads, DEFAULT_PAYLOAD_HOST

logger  = logging.getLogger(__name__)
TIMEOUT = 10  # 초

_SUCCESS_STATUSES  = (200, 201)
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# <meta http-equiv="refresh" content="0;url=https://evil.com/"> 형태에서 url= 뒤 목적지 추출
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>]+)',
    re.IGNORECASE,
)

# location.href = "..." / window.location = "..." / document.location = "..." /
# location.replace("...") / .assign("...") 형태
_JS_REDIRECT_RE = re.compile(
    r'(?:(?:window|document)\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_GUIDE_REFERENCE = "SK Shieldus Web/API 개발보안 Guideline v3.0.0 항목 1-5 대응방안 참조"


def probe_candidate(
    candidate:      RedirectCandidate,
    payload_host:   str = DEFAULT_PAYLOAD_HOST,
    custom_header:  str = None,
) -> list[RedirectFinding]:
    """
    단일 RedirectCandidate에 대해 페이로드를 주입하고 Reflected 여부를 판별한다.

    Returns:
        list[RedirectFinding] — 반영이 확인된 항목만 (이상 없으면 빈 리스트)
    """
    c = candidate.collected
    parsed_target   = urlparse(c.url)
    payloads        = build_payloads(payload_host=payload_host, allowlisted_host=parsed_target.netloc)

    baseline = _send(c, c.param_value, custom_header)

    findings: list[RedirectFinding] = []
    for payload_val, payload_desc in payloads:
        test = _send(c, payload_val, custom_header)
        finding = _judge(c, payload_val, payload_desc, baseline, test, payload_host)
        if finding:
            findings.append(finding)
            logger.info(
                f"[1-5][Phase 3] Reflected 리다이렉트 확인 — {finding.detection_type} | "
                f"{c.url} | {c.param_name}={payload_val!r}"
            )

    return findings


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _judge(
    c:             CollectedParam,
    payload_val:   str,
    payload_desc:  str,
    baseline:      dict,
    test:          dict,
    payload_host:  str,
) -> RedirectFinding | None:
    """baseline/test 응답을 보고 payload_host가 그대로 반영됐는지 판별한다."""
    if test["status"] == -1:
        return None

    host_needle = payload_host.lower()

    # ── 패턴 1: Location 헤더 반영 (서버 사이드 리다이렉트 — 가장 확실한 증거) ──
    location = test.get("location", "")
    if test["status"] in _REDIRECT_STATUSES and host_needle in location.lower():
        return RedirectFinding(
            url=c.url, method=c.method, param_name=c.param_name,
            payload_used=payload_val, payload_description=payload_desc,
            detection_type="LOCATION_HEADER",
            evidence=f"Location: {location}",
            baseline_status=baseline["status"], test_status=test["status"],
            severity="HIGH",
            confirmed_redirect=True,
            description=(
                f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지가 서버 검증 없이 "
                f"HTTP {test['status']} 응답의 Location 헤더에 그대로 반영됩니다. "
                f"공격자가 이 파라미터를 조작한 링크를 배포하면 피해자를 피싱/악성 사이트로 "
                f"리다이렉트시킬 수 있습니다."
            ),
            recommendation=(
                "목적지 URL을 파라미터로 직접 받지 말고, 사전에 정의한 경로/도메인 화이트리스트 "
                f"중에서만 선택하도록 서버측 검증을 적용하세요. ({_GUIDE_REFERENCE})"
            ),
            request_body=test.get("request_body", ""),
        )

    # ── 패턴 2/3: 응답 본문 내 클라이언트 사이드 리다이렉트 반영 ──
    # 3xx 응답이라도 body에 meta refresh/JS redirect가 함께 포함될 수 있으므로
    # 상태코드 조건 없이 body 유무만으로 검사한다.
    # search()로 첫 매치 하나만 보면, 페이로드와 무관한 조건부 리다이렉트가 본문
    # 앞부분에 먼저 나오고 실제 반영은 뒤쪽 매치에서만 일어나는 경우(SPA 라우팅
    # 분기 등)를 놓친다 — finditer()로 모든 매치를 훑어 payload_host가 하나라도
    # 나오면 반영으로 판정한다.
    if test.get("body"):
        meta_match = next(
            (m for m in _META_REFRESH_RE.finditer(test["body"]) if host_needle in m.group(1).lower()),
            None,
        )
        if meta_match:
            return RedirectFinding(
                url=c.url, method=c.method, param_name=c.param_name,
                payload_used=payload_val, payload_description=payload_desc,
                detection_type="META_REFRESH",
                evidence=meta_match.group(0)[:300],
                baseline_status=baseline["status"], test_status=test["status"],
                severity="MEDIUM",
                confirmed_redirect=True,
                description=(
                    f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지가 응답 본문의 "
                    f"<meta http-equiv=\"refresh\"> 태그에 그대로 반영되어, 브라우저가 페이지를 "
                    f"자동으로 외부 사이트로 이동시킬 수 있습니다."
                ),
                recommendation=(
                    "클라이언트 사이드 리다이렉트에 사용할 목적지도 서버측 화이트리스트 검증을 "
                    f"거치도록 하세요. ({_GUIDE_REFERENCE})"
                ),
                request_body=test.get("request_body", ""),
            )

        js_match = next(
            (m for m in _JS_REDIRECT_RE.finditer(test["body"]) if host_needle in m.group(1).lower()),
            None,
        )
        if js_match:
            return RedirectFinding(
                url=c.url, method=c.method, param_name=c.param_name,
                payload_used=payload_val, payload_description=payload_desc,
                detection_type="JS_REDIRECT",
                evidence=js_match.group(0)[:300],
                baseline_status=baseline["status"], test_status=test["status"],
                severity="MEDIUM",
                confirmed_redirect=True,
                description=(
                    f"'{c.param_name}' 파라미터에 주입한 미검증 외부 목적지가 응답에 포함된 "
                    f"JavaScript의 location 대입 코드에 그대로 반영되어, 페이지 로드 시 브라우저가 "
                    f"외부 사이트로 이동될 수 있습니다."
                ),
                recommendation=(
                    "JS로 처리하는 리다이렉트도 서버가 내려준 값이 화이트리스트 안에 있는지 "
                    f"검증한 뒤에만 location에 대입하도록 하세요. ({_GUIDE_REFERENCE})"
                ),
                request_body=test.get("request_body", ""),
            )

        # ── 패턴 4: 단순 반사(Reflected) — 리다이렉트 문맥(Location/meta refresh/JS 대입)과
        # 무관하게, 주입한 외부 목적지 문자열이 응답 본문에 검증 없이 그대로 노출되는지만 본다.
        # 위 패턴들이 이미 실제 리다이렉트 실행 증거를 잡아내므로, 여기서는 그 외 나머지
        # 케이스(JSON 필드 echo, 에러 메시지 등)에서 payload_host 문자열 자체가 그대로
        # 반사되는지만 결정적으로 판별한다.
        body_lower = test["body"].lower()
        if host_needle in body_lower:
            idx = body_lower.find(host_needle)
            snippet = test["body"][max(0, idx - 100): idx + 100]
            return RedirectFinding(
                url=c.url, method=c.method, param_name=c.param_name,
                payload_used=payload_val, payload_description=payload_desc,
                detection_type="REFLECTED_VALUE",
                evidence=snippet,
                baseline_status=baseline["status"], test_status=test["status"],
                severity="LOW",
                confirmed_redirect=False,
                description=(
                    f"[반사만 확인됨 — 리다이렉트 실행 증거 없음] '{c.param_name}' 파라미터에 주입한 "
                    f"미검증 외부 목적지 문자열이 응답 본문에 검증 없이 그대로 반사(echo)됩니다. "
                    f"Location 헤더/meta refresh/JS location 대입 등 실제 리다이렉트 실행 증거는 "
                    f"확인되지 않았으므로 1-5 확정 취약점은 아니며, 참고용 정보 노출 신호로만 "
                    f"취급해야 합니다. (예: 타입 검증 실패 에러 메시지가 입력값을 그대로 포함하는 "
                    f"경우에도 이 패턴이 발생하며, 이는 실제 리다이렉트와 무관합니다.)"
                ),
                recommendation=(
                    "사용자 입력을 응답에 반사하기 전에 화이트리스트 검증을 적용하거나, 반사가 "
                    f"불필요하다면 해당 값을 응답에서 제거하세요. ({_GUIDE_REFERENCE})"
                ),
                request_body=test.get("request_body", ""),
            )

    return None


def _send(c: CollectedParam, value: str, custom_header: str = None) -> dict:
    """
    파라미터 값을 payload로 교체한 요청을 전송하고
    {"status": int, "body": str, "location": str, "request_body": str} 형태로 반환한다.
    리다이렉트를 자동으로 따라가지 않아야 Location 헤더를 확인할 수 있으므로
    allow_redirects=False로 고정한다. 요청 실패 시 status=-1.
    """
    req_headers = {}
    if "application/json" in (c.content_type or ""):
        req_headers["Content-Type"] = "application/json"

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

    request_body_repr = ""
    try:
        content_type = c.content_type or ""

        if "application/json" in content_type:
            body_obj = _apply_json(c.raw_body, c.param_name, value)
            request_body_repr = json.dumps(body_obj, ensure_ascii=False)
            resp = requests.request(
                c.method, c.url, timeout=TIMEOUT, json=body_obj,
                headers=req_headers, allow_redirects=False,
            )
        elif "application/x-www-form-urlencoded" in content_type:
            body_obj = _apply_form(c.raw_body, c.param_name, value)
            request_body_repr = urlencode(body_obj)
            resp = requests.request(
                c.method, c.url, timeout=TIMEOUT, data=body_obj,
                headers=req_headers, allow_redirects=False,
            )
        else:
            # query string (기본) — multipart/form-data 등 리다이렉트와 무관한 바이너리
            # 케이스는 1-5 대상이 아니므로 query 교체로 폴백해도 안전하다.
            parsed  = urlparse(c.url)
            qs      = parse_qs(parsed.query, keep_blank_values=True)
            qs[c.param_name] = [value]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            request_body_repr = f"(query string) {new_url}"
            resp = requests.request(
                c.method, new_url, timeout=TIMEOUT,
                headers=req_headers, allow_redirects=False,
            )

        return {
            "status":       resp.status_code,
            "body":         resp.text,
            "location":     resp.headers.get("Location", ""),  # CaseInsensitiveDict이므로 단일 조회로 충분
            "request_body": request_body_repr,
        }

    except requests.RequestException as e:
        logger.warning(f"요청 실패 ({c.method} {c.url} [{c.param_name}={value!r}]): {e}")
        return {"status": -1, "body": str(e), "location": "", "request_body": request_body_repr}


def _apply_json(raw_body: str, param_name: str, value: str) -> dict:
    """raw_body(JSON)를 파싱해 param_name 위치의 값만 교체하고 다른 필드는 보존한다."""
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


def _apply_form(raw_body: str, param_name: str, value: str) -> dict:
    """raw_body(form-urlencoded)를 파싱해 param_name 값만 교체하고 나머지 필드는 보존한다."""
    if not raw_body:
        return {param_name: value}
    qs = parse_qs(raw_body, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param_name] = value
    return flat
