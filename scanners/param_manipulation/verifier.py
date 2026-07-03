"""
verifier.py — Phase 3.5: 저장형(persisted) 권한 상승 후속 검증

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3

배경:
    comparator.py의 즉시 응답 diff(VALUE_ACCEPTED 등)는 조작한 요청의 "그 응답"에
    변조값이 그대로 반영될 때만 잡을 수 있다. 하지만 회원가입처럼 응답에 role이
    아예 노출되지 않는 API(예: {"success":true}만 반환)는 baseline/test 응답이
    완전히 동일하게 성공해서 즉시 diff로는 절대 못 잡는다 — 조작의 효과가 서버에
    "저장"만 되고, 그걸 확인하려면 별도 요청(로그인 후 프로필 조회)이 필요하다.
    (수동 진단에서 role 변조 가입이 실제로 통과한 걸 확인했는데 자동 스캔 결과에는
    하나도 안 잡힌 문제 — 원인은 정확히 이 지점이었음)

역할:
    - PRIVILEGE 카테고리 파라미터가 회원가입/계정생성으로 보이는 요청에 쓰였고
      조작된 값으로 요청이 성공(2xx)했을 때만 동작.
    - 그 요청에 실려 간 자격증명(아이디/비밀번호로 보이는 필드)을 추출해 로그인 시도.
    - 로그인에 성공하면 흔한 "내 정보" 엔드포인트 후보들을 순회 조회해 role 계열
      필드가 주입한 조작값과 일치하는지 확인.
    - 일치하면 RawFinding(PERSISTED_PRIVILEGE_ESCALATION, HIGH)을 만들어 반환.

한계 (휴리스틱 기반):
    - 로그인/프로필 엔드포인트 경로와 필드명은 흔한 규칙(email/username, password,
      /me, /users/me 등)으로 추측한다 — 대상 서비스가 이 규칙을 벗어나면 이 단계는
      조용히 실패(None 반환)하고, Phase 3의 즉시 diff 결과는 그대로 남는다.
    - login_config가 주어졌다면(로그인 URL/필드가 이미 알려진 것) 이를 최우선으로
      사용해 휴리스틱 실패 확률을 낮춘다.
    - 가입 성공 시 실제 계정이 생성된다 — 진단 대상 시스템에 테스트 계정이
      남는 부작용은 이 검증 단계의 성격상 불가피하다.
"""

import json
import logging
import re
from urllib.parse import parse_qs, urlparse

import requests

from .models import ClassifiedParam, RawFinding

logger = logging.getLogger(__name__)

TIMEOUT = 10  # 초

_SIGNUP_URL_HINTS = re.compile(r"sign[-_]?up|register|join|create[-_]?account|enroll", re.I)

_USERNAME_FIELD_HINTS = re.compile(r"email|username|userid|user_id|loginid|login_id|account", re.I)
_PASSWORD_FIELD_HINTS = re.compile(r"password|passwd|pwd", re.I)

_TOKEN_KEY_HINTS = re.compile(r"token|accesstoken|access_token|jwt", re.I)
_ROLE_KEY_HINTS  = re.compile(r"role|grade|level|authority", re.I)

_PROFILE_PATH_CANDIDATES = [
    "users/me", "user/me", "me", "profile", "mypage", "my-page",
    "auth/me", "account/me", "members/me",
]
_LOGIN_PATH_CANDIDATES = [
    "login", "signin", "sign-in", "auth/login", "auth/signin",
]


def verify_persisted_privilege(
    param:              ClassifiedParam,
    payload_value:      str,
    payload_desc:       str,
    test_request_body:  str,
    test_status:        int,
    custom_header:      str = None,
    login_config:       dict = None,
) -> RawFinding | None:
    """
    회원가입성 요청에 주입한 PRIVILEGE 값이 실제로 서버에 저장돼 로그인 후
    프로필에 반영되는지 확인한다. (comparator.py의 즉시 diff로는 못 잡는 저장형 케이스)

    조건에 맞지 않거나 로그인/프로필 조회 중 어느 단계라도 실패하면 조용히
    None을 반환한다 — 이 단계는 어디까지나 보강 검증이라, 실패해도 Phase 3의
    기존 즉시 diff 결과에는 영향을 주지 않는다.
    """
    c = param.collected

    if param.category != "PRIVILEGE":
        return None
    if test_status not in (200, 201):
        return None
    if not _SIGNUP_URL_HINTS.search(c.url):
        return None

    body_obj = _parse_body(test_request_body)
    if not body_obj:
        return None

    username, password = _extract_credentials(body_obj)
    if not username or not password:
        logger.debug("[검증] 자격증명(아이디/비밀번호) 추출 실패 — 후속 검증 건너뜀")
        return None

    token = _try_login(c.url, username, password, custom_header, login_config)
    if not token:
        logger.debug("[검증] 로그인 실패 — 후속 검증 건너뜀 (가입 미승인/필드 추측 실패 등)")
        return None

    role_value, profile_url, profile_body = _fetch_profile_role(c.url, token, custom_header)
    if role_value is None:
        logger.debug("[검증] 프로필 조회에서 role 계열 필드를 찾지 못함 — 후속 검증 건너뜀")
        return None

    if str(role_value).strip().lower() != str(payload_value).strip().lower():
        return None

    logger.info(
        f"[검증] 저장형 권한 상승 확인 — {c.url} | {c.param_name}={payload_value!r} "
        f"→ 로그인 후 {profile_url}에서 role={role_value!r} 확인됨"
    )

    return RawFinding(
        url=c.url,
        method=c.method,
        param_name=c.param_name,
        category=param.category,
        payload_used=payload_value,
        payload_description=payload_desc,
        baseline_status=test_status,
        test_status=200,
        anomaly_type="PERSISTED_PRIVILEGE_ESCALATION",
        anomaly_detail=(
            f"가입 시 주입한 '{c.param_name}={payload_value}'가 서버에 저장되어, "
            f"로그인 후 프로필 조회({profile_url})에서 실제로 role={role_value!r}로 확인됨"
        ),
        baseline_body=test_request_body,
        test_body=profile_body,
        baseline_request_body=test_request_body,
        test_request_body=test_request_body,
    )


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _parse_body(test_request_body: str) -> dict:
    """JSON 또는 form-urlencoded 요청 바디를 dict로 파싱한다. 실패 시 빈 dict."""
    if not test_request_body or test_request_body.startswith("(query string)"):
        return {}
    try:
        data = json.loads(test_request_body)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    try:
        qs = parse_qs(test_request_body, keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in qs.items()}
    except Exception:
        return {}


def _extract_credentials(body_obj: dict) -> tuple[str, str]:
    """가입 요청 바디에서 로그인에 재사용할 아이디/비밀번호로 보이는 필드를 찾는다."""
    username = password = ""
    for key, val in body_obj.items():
        if not isinstance(val, str):
            continue
        if not username and _USERNAME_FIELD_HINTS.search(key):
            username = val
        if not password and _PASSWORD_FIELD_HINTS.search(key):
            password = val
    return username, password


def _build_headers(custom_header: str = None) -> dict:
    headers = {}
    if custom_header:
        custom_header = custom_header.strip()
        if ":" in custom_header:
            h_name, h_val = custom_header.split(":", 1)
            headers[h_name.strip()] = h_val.strip()
        elif custom_header.startswith("Bearer "):
            headers["Authorization"] = custom_header
        elif custom_header.startswith("eyJ"):
            headers["Authorization"] = f"Bearer {custom_header}"
        else:
            headers["Authorization"] = custom_header
    return headers


def _try_login(
    signup_url:    str,
    username:      str,
    password:      str,
    custom_header: str = None,
    login_config:  dict = None,
) -> str:
    """로그인을 시도해 토큰 문자열을 반환한다. 모두 실패하면 빈 문자열."""
    headers = _build_headers(custom_header)
    headers["Content-Type"] = "application/json"

    # login_config가 있으면(실제 로그인 URL/필드가 이미 알려진 경우) 최우선 시도 —
    # 휴리스틱 후보보다 성공 확률이 훨씬 높다.
    candidates: list[tuple[str, str, str]] = []
    if login_config and login_config.get("login_url"):
        candidates.append((
            login_config["login_url"],
            login_config.get("username_field", "username"),
            login_config.get("password_field", "password"),
        ))
    for path in _LOGIN_PATH_CANDIDATES:
        url = _sibling_url(signup_url, path)
        candidates.append((url, "email", "password"))
        candidates.append((url, "username", "password"))

    for url, user_field, pw_field in candidates:
        try:
            resp = requests.post(
                url, json={user_field: username, pw_field: password},
                headers=headers, timeout=TIMEOUT,
            )
        except requests.RequestException:
            continue
        if resp.status_code not in (200, 201):
            continue
        token = _extract_token(resp)
        if token:
            return token

    return ""


def _extract_token(resp: requests.Response) -> str:
    """응답 헤더/바디에서 인증 토큰으로 보이는 값을 추출한다."""
    auth_header = resp.headers.get("Authorization") or resp.headers.get("authorization")
    if auth_header:
        return auth_header

    try:
        data = resp.json()
    except ValueError:
        return ""

    return _walk_for_key(data, _TOKEN_KEY_HINTS, (str,)) or ""


def _fetch_profile_role(
    signup_url:    str,
    token:         str,
    custom_header: str = None,
) -> tuple[object, str, str]:
    """흔한 '내 정보' 엔드포인트 후보를 순회하며 role 계열 필드를 찾는다."""
    headers = _build_headers(custom_header)
    headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"

    for path in _PROFILE_PATH_CANDIDATES:
        url = _sibling_url(signup_url, path)
        try:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            continue
        role_value = _walk_for_key(data, _ROLE_KEY_HINTS, (str, int, bool))
        if role_value is not None:
            return role_value, url, resp.text

    return None, "", ""


def _walk_for_key(obj: object, key_pattern: re.Pattern, value_types: tuple) -> object:
    """JSON 오브젝트를 재귀 탐색해 key_pattern에 매칭되는 첫 값을 반환한다."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, value_types) and key_pattern.search(k):
                return v
            found = _walk_for_key(v, key_pattern, value_types)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _walk_for_key(item, key_pattern, value_types)
            if found is not None:
                return found
    return None


def _sibling_url(base_url: str, new_last_segment: str) -> str:
    """
    base_url에서 마지막 path segment를 떼어낸 자리에 new_last_segment를 붙인
    '형제' URL을 만든다. 예: (".../api/v1/users/signup", "auth/login")
    → ".../api/v1/users/auth/login"
    """
    parsed = urlparse(base_url)
    parts  = parsed.path.rstrip("/").split("/")
    parent = "/".join(parts[:-1])
    new_path = f"{parent}/{new_last_segment.strip('/')}"
    return f"{parsed.scheme}://{parsed.netloc}{new_path}"
