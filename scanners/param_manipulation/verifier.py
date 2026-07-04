"""
verifier.py — Phase 3.5: 저장형(persisted) 권한 상승/가격 조작 후속 검증

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3

배경:
    comparator.py의 즉시 응답 diff(VALUE_ACCEPTED 등)는 조작한 요청의 "그 응답"에
    변조값이 그대로 반영될 때만 잡을 수 있다. 하지만 회원가입처럼 응답에 role이
    아예 노출되지 않는 API(예: {"success":true}만 반환)는 baseline/test 응답이
    완전히 동일하게 성공해서 즉시 diff로는 절대 못 잡는다 — 조작의 효과가 서버에
    "저장"만 되고, 그걸 확인하려면 별도 요청(로그인 후 프로필 조회)이 필요하다.
    (수동 진단에서 role 변조 가입이 실제로 통과한 걸 확인했는데 자동 스캔 결과에는
    하나도 안 잡힌 문제 — 원인은 정확히 이 지점이었음)

    동일한 사각지대가 PRICE 카테고리에도 그대로 있다: 예약/주문 생성 API가
    {"success":true,"reservationId":45}처럼 가격을 돌려주지 않는 형태라면, totalPrice를
    1원으로 조작해 서버가 실제로 그 값을 저장했더라도 즉시 diff로는 절대 못 잡는다.
    PRIVILEGE에서 이미 발견하고 고친 것과 동일한 유형의 문제라 같은 방식(생성 직후
    응답에서 리소스 ID를 뽑아 재조회)으로 확장한다.

역할:
    - verify_persisted_privilege: PRIVILEGE 카테고리 파라미터가 회원가입/계정생성으로
      보이는 요청에 쓰였고 조작된 값으로 요청이 성공(2xx)했을 때만 동작. 그 요청에
      실려 간 자격증명(아이디/비밀번호로 보이는 필드)을 추출해 로그인 시도 후, 흔한
      "내 정보" 엔드포인트 후보들을 순회 조회해 role 계열 필드가 주입한 조작값과
      일치하는지 확인한다. 일치하면 RawFinding(PERSISTED_PRIVILEGE_ESCALATION, HIGH).
    - verify_persisted_price: PRICE 카테고리 파라미터가 리소스 생성(POST) 요청에
      쓰였고 요청이 성공(2xx)했는데 그 즉시 응답에는 가격 계열 필드가 아예 없을 때만
      동작. 응답에서 리소스 ID로 보이는 필드를 찾아 "생성 URL/{id}" 형태로 재조회해,
      그 결과에 포함된 가격 계열 필드가 주입한 조작값과 일치하는지 확인한다.
      일치하면 RawFinding(PERSISTED_VALUE_ACCEPTED, HIGH).

한계 (휴리스틱 기반):
    - 로그인/프로필/재조회 엔드포인트 경로와 필드명은 흔한 규칙(email/username,
      password, /me, /users/me, "생성 URL 뒤에 /{id}" 등)으로 추측한다 — 대상
      서비스가 이 규칙을 벗어나면 이 단계는 조용히 실패(None 반환)하고, Phase 3의
      즉시 diff 결과는 그대로 남는다.
    - login_config가 주어졌다면(로그인 URL/필드가 이미 알려진 것) 이를 최우선으로
      사용해 휴리스틱 실패 확률을 낮춘다.
    - 가입 성공 시 실제 계정이, 예약/주문 생성 성공 시 실제 리소스가 생성된다 —
      진단 대상 시스템에 테스트 데이터가 남는 부작용은 이 검증 단계의 성격상
      불가피하다.
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

# classifier.py의 PRICE 규칙과 동일한 어휘 — 재조회한 리소스에서 가격 계열
# 필드를 찾아내는 데 쓴다 (완전히 같은 정규식일 필요는 없고, 값 검증용이라 느슨해도 됨).
_PRICE_KEY_HINTS = re.compile(r"price|amount|cost|fee|total|charge|balance", re.I)
# 생성 응답에서 방금 만들어진 리소스의 식별자로 보이는 필드를 찾는 데 쓴다.
_CREATED_ID_KEY_HINTS = re.compile(r"(^|_)id$|[a-z0-9](Id|ID)$")


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


def verify_persisted_price(
    param:              ClassifiedParam,
    payload_value:      str,
    payload_desc:       str,
    test_request_body:  str,
    test_status:        int,
    test_body:          str,
    custom_header:      str = None,
) -> RawFinding | None:
    """
    예약/주문 생성처럼 응답에 가격 필드가 아예 노출되지 않는 API에서, 주입한 PRICE
    조작값이 실제로 서버에 저장되는지 확인한다. (comparator.py의 즉시 diff로는 못
    잡는 저장형 케이스 — verify_persisted_privilege와 동일한 유형의 사각지대를 PRICE로
    확장한 것)

    조건에 맞지 않거나 재조회 중 어느 단계라도 실패하면 조용히 None을 반환한다 —
    이 단계는 어디까지나 보강 검증이라, 실패해도 Phase 3의 기존 즉시 diff 결과에는
    영향을 주지 않는다.
    """
    c = param.collected

    if param.category != "PRICE":
        return None
    if c.method.upper() != "POST":
        return None
    if test_status not in (200, 201):
        return None

    body_obj = _parse_body(test_body)
    if not isinstance(body_obj, dict) or not body_obj:
        return None

    # 생성 응답에 이미 가격 계열 필드가 있다면 comparator.py의 VALUE_ACCEPTED가
    # 이미 판단할 수 있는 범위다 — 여기 도달했다는 건 그 필드 값이 조작값과
    # 달랐다는(서버가 정상적으로 재계산했다는) 뜻이므로 중복 검증 없이 건너뛴다.
    if _walk_for_key(body_obj, _PRICE_KEY_HINTS, (str, int, float)) is not None:
        return None

    created_id = _walk_for_key(body_obj, _CREATED_ID_KEY_HINTS, (str, int))
    if created_id is None:
        logger.debug("[검증] 생성 응답에서 리소스 ID를 찾지 못함 — 가격 후속 검증 건너뜀")
        return None

    # 생성(POST) URL과 단건 조회 URL의 경로가 다른 서비스가 흔하다 (실측: POST
    # .../api/v1/reservations/flights로 생성하지만, 실제 단건 리소스는
    # .../api/v1/members/me/reservations/flights/{id}에 있어 "생성 URL 그대로에
    # /id만 붙이는" 단일 추측은 404가 나서 검증 자체가 조용히 무산됐음).
    # verify_persisted_privilege가 프로필 경로 후보를 여러 개 순회하는 것과 동일한
    # 방식으로, 흔한 REST 관례 후보를 순서대로 시도한다.
    headers = _build_headers(custom_header)
    fetched, refetch_url = None, ""
    for candidate_url in _candidate_refetch_urls(c.url, created_id):
        try:
            resp = requests.get(candidate_url, headers=headers, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            candidate_fetched = json.loads(resp.text)
        except json.JSONDecodeError:
            continue
        fetched, refetch_url = candidate_fetched, candidate_url
        break

    if fetched is None:
        logger.debug(f"[검증] 생성된 리소스 재조회 실패 — 후보 경로 전부 무응답/404: {c.url}")
        return None

    price_value = _walk_for_key(fetched, _PRICE_KEY_HINTS, (str, int, float))
    if price_value is None:
        logger.debug("[검증] 재조회 응답에서 가격 계열 필드를 찾지 못함 — 후속 검증 건너뜀")
        return None

    if str(price_value).strip().lower() != str(payload_value).strip().lower():
        return None

    logger.info(
        f"[검증] 저장형 가격 조작 확인 — {c.url} | {c.param_name}={payload_value!r} "
        f"→ 재조회({refetch_url})에서 가격={price_value!r}로 저장된 것이 확인됨"
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
        anomaly_type="PERSISTED_VALUE_ACCEPTED",
        anomaly_detail=(
            f"생성 시 주입한 '{c.param_name}={payload_value}'가 응답에는 안 보였지만, "
            f"재조회({refetch_url})에서 실제로 가격={price_value!r}로 저장된 것이 확인됨"
        ),
        baseline_body=test_body,
        test_body=resp.text,
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


def _candidate_refetch_urls(creation_url: str, created_id: object) -> list[str]:
    """
    생성(POST) URL로부터 방금 만들어진 리소스의 단건 조회 URL 후보들을 만든다.

    생성 경로와 단건 조회 경로가 다른 서비스가 흔하다 (실측: POST
    .../api/v1/reservations/flights로 예약을 생성하지만, 실제 단건 리소스는
    .../api/v1/members/me/reservations/flights/{id}에 있음 — "생성 URL 그대로에
    /id만 붙이는" 단일 추측만으로는 404가 나서 재조회 검증 자체가 조용히
    무산됐었다). verify_persisted_privilege가 프로필 경로 후보를 여러 개
    순회하는 것과 동일한 방식으로, 흔한 REST 관례 후보를 순서대로 만든다.
    """
    parsed = urlparse(creation_url)
    parts  = parsed.path.split("/")  # 맨 앞 빈 문자열 포함 (선행 "/" 보존용)

    def build(path_parts: list[str]) -> str:
        return f"{parsed.scheme}://{parsed.netloc}{'/'.join(path_parts)}"

    candidates: list[str] = []

    # 1. 생성 URL 그대로에 /{id} 추가 (가장 흔한 REST 관례)
    candidates.append(f"{creation_url.rstrip('/')}/{created_id}")

    # 2. 마지막 segment(하위 리소스명)를 떼고 그 상위 컬렉션이 단건 조회를
    #    담당하는 경우 — POST .../reservations/flights → GET .../reservations/{id}
    if len(parts) >= 2:
        candidates.append(build(parts[:-1] + [str(created_id)]))

    # 3. 생성 경로엔 없다가 조회 경로에만 "내 정보" 스코프가 붙는 경우 —
    #    끝에서 두 세그먼트 앞에 스코프를 끼워 넣는다 (예: .../reservations/flights
    #    → .../members/me/reservations/flights/{id})
    if len(parts) >= 3:
        for scope in ("members/me", "users/me", "user/me"):
            candidates.append(build(parts[:-2] + [scope] + parts[-2:] + [str(created_id)]))

    seen: set[str] = set()
    ordered: list[str] = []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered
