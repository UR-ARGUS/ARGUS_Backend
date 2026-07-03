"""
comparator.py — Phase 3: 응답 이상 1차 탐지 (규칙 기반, LLM 미사용)

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 6

역할:
    - baseline(원본 응답)과 test(조작 응답)를 비교
    - 4가지 이상 패턴 탐지 후 RawFinding 생성 (최종 취약 여부 확정은 Phase 4 classifier.py)
    - 이상 없으면 None 반환 → engine.py에서 필터링

이상 탐지 패턴:
    PRIVILEGE_BYPASS  baseline 401/403 → test 200 (권한 검증 우회)
    VALUE_ACCEPTED    PRICE/PRIVILEGE/STATUS/HIDDEN 카테고리에서 기존 응답 필드의 값이
                      baseline과 다르며 그 값이 주입한 조작값과 일치 (서버가 클라이언트
                      제공 값을 검증 없이 그대로 계산/저장/반환에 반영했다는 직접 증거.
                      예: 회원가입 시 role=ADMIN 주입 → 응답의 role 필드가 실제 ADMIN으로 반영
                      예: 주문 생성 시 status=PAID 주입 → 응답의 status 필드가 실제 PAID로 반영)
    POTENTIAL_IDOR    test 200 + body 500byte 이상 증가 (타인 자원 노출 추정)
    DATA_EXPOSURE     test 응답에 baseline에 없던 JSON 키 출현
    ERROR_SUPPRESSED  baseline 에러 키워드 있음 → test 에러 없음 (조작값 수용)

주의 (VALUE_ACCEPTED를 IDOR에는 적용하지 않는 이유):
    IDOR 카테고리는 ID 값을 바꾸면 응답이 다른 레코드로 바뀌는 게 정상 동작이라
    (다른 상품/게시글 조회), 값 일치 여부만으로 판단하면 정상 케이스가 전부
    오탐으로 잡힌다. PRICE/PRIVILEGE/STATUS/HIDDEN은 반대로 서버가 재계산하거나
    무시해야 할 필드라 조작값이 그대로 반영되는 순간 그 자체가 이상 신호다.

여기서는 규칙 기반 탐지만 수행 — LLM을 호출하지 않으므로 이 단계는 결정적이고
실행시간이 유계(bounded)이다. severity/취약 여부 최종 확정은 Phase 4에서 LLM이 담당.
"""

import json
import logging
import re

from .models import ClassifiedParam, RawFinding

logger = logging.getLogger(__name__)

ERROR_KEYWORDS = [
    "error", "invalid", "denied", "forbidden",
    "unauthorized", "exception", "fail",
]

# POTENTIAL_IDOR 탐지 기준 응답 크기 증가량 (byte)
_IDOR_BODY_DELTA_THRESHOLD = 500


def detect_anomaly(
    param:           ClassifiedParam,
    payload_value:   str,
    payload_desc:    str,
    baseline:        dict,
    test:            dict,
) -> RawFinding | None:
    """
    baseline과 test 응답을 비교해 이상 패턴을 탐지한다.

    Args:
        param:         분류된 파라미터
        payload_value: 주입한 페이로드 값
        payload_desc:  페이로드 설명
        baseline:      원본 응답 {"status": int, "body": str, "headers": dict}
        test:          조작 응답 {"status": int, "body": str, "headers": dict}

    Returns:
        RawFinding if anomaly detected, else None (Phase 4에서 LLM이 최종 확정)
    """
    c             = param.collected
    anomaly_type  = None
    anomaly_detail = None

    # 요청 자체가 실패한 경우 건너뜀
    if test["status"] == -1:
        return None

    # ── 패턴 1: 권한 우회 ────────────────────────────────────────
    if baseline["status"] in (401, 403) and test["status"] == 200:
        anomaly_type   = "PRIVILEGE_BYPASS"
        anomaly_detail = (
            f"원본 응답 {baseline['status']} → "
            f"조작 후 200 OK (권한 검증 우회 가능성)"
        )

    # ── 패턴 2: 조작값이 그대로 응답에 반영됨 ───────────────────
    # PRICE/PRIVILEGE/STATUS/HIDDEN 필드는 서버가 재계산·검증해야 할 값이라, 기존에
    # 존재하던 응답 필드의 값이 baseline과 달라지면서 그 값이 주입한 조작값과
    # 일치하면 그 자체가 "서버가 클라이언트 입력을 검증 없이 수용했다"는 증거다.
    # (기존 DATA_EXPOSURE 패턴은 "새 키 출현"만 봐서, role처럼 baseline 응답에도
    #  이미 존재하던 키의 값만 바뀌는 경우는 전혀 잡지 못했다.)
    elif (
        param.category in ("PRICE", "PRIVILEGE", "STATUS", "HIDDEN")
        and test["status"] == 200
    ):
        changed = _detect_value_changed_to_payload(
            baseline["body"], test["body"], payload_value
        )
        if changed:
            anomaly_type   = "VALUE_ACCEPTED"
            anomaly_detail = f"조작값이 그대로 응답에 반영됨: {changed}"

    # ── 패턴 3: IDOR — 응답 크기 급증 ───────────────────────────
    # category가 IDOR(ID류 파라미터)일 때만 적용한다. PRICE/PRIVILEGE/STATUS 같은
    # 필터성 파라미터는 유효한 값을 넣을수록 매칭되는 레코드가 늘어나 응답이 커지는
    # 게 정상 동작이라, 카테고리 구분 없이 이 규칙을 적용하면 그런 정상 필터링을
    # 전부 "타인 자원 노출"로 오탐한다.
    if anomaly_type is None and (
        param.category == "IDOR"
        and test["status"] == 200
        and len(test["body"]) - len(baseline["body"]) > _IDOR_BODY_DELTA_THRESHOLD
    ):
        delta          = len(test["body"]) - len(baseline["body"])
        anomaly_type   = "POTENTIAL_IDOR"
        anomaly_detail = f"응답 크기 {delta:+d}byte 증가 — 타인 자원 노출 가능성"

    # ── 패턴 4: 새로운 JSON 키 출현 ─────────────────────────────
    if anomaly_type is None:
        new_keys = _detect_new_json_keys(baseline["body"], test["body"])
        if new_keys and test["status"] == 200:
            anomaly_type   = "DATA_EXPOSURE"
            anomaly_detail = f"조작 후 신규 응답 필드 출현: {new_keys}"

    # ── 패턴 5: 에러 사라짐 ─────────────────────────────────────
    if anomaly_type is None:
        if (
            _has_error(baseline["body"])
            and not _has_error(test["body"])
            and test["status"] == 200
        ):
            anomaly_type   = "ERROR_SUPPRESSED"
            anomaly_detail = "에러 응답이 조작 후 사라짐 — 서버가 조작값을 수용한 것으로 추정"

    if anomaly_type is None:
        return None

    raw_finding = RawFinding(
        url=c.url,
        method=c.method,
        param_name=c.param_name,
        category=param.category,
        payload_used=payload_value,
        payload_description=payload_desc,
        baseline_status=baseline["status"],
        test_status=test["status"],
        anomaly_type=anomaly_type,
        anomaly_detail=anomaly_detail,
        baseline_body=baseline["body"],
        test_body=test["body"],
        baseline_request_body=baseline.get("request_body", ""),
        test_request_body=test.get("request_body", ""),
    )

    logger.debug(
        f"[1차 탐지] {anomaly_type} | {c.url} | "
        f"{c.param_name}={payload_value!r}"
    )
    return raw_finding


# ──────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────

def _detect_new_json_keys(baseline_body: str, test_body: str) -> list[str]:
    """test 응답에만 있고 baseline에는 없는 JSON 키 목록을 반환한다."""
    try:
        base_keys = set(_extract_all_keys(json.loads(baseline_body)))
        test_keys = set(_extract_all_keys(json.loads(test_body)))
        return sorted(test_keys - base_keys)
    except (json.JSONDecodeError, TypeError):
        return []


def _extract_all_keys(obj: object, prefix: str = "") -> list[str]:
    """JSON 오브젝트의 모든 키를 dot-notation으로 재귀 추출한다."""
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            keys.append(full)
            keys.extend(_extract_all_keys(v, full))
    elif isinstance(obj, list):
        for item in obj:
            keys.extend(_extract_all_keys(item, prefix))
    return keys


_ERROR_FIELD_NAMES = {
    "error", "errors", "message", "msg", "detail", "details",
    "errormessage", "error_message", "reason", "description",
}


def _has_error(body: str) -> bool:
    """
    응답 바디에 에러 관련 신호가 있는지 확인한다.

    JSON 응답이면 error/message류 필드의 값만 검사한다 — 전체 바디를 통째로 검색하면
    게시글 본문 같은 자유 텍스트 콘텐츠에 우연히 키워드가 섞여 들어간 것만으로 오탐이
    난다 (실측: 저장된 XSS 페이로드 `<img src=x onerror=...>` 안의 "onerror"가 "error"에
    매칭되어, 실제로는 정상적인 대량 목록 응답이 "에러 응답"으로 잘못 분류됨).
    JSON이 아니면(HTML 에러 페이지 등) 단어 경계 기준으로 키워드를 찾는다.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        body_lower = body.lower()
        return any(re.search(rf"\b{kw}\b", body_lower) for kw in ERROR_KEYWORDS)

    for key, value in _extract_leaf_values(data).items():
        if not isinstance(value, str):
            continue
        field_name = key.rsplit(".", 1)[-1].lower()
        if field_name in _ERROR_FIELD_NAMES:
            value_lower = value.lower()
            if any(kw in value_lower for kw in ERROR_KEYWORDS):
                return True
    return False


def _detect_value_changed_to_payload(
    baseline_body: str,
    test_body:     str,
    payload_value: str,
) -> list[str]:
    """
    baseline과 test에 공통으로 존재하는 키 중, test 쪽 값이 baseline과 다르면서
    그 값이 주입한 payload_value와 일치(대소문자 무시)하는 항목을 찾는다.

    새 키 출현이 아니라 "기존 키의 값이 조작값으로 바뀜"을 잡기 위한 것 —
    role처럼 baseline 응답에도 이미 존재하는 필드가 대상인 경우를 커버한다.
    """
    payload_norm = str(payload_value).strip().lower()
    if not payload_norm:
        return []

    try:
        base_values = _extract_leaf_values(json.loads(baseline_body))
        test_values = _extract_leaf_values(json.loads(test_body))
    except (json.JSONDecodeError, TypeError):
        return []

    changed: list[str] = []
    for key, test_val in test_values.items():
        if key not in base_values:
            continue
        base_val = base_values[key]
        if base_val == test_val:
            continue
        if str(test_val).strip().lower() == payload_norm:
            changed.append(f"{key}: {base_val!r} -> {test_val!r}")
    return changed


def _extract_leaf_values(obj: object, prefix: str = "") -> dict:
    """JSON 오브젝트의 리프(leaf) 값만 dot-notation 키로 평탄화한다."""
    values: dict = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            values.update(_extract_leaf_values(v, full))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            values.update(_extract_leaf_values(item, f"{prefix}[{i}]"))
    else:
        values[prefix] = obj
    return values
