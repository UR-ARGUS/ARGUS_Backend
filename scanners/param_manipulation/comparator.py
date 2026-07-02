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
    POTENTIAL_IDOR    test 200 + body 500byte 이상 증가 (타인 자원 노출 추정)
    DATA_EXPOSURE     test 응답에 baseline에 없던 JSON 키 출현
    ERROR_SUPPRESSED  baseline 에러 키워드 있음 → test 에러 없음 (조작값 수용)

여기서는 규칙 기반 탐지만 수행 — LLM을 호출하지 않으므로 이 단계는 결정적이고
실행시간이 유계(bounded)이다. severity/취약 여부 최종 확정은 Phase 4에서 LLM이 담당.
"""

import json
import logging

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

    # ── 패턴 2: IDOR — 응답 크기 급증 ───────────────────────────
    elif (
        test["status"] == 200
        and len(test["body"]) - len(baseline["body"]) > _IDOR_BODY_DELTA_THRESHOLD
    ):
        delta          = len(test["body"]) - len(baseline["body"])
        anomaly_type   = "POTENTIAL_IDOR"
        anomaly_detail = f"응답 크기 {delta:+d}byte 증가 — 타인 자원 노출 가능성"

    # ── 패턴 3: 새로운 JSON 키 출현 ─────────────────────────────
    else:
        new_keys = _detect_new_json_keys(baseline["body"], test["body"])
        if new_keys and test["status"] == 200:
            anomaly_type   = "DATA_EXPOSURE"
            anomaly_detail = f"조작 후 신규 응답 필드 출현: {new_keys}"

    # ── 패턴 4: 에러 사라짐 ─────────────────────────────────────
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


def _has_error(body: str) -> bool:
    """응답 바디에 에러 관련 키워드가 포함되어 있는지 확인한다."""
    body_lower = body.lower()
    return any(kw in body_lower for kw in ERROR_KEYWORDS)
