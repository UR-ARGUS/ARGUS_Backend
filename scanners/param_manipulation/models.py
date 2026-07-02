"""
models.py — 1-3 파이프라인 전 단계가 공유하는 데이터 모델

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 2
"""

from dataclasses import dataclass


@dataclass
class CollectedParam:
    """ZAP Ajax Spider가 수집한 파라미터 단위."""

    url: str
    method: str           # GET | POST | PUT | PATCH | DELETE
    param_name: str
    param_value: str
    param_type: str       # "query" | "body" | "hidden"
    content_type: str     # application/json, application/x-www-form-urlencoded 등
    raw_body: str = ""    # 이 파라미터가 속한 요청의 전체 baseline body (JSON/form).
                           # manipulator.py가 변조 시 다른 필드를 지우지 않고 이 값만 교체하는 데 사용.
                           # 알 수 없으면 빈 문자열 — 이 경우 해당 필드 하나만 담은 body로 폴백.
    binary_fields: str = ""  # content_type이 multipart/form-data일 때, raw_body 필드 중
                              # 실제 파일(바이너리)로 보내야 하는 필드명 목록 (콤마 구분).


@dataclass
class ClassifiedParam:
    """규칙 기반(정규식)으로 위험 카테고리를 태깅한 파라미터 — Phase 2, LLM 미사용."""

    collected: CollectedParam
    category: str         # PRICE | PRIVILEGE | IDOR | HIDDEN | SAFE
    reason: str           # 분류 근거 (규칙 매칭 내역)


@dataclass
class RawFinding:
    """
    comparator.py(Phase 3)가 규칙 기반으로 1차 탐지한 이상 징후.
    classifier.py(Phase 4)가 LLM으로 최종 취약 여부를 확정하기 전 중간 산출물.

    anomaly_type / anomaly_detail 정의는 Finding과 동일.
    """

    url: str
    method: str
    param_name: str
    category: str          # Phase 2 규칙 기반 초기 카테고리 — LLM 실패 시 폴백에 재사용
    payload_used: str
    payload_description: str
    baseline_status: int
    test_status: int
    anomaly_type: str
    anomaly_detail: str
    baseline_body: str
    test_body: str


@dataclass
class Finding:
    """
    최종 확정된 취약점 단위 — 다음 단계(Selenium 증적 캡처)로 전달.

    anomaly_type:
        PRIVILEGE_BYPASS  baseline 401/403 → test 200 (권한 검증 우회)
        POTENTIAL_IDOR    test 200 + body 500byte↑ 증가 (타인 자원 노출 추정)
        DATA_EXPOSURE     test 응답에 baseline에 없던 JSON 키 출현
        ERROR_SUPPRESSED  baseline 에러 키워드 → test 에러 없음 (조작값 수용)

    severity: HIGH | MEDIUM
    llm_description / llm_recommendation: Phase 4에서 LLM이 채움 (폴백 시 규칙 기반 문구)
    """

    url: str
    method: str
    param_name: str
    category: str
    payload_used: str
    payload_description: str
    baseline_status: int
    test_status: int
    anomaly_type: str
    anomaly_detail: str
    baseline_body: str    # Selenium 재현용 원본 응답 보존
    test_body: str        # Selenium 재현용 조작 응답 보존
    severity: str         # HIGH | MEDIUM
    llm_description: str = ""
    llm_recommendation: str = ""
