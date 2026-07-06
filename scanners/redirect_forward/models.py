"""
models.py — 1-5 리다이렉트/포워드(Reflected 전용) 스캐너가 공유하는 데이터 모델

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-5
"검증되지 않은 리다이렉트와 포워드" — 예: http://ooo.com/redirect.jsp?returl=evil.com

CollectedParam은 1-3 스캔 엔진(scanners.param_manipulation)이 이미 ZAP Ajax Spider +
Swagger Spec 파싱으로 구현해 둔 파라미터 수집 자산을 그대로 재사용한다 — 리다이렉트
전용 파라미터만 다시 크롤링할 이유가 없고, 수집 로직(인증/헤더/멀티파트 처리 등)을
중복 구현하면 유지보수 지점만 늘어난다.
"""

from dataclasses import dataclass

from scanners.param_manipulation.models import CollectedParam


@dataclass
class RedirectCandidate:
    """이름 기반 규칙으로 리다이렉트/포워드 후보로 태깅된 파라미터 — Phase 2 산출물."""

    collected: CollectedParam
    reason: str  # 후보로 선정된 근거 (매칭된 규칙 설명)


@dataclass
class RedirectFinding:
    """
    Reflected 리다이렉트/포워드 확정 결과 — Phase 3 산출물.

    detection_type:
        LOCATION_HEADER  3xx 응답의 Location 헤더에 주입한 외부 목적지가 그대로 노출
                         (서버 사이드 리다이렉트 — 가장 확실한 증거)
        META_REFRESH     200 응답 본문의 <meta http-equiv="refresh" ... url=...>에
                         주입한 외부 목적지가 그대로 노출 (클라이언트 사이드)
        JS_REDIRECT      200 응답 본문의 location.href / location.replace(/.assign() 등
                         JS 대입문에 주입한 외부 목적지가 그대로 노출 (클라이언트 사이드)

    severity: HIGH(서버 사이드 확정) | MEDIUM(클라이언트 사이드 — 실제 렌더링/실행 여부는
              Selenium 등 브라우저 재현으로 추가 확인 권장)
    """

    url: str
    method: str
    param_name: str
    payload_used: str
    payload_description: str
    detection_type: str
    evidence: str          # Location 헤더 값 또는 매칭된 본문 스니펫
    baseline_status: int
    test_status: int
    severity: str
    description: str
    recommendation: str
    request_body: str = ""  # 실제 전송한 테스트 요청 바디/쿼리 (증적)
