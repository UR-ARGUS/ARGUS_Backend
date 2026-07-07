"""
engine.py — 1-5(검증되지 않은 리다이렉트와 포워드, Reflected 전용) 스캔 오케스트레이터

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-5

파이프라인:
    Phase 1: scanners.param_manipulation.collector.collect_params — 파라미터 수집
             (ZAP Ajax Spider + Swagger Spec, 1-3과 동일 자산 재사용)
    Phase 2: candidates.select_candidates    — 이름 기반 규칙으로 리다이렉트 후보만 선별
    Phase 3: detector.probe_candidate        — 외부 목적지 페이로드 주입 + Reflected 판별
             (결정적 규칙 기반 — LLM 해석 단계 없음)

외부 연동 인터페이스:
    from scanners.redirect_forward.engine import run_redirect_scan

    findings = run_redirect_scan("https://target.example.com")
    for f in findings:
        ...  # Selenium 증적 캡처 등 후속 단계로 전달
"""

import logging

from scanners.param_manipulation.collector import collect_params
from .candidates import select_candidates
from .detector    import probe_candidate
from .payloads    import DEFAULT_PAYLOAD_HOST
from .models      import RedirectFinding

logger = logging.getLogger(__name__)


def run_redirect_scan(
    target_url:        str,
    max_wait_seconds:   int = 120,
    login_config:       dict = None,
    custom_header:      str = None,
    api_base_url:       str = None,
    payload_host:       str = DEFAULT_PAYLOAD_HOST,
    progress_callback=None,
    coverage_callback=None,
) -> list[RedirectFinding]:
    """
    1-5(Reflected) 스캔 엔진 진입점.

    Args:
        target_url:        진단 대상 URL (프론트엔드 SPA 등 ZAP Ajax Spider 크롤링 대상)
        max_wait_seconds:  Ajax Spider 완료 대기 최대 시간 (초, 기본 120)
        login_config:      자동 로그인 설정 정보
        custom_header:     사용자 정의 헤더/쿠키 문자열
        api_base_url:      백엔드 API 서버 URL (Swagger Spec 병행 수집, 1-3과 동일 동작)
        payload_host:      리다이렉트 목적지로 주입할 미검증 외부 호스트. 기본값을 그대로
                            써도 되지만, 사내망 등에서 이 문자열이 실제 도메인과 우연히
                            겹칠 가능성이 있다면 호출 시 다른 값으로 지정한다.
        progress_callback: Callable[[str, int], None] — (phase, percent 0~100) 보고.
                            phase는 "collect" / "classify" / "probe" 중 하나.
        coverage_callback: Callable[[list[dict]], None] — Phase 2에서 후보로 선정돼
                            Phase 3(실 요청)로 넘어간 전체 파라미터 목록을 한 번 보고한다.
                            각 원소는 {"url", "method", "param_name", "reason"}.

    Returns:
        List[RedirectFinding] — 결정적 규칙 기반 판정이므로 1-3과 달리 "미확정" 상태는 없지만,
        confirmed_redirect 값으로 두 종류가 섞여 있다:
          - confirmed_redirect=True  : Location 헤더/meta refresh/JS location 대입에서
                                        실제 리다이렉트 실행 증거가 확인된 1-5 확정 findings
          - confirmed_redirect=False : REFLECTED_VALUE — 주입 값이 응답에 반사된 것만
                                        확인되고 리다이렉트 실행 증거는 없는 참고용 findings
                                        (1-5 확정 취약점 아님)
    """
    def report(phase: str, percent: int) -> None:
        if not progress_callback:
            return
        try:
            progress_callback(phase, percent)
        except Exception as e:
            logger.warning(f"progress_callback 호출 실패 (무시하고 진행): {e}")

    def report_coverage(candidates: list) -> None:
        if not coverage_callback:
            return
        try:
            coverage_callback([
                {
                    "url":        c.collected.url,
                    "method":     c.collected.method,
                    "param_name": c.collected.param_name,
                    "reason":     c.reason,
                }
                for c in candidates
            ])
        except Exception as e:
            logger.warning(f"coverage_callback 호출 실패 (무시하고 진행): {e}")

    # ── Phase 1: 파라미터 수집 (1-3과 동일 자산 재사용) ──────────
    logger.info(f"[1-5][Phase 1] 파라미터 수집 시작: {target_url}")
    collected = collect_params(
        target_url,
        max_wait_seconds=max_wait_seconds,
        login_config=login_config,
        custom_header=custom_header,
        progress_callback=lambda pct: report("collect", pct),
        api_base_url=api_base_url,
    )
    logger.info(f"[1-5][Phase 1] 수집된 파라미터 수: {len(collected)}")

    if not collected:
        logger.warning("[1-5][Phase 1] 수집된 파라미터 없음 — 종료")
        return []

    # ── Phase 2: 리다이렉트/포워드 후보 선별 (규칙 기반) ─────────
    logger.info("[1-5][Phase 2] 후보 파라미터 선별 시작")
    report("classify", 0)
    candidates = select_candidates(collected)
    report("classify", 100)
    report_coverage(candidates)

    if not candidates:
        logger.info("[1-5][Phase 2] 리다이렉트/포워드 후보 없음 — 종료")
        return []

    # ── Phase 3: 페이로드 주입 + Reflected 판별 ─────────────────
    logger.info("[1-5][Phase 3] 페이로드 주입 및 Reflected 판별 시작")
    findings: list[RedirectFinding] = []
    report("probe", 0)
    for i, candidate in enumerate(candidates):
        findings.extend(probe_candidate(candidate, payload_host=payload_host, custom_header=custom_header))
        report("probe", int((i + 1) / len(candidates) * 100))

    confirmed = [f for f in findings if f.confirmed_redirect]
    reflected_only = [f for f in findings if not f.confirmed_redirect]
    high_count   = sum(1 for f in confirmed if f.severity == "HIGH")
    medium_count = sum(1 for f in confirmed if f.severity == "MEDIUM")
    logger.info(
        f"[1-5][완료] 후보 {len(candidates)}건 검사 — "
        f"확정 리다이렉트/포워드 findings: {len(confirmed)}건 (HIGH: {high_count}, MEDIUM: {medium_count}) / "
        f"반사만 확인된 참고 findings: {len(reflected_only)}건 (리다이렉트 실행 증거 없음, 1-5 확정 아님)"
    )

    return findings
