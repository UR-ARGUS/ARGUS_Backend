"""
engine.py — 전체 파이프라인 오케스트레이터

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 7

역할:
    - Phase 1~4를 순서대로 실행
    - 각 단계 결과를 다음 단계로 전달
    - 최종 findings[] 리스트를 반환 → Selenium 증적 캡처 모듈로 전달

파이프라인 (v2 — LLM을 Phase 4로 이동, 탐지는 규칙 기반으로 유계 실행시간 보장):
    Phase 1:   collector.py  — 파라미터 수집
    Phase 2:   classifier.py — 규칙 기반 사전 분류 (LLM 미사용, SAFE 필터링으로 요청량 절감)
    Phase 3:   manipulator.py + comparator.py — 페이로드 주입 + 규칙 기반 1차 이상 탐지 (RawFinding)
    Phase 3.5: verifier.py — Phase 3의 즉시 응답 diff로 못 잡는 "저장형" 권한 상승 후속 검증
               (회원가입 등 응답에 role이 노출되지 않는 API 대상 — 로그인 후 프로필 재조회)
    Phase 4:   classifier.py — LLM이 RawFinding을 해석해 최종 Finding으로 확정 (timeout 적용)

외부 연동 인터페이스 (명세 §8):
    from scanners.param_manipulation.engine import run_scan

    findings = run_scan("https://target.example.com")
    for f in findings:
        selenium_capture(
            url=f.url,
            method=f.method,
            param_name=f.param_name,
            payload=f.payload_used,
            anomaly_type=f.anomaly_type,
            evidence_body=f.test_body,
        )
"""

import logging

from .collector   import collect_params
from .classifier  import classify_params, interpret_findings
from .manipulator import run_manipulation
from .comparator  import detect_anomaly
from .verifier    import verify_persisted_privilege, verify_persisted_price
from .models      import Finding, RawFinding

logger = logging.getLogger(__name__)


def run_scan(
    target_url: str,
    max_wait_seconds: int = 120,
    login_config: dict = None,
    custom_header: str = None,
    progress_callback=None,
    api_base_url: str = None,
    coverage_callback=None,
    attempt_callback=None,
) -> list[Finding]:
    """
    1-3 스캔 엔진 진입점.

    target_url과 옵션 정보(login_config, custom_header)를 받아 Phase 1~4를 순서대로 실행하고
    이상 탐지 결과인 findings[] 리스트를 반환한다.

    Args:
        target_url:        진단 대상 URL (프론트엔드 SPA 등 ZAP Ajax Spider 크롤링 대상)
        max_wait_seconds:  Ajax Spider 완료 대기 최대 시간 (초, 기본 120)
        login_config:      자동 로그인 설정 정보
        custom_header:     사용자 정의 헤더/쿠키 문자열
        progress_callback: Callable[[str, int], None] — (phase, percent 0~100)을 단계마다 보고.
                            phase는 "collect" / "classify" / "manipulate" / "llm_review" 중 하나.
        api_base_url:      백엔드 API 서버 URL. 주어지면 Swagger Spec으로 비즈니스 파라미터를
                            먼저 확보하고, target_url은 ZAP Ajax Spider로 별도 크롤링해 Swagger에
                            없는 파라미터만 보완한다 (collector.collect_params 참고).
        coverage_callback: Callable[[list[dict]], None] — Phase 2에서 SAFE가 아니라고
                            분류돼 Phase 3(실 요청)로 넘어간 전체 후보 파라미터 목록을
                            한 번 보고한다. 각 원소는
                            {"url", "method", "param_name", "category"}.
                            findings[]에는 이상 신호가 잡힌 것만 남아서, 결과만 보고는
                            "테스트했지만 이상없음"과 "애초에 수집조차 안 됨"(예: 크롤러가
                            예약 생성 POST 같은 다단계 플로우를 못 찾은 경우)을 구분할 수
                            없었던 문제 대응 — 반환값(list[Finding]) 계약은 그대로 유지한 채
                            선택적 채널로만 노출한다.
        attempt_callback:  Callable[[dict], None] — Phase 3에서 실제로 전송한 (파라미터,
                            페이로드) 조합마다 한 번씩 호출된다. 각 dict는
                            {"url", "method", "param_name", "category", "payload_value",
                            "baseline_status", "test_status", "anomaly_type"}.
                            anomaly_type이 None이면 이상 신호 없음 — coverage_callback은
                            "시도는 됐다"만 알려줘서, 서버가 400/404로 거절해 애초에
                            비교 자체가 성립 안 한 것("탐지 로직 결함")과 서버가 정상
                            거절해서 진짜 이상 없음("정상 동작")을 구분할 수 없었다.
                            이 콜백으로 실제 응답 상태 코드까지 남겨 그 둘을 구분한다.

    Returns:
        List[Finding] — Phase 4에서 LLM이 검토한 항목 전체 (is_vulnerable=False 포함).
        확정된 취약점만 필요하면 [f for f in findings if f.is_vulnerable]로 거를 것.
    """
    findings: list[Finding] = []

    def report(phase: str, percent: int) -> None:
        if not progress_callback:
            return
        try:
            progress_callback(phase, percent)
        except Exception as e:
            logger.warning(f"progress_callback 호출 실패 (무시하고 진행): {e}")

    def report_coverage(candidate_params: list) -> None:
        if not coverage_callback:
            return
        try:
            coverage_callback([
                {
                    "url":        p.collected.url,
                    "method":     p.collected.method,
                    "param_name": p.collected.param_name,
                    "category":   p.category,
                }
                for p in candidate_params
            ])
        except Exception as e:
            logger.warning(f"coverage_callback 호출 실패 (무시하고 진행): {e}")

    def report_attempt(entry: dict) -> None:
        if not attempt_callback:
            return
        try:
            attempt_callback(entry)
        except Exception as e:
            logger.warning(f"attempt_callback 호출 실패 (무시하고 진행): {e}")

    # ── Phase 1: ZAP Ajax Spider 수집 ───────────────────────────
    logger.info(f"[Phase 1] ZAP Ajax Spider 시작: {target_url}")
    collected = collect_params(
        target_url,
        max_wait_seconds=max_wait_seconds,
        login_config=login_config,
        custom_header=custom_header,
        progress_callback=lambda pct: report("collect", pct),
        api_base_url=api_base_url,
    )
    logger.info(f"[Phase 1] 수집된 파라미터 수: {len(collected)}")

    if not collected:
        logger.warning("[Phase 1] 수집된 파라미터 없음 — 종료")
        return findings

    # ── Phase 2: 규칙 기반 사전 분류 (LLM 미사용) ───────────────
    logger.info("[Phase 2] 규칙 기반 파라미터 분류 시작")
    report("classify", 0)
    classified = classify_params(collected)
    report("classify", 100)

    # SAFE 제외 — 대상 서비스로 나가는 불필요한 요청을 줄임
    candidates = [p for p in classified if p.category != "SAFE"]
    logger.info(f"[Phase 2] 위험 파라미터 수 (SAFE 제외): {len(candidates)}")
    report_coverage(candidates)

    if not candidates:
        logger.info("[Phase 2] 위험 파라미터 없음 — 종료")
        return findings

    # ── Phase 3: 페이로드 주입 + 규칙 기반 1차 이상 탐지 ─────────
    logger.info("[Phase 3] 페이로드 주입 및 1차 이상 탐지 시작")
    raw_findings: list[RawFinding] = []
    report("manipulate", 0)
    for i, param in enumerate(candidates):
        manipulation_results = run_manipulation(param, custom_header=custom_header)
        for result in manipulation_results:
            raw_finding = detect_anomaly(
                param          = result["param"],
                payload_value  = result["payload_value"],
                payload_desc   = result["payload_description"],
                baseline       = result["baseline"],
                test           = result["test"],
            )

            persisted_finding = None
            if raw_finding:
                raw_findings.append(raw_finding)
                # 즉시 diff로 이미 잡힌 항목은 후속 검증(네트워크 추가 호출) 생략
            else:
                # ── Phase 3.5: 저장형(persisted) 권한 상승/가격 조작 후속 검증 ──
                # 회원가입처럼 응답에 role이, 예약/주문 생성처럼 응답에 가격이 노출되지
                # 않아 즉시 diff로는 무신호였던 케이스만 대상 — 두 verify_* 함수 모두
                # 내부에서 카테고리/메서드 힌트로 조건에 안 맞으면 네트워크 호출 없이
                # 즉시 None을 반환한다.
                persisted_finding = verify_persisted_privilege(
                    param              = result["param"],
                    payload_value      = result["payload_value"],
                    payload_desc       = result["payload_description"],
                    test_request_body  = result["test"].get("request_body", ""),
                    test_status        = result["test"]["status"],
                    custom_header      = custom_header,
                    login_config       = login_config,
                ) or verify_persisted_price(
                    param              = result["param"],
                    payload_value      = result["payload_value"],
                    payload_desc       = result["payload_description"],
                    test_request_body  = result["test"].get("request_body", ""),
                    test_status        = result["test"]["status"],
                    test_body          = result["test"]["body"],
                    custom_header      = custom_header,
                )
                if persisted_finding:
                    raw_findings.append(persisted_finding)

            found = raw_finding or persisted_finding
            report_attempt({
                "url":             result["param"].collected.url,
                "method":          result["param"].collected.method,
                "param_name":      result["param"].collected.param_name,
                "category":        result["param"].category,
                "payload_value":   result["payload_value"],
                "baseline_status": result["baseline"]["status"],
                "test_status":     result["test"]["status"],
                "anomaly_type":    found.anomaly_type if found else None,
            })

        report("manipulate", int((i + 1) / len(candidates) * 100))

    logger.info(f"[Phase 3/3.5] 1차 탐지된 이상 징후: {len(raw_findings)}건")
    if not raw_findings:
        logger.info("[Phase 3] 이상 징후 없음 — 종료")
        return findings

    # ── Phase 4: LLM이 이상 징후를 해석해 최종 취약 여부 확정 ────
    # 반환되는 findings에는 is_vulnerable=False(LLM이 검토 후 취약점 아니라고 판단한 것)도
    # 포함된다 — 뭐가 왜 걸러졌는지 검토할 수 있도록 여기서 숨기지 않는다.
    logger.info("[Phase 4] LLM 해석 시작")
    report("llm_review", 0)
    findings = interpret_findings(raw_findings, progress_callback=lambda pct: report("llm_review", pct))
    report("llm_review", 100)
    for finding in findings:
        if finding.is_vulnerable:
            logger.info(
                f"[Finding] [{finding.severity}] {finding.anomaly_type} | "
                f"{finding.url} | {finding.param_name}={finding.payload_used!r}"
            )

    # ── 결과 요약 ────────────────────────────────────────────────
    confirmed    = [f for f in findings if f.is_vulnerable]
    high_count   = sum(1 for f in confirmed if f.severity == "HIGH")
    medium_count = sum(1 for f in confirmed if f.severity == "MEDIUM")
    logger.info(
        f"[완료] 검토 {len(findings)}건 중 확정 findings: {len(confirmed)}건 "
        f"(HIGH: {high_count}, MEDIUM: {medium_count})"
    )

    return findings
