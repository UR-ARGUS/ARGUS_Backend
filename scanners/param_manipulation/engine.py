"""
engine.py — 전체 파이프라인 오케스트레이터

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 7

역할:
    - Phase 1~4를 순서대로 실행
    - 각 단계 결과를 다음 단계로 전달
    - 최종 findings[] 리스트를 반환 → Selenium 증적 캡처 모듈로 전달

파이프라인 (v2 — LLM을 Phase 4로 이동, 탐지는 규칙 기반으로 유계 실행시간 보장):
    Phase 1: collector.py  — 파라미터 수집
    Phase 2: classifier.py — 규칙 기반 사전 분류 (LLM 미사용, SAFE 필터링으로 요청량 절감)
    Phase 3: manipulator.py + comparator.py — 페이로드 주입 + 규칙 기반 1차 이상 탐지 (RawFinding)
    Phase 4: classifier.py — LLM이 RawFinding을 해석해 최종 Finding으로 확정 (timeout 적용)

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
from .models      import Finding, RawFinding

logger = logging.getLogger(__name__)


def run_scan(
    target_url: str,
    max_wait_seconds: int = 120,
    login_config: dict = None,
    custom_header: str = None,
) -> list[Finding]:
    """
    1-3 스캔 엔진 진입점.

    target_url과 옵션 정보(login_config, custom_header)를 받아 Phase 1~4를 순서대로 실행하고
    이상 탐지 결과인 findings[] 리스트를 반환한다.

    Args:
        target_url:        진단 대상 URL
        max_wait_seconds:  Ajax Spider 완료 대기 최대 시간 (초, 기본 120)
        login_config:      자동 로그인 설정 정보
        custom_header:     사용자 정의 헤더/쿠키 문자열

    Returns:
        List[Finding] — Selenium 모듈로 그대로 전달 가능
    """
    findings: list[Finding] = []

    # ── Phase 1: ZAP Ajax Spider 수집 ───────────────────────────
    logger.info(f"[Phase 1] ZAP Ajax Spider 시작: {target_url}")
    collected = collect_params(
        target_url, 
        max_wait_seconds=max_wait_seconds,
        login_config=login_config,
        custom_header=custom_header
    )
    logger.info(f"[Phase 1] 수집된 파라미터 수: {len(collected)}")

    if not collected:
        logger.warning("[Phase 1] 수집된 파라미터 없음 — 종료")
        return findings

    # ── Phase 2: 규칙 기반 사전 분류 (LLM 미사용) ───────────────
    logger.info("[Phase 2] 규칙 기반 파라미터 분류 시작")
    classified = classify_params(collected)

    # SAFE 제외 — 대상 서비스로 나가는 불필요한 요청을 줄임
    candidates = [p for p in classified if p.category != "SAFE"]
    logger.info(f"[Phase 2] 위험 파라미터 수 (SAFE 제외): {len(candidates)}")

    if not candidates:
        logger.info("[Phase 2] 위험 파라미터 없음 — 종료")
        return findings

    # ── Phase 3: 페이로드 주입 + 규칙 기반 1차 이상 탐지 ─────────
    logger.info("[Phase 3] 페이로드 주입 및 1차 이상 탐지 시작")
    raw_findings: list[RawFinding] = []
    for param in candidates:
        manipulation_results = run_manipulation(param, custom_header=custom_header)
        for result in manipulation_results:
            raw_finding = detect_anomaly(
                param          = result["param"],
                payload_value  = result["payload_value"],
                payload_desc   = result["payload_description"],
                baseline       = result["baseline"],
                test           = result["test"],
            )
            if raw_finding:
                raw_findings.append(raw_finding)

    logger.info(f"[Phase 3] 1차 탐지된 이상 징후: {len(raw_findings)}건")
    if not raw_findings:
        logger.info("[Phase 3] 이상 징후 없음 — 종료")
        return findings

    # ── Phase 4: LLM이 이상 징후를 해석해 최종 취약 여부 확정 ────
    logger.info("[Phase 4] LLM 해석 시작")
    findings = interpret_findings(raw_findings)
    for finding in findings:
        logger.info(
            f"[Finding] [{finding.severity}] {finding.anomaly_type} | "
            f"{finding.url} | {finding.param_name}={finding.payload_used!r}"
        )

    # ── 결과 요약 ────────────────────────────────────────────────
    high_count   = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    logger.info(
        f"[완료] 총 findings: {len(findings)}건 "
        f"(HIGH: {high_count}, MEDIUM: {medium_count})"
    )

    return findings
