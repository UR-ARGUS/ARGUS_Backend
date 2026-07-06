"""
verify_redirect_scan.py — Postgres/Redis/Celery 없이 1-5 리다이렉트 스캔 엔진만 검증하는 독립 스크립트

verify_scan.py(1-3)와 동일한 패턴 — scanners.redirect_forward.engine.run_redirect_scan을
직접 호출해서 스캔을 돌리고 결과를 확인한다.

실행 방법:
    venv/Scripts/python.exe verify_redirect_scan.py --url http://localhost:5173 --verbose
"""

import argparse
import io
import json
import logging
import sys
from dataclasses import asdict
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from argus.core.config import settings
from scanners.redirect_forward.engine import run_redirect_scan


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


def check_zap_reachable(api_url: str, api_key: str) -> bool:
    import requests as req
    try:
        url = f"{api_url}/JSON/core/view/version/"
        params = {"apikey": api_key} if api_key else {}
        r = req.get(url, params=params, timeout=5)
        version = r.json().get("version", "unknown")
        print(f"[v] ZAP 응답 확인 — version: {version}")
        return True
    except Exception as e:
        print(f"[x] ZAP 에 접근할 수 없습니다: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="1-5 리다이렉트/포워드 스캔 엔진 독립 검증 스크립트")
    parser.add_argument("--url", required=True, help="진단 대상 URL")
    parser.add_argument("--api-base", default="", help="백엔드 API base URL (Swagger 병행 수집)")
    parser.add_argument("--auth", default="", help='인증 헤더 (예: "Bearer TOKEN")')
    parser.add_argument("--payload-host", default=None, help="리다이렉트 목적지로 주입할 외부 호스트")
    parser.add_argument("--max-wait", type=int, default=120, help="Ajax Spider 완료 대기 최대 시간(초)")
    parser.add_argument("--login-url", default=None, help="로그인 API URL")
    parser.add_argument("--email-field", default="email", help="로그인 요청 바디의 이메일 필드명")
    parser.add_argument("--password-field", default="password", help="로그인 요청 바디의 비밀번호 필드명")
    parser.add_argument("--email", default=None, help="로그인 이메일/아이디")
    parser.add_argument("--password", default=None, help="로그인 비밀번호")
    parser.add_argument("--login-content-type", default="json", help="로그인 요청 바디 형식 (json|form)")
    parser.add_argument("--verbose", action="store_true", help="상세 로그 출력")
    args = parser.parse_args()

    setup_logging(args.verbose)

    print("=" * 60)
    print(" Argus — 1-5 리다이렉트/포워드(Reflected) 스캔 엔진 독립 검증")
    print("=" * 60)
    print(f"  대상 URL: {args.url}")
    print()

    if not check_zap_reachable(settings.ZAP_API_URL, settings.ZAP_API_KEY):
        sys.exit(1)

    coverage: list = []

    def progress(phase: str, pct: int) -> None:
        print(f"      [{phase}] {pct}%", end="\r", flush=True)

    login_config = None
    if args.login_url:
        if not (args.email and args.password):
            parser.error("--login-url을 사용하려면 --email과 --password가 필요합니다.")
        login_config = {
            "login_url": args.login_url,
            "username_field": args.email_field,
            "password_field": args.password_field,
            "username": args.email,
            "password": args.password,
            "content_type": args.login_content_type,
        }

    kwargs = dict(
        max_wait_seconds=args.max_wait,
        custom_header=args.auth or None,
        api_base_url=args.api_base or None,
        login_config=login_config,
        progress_callback=progress,
        coverage_callback=coverage.extend,
    )
    if args.payload_host:
        kwargs["payload_host"] = args.payload_host

    findings = run_redirect_scan(args.url, **kwargs)
    print()

    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")

    print("\n결과 요약")
    print(f"  후보로 선정된 파라미터 수: {len(coverage)}")
    print(f"  확정 Reflected findings: {len(findings)} (HIGH: {high_count}, MEDIUM: {medium_count})")

    if coverage:
        print("\n  --- 후보 파라미터 (Phase 2) ---")
        for c in coverage:
            print(f"  {c['method']} {c['url']} | {c['param_name']} ({c['reason']})")

    if findings:
        print("\n  --- 확정 Findings ---")
        for f in findings:
            print(f"  [{f.severity:6}] {f.detection_type}")
            print(f"           URL:   {f.method} {f.url}")
            print(f"           Param: {f.param_name} = {f.payload_used!r}")
            print(f"           Evidence: {f.evidence[:200]}")
            print()
    else:
        print("\n  [!] 확정 findings 0건 — 후보 파라미터 수가 0이면 크롤링/이름규칙 매칭 실패,")
        print("      후보는 있는데 findings가 0이면 실제로 안전하거나 페이로드가 안 먹힌 것.")

    import os
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"verify_redirect_scan_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(finding) for finding in findings], f, ensure_ascii=False, indent=2)
    print(f"\n[v] 결과 저장: {path}")


if __name__ == "__main__":
    main()
