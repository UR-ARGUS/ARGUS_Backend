"""
verify_scan.py — Postgres/Redis/Celery 없이 파라미터 조작 스캔 엔진만 검증하는 독립 스크립트

FastAPI + Celery 를 전부 올리지 않아도 scanners.param_manipulation.engine.run_scan 을
직접 호출해서 스캔을 돌리고 결과를 확인할 수 있다.

─────────────────────────────── 실행 방법 ──────────────────────────────────
# Poetry 환경 (pyproject.toml 기준)
poetry run python verify_scan.py --url https://target.com

# 또는 가상환경 직접 활성화 후
python verify_scan.py --url https://target.com --auth "Bearer TOKEN" --verbose

# 선택 옵션
#   --url        진단 대상 URL (필수)
#   --api-url    ZAP REST API URL (기본: .env 의 ZAP_API_URL)
#   --api-key    ZAP API Key (기본: .env 의 ZAP_API_KEY)
#   --auth       Authorization/Cookie 헤더값 (e.g. "Bearer xxx" 또는 "Cookie: SESSION=yyy")
#   --api-base   백엔드 API base URL (SPA 와 API 서버가 분리된 경우, Swagger/OpenAPI 스펙 스캔)
#   --max-wait   Ajax Spider 완료 대기 최대 시간(초, 기본 120)
#   --verbose    상세 로그를 stdout 에 출력
─────────────────────────────────────────────────────────────────────────────

주의:
- ZAP 이 포트 8090 으로 실행 중이어야 합니다 (collector.py의 Phase 1이 ZAP Ajax Spider를 사용).
- AJAX Spider 는 chrome-headless 를 사용하므로 Chrome 이 설치되어 있어야 합니다.
"""

import argparse
import json
import logging
import sys
from dataclasses import asdict
from datetime import datetime

# scanners 패키지는 프로젝트 루트에서 실행해야 임포트가 된다.
# (poetry run python verify_scan.py 또는 PYTHONPATH=. python verify_scan.py)
from argus.core.config import settings
from scanners.param_manipulation.engine import run_scan


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


def check_zap_reachable(api_url: str, api_key: str) -> bool:
    """ZAP REST API 접근 가능 여부 사전 확인."""
    import requests as req
    try:
        url = f"{api_url}/JSON/core/view/version/"
        params = {"apikey": api_key} if api_key else {}
        r = req.get(url, params=params, timeout=5)
        version = r.json().get("version", "unknown")
        print(f"[✓] ZAP 응답 확인 — version: {version}")
        return True
    except Exception as e:
        print(f"[✗] ZAP 에 접근할 수 없습니다: {e}")
        print("    → ZAP 이 실행 중인지, 포트가 맞는지 확인하세요.")
        print(f"    → 현재 설정 URL: {api_url}")
        return False


def check_chrome_headless(api_url: str, api_key: str) -> None:
    """AJAX Spider 브라우저 설정 확인."""
    import requests as req
    try:
        url = f"{api_url}/JSON/ajaxSpider/view/optionBrowserId/"
        params = {"apikey": api_key} if api_key else {}
        r = req.get(url, params=params, timeout=5)
        browser = r.json().get("BrowserId", "unknown")
        if "chrome" in browser.lower():
            print(f"[✓] AJAX Spider 브라우저: {browser}")
        else:
            print(f"[!] AJAX Spider 브라우저가 {browser} 입니다 (chrome-headless 권장)")
            print("    → ZAP GUI: Tools > Options > Ajax Spider > Browser 를 'Chrome Headless' 로 변경")
    except Exception:
        print("[!] AJAX Spider 브라우저 설정을 확인할 수 없습니다 (무시하고 계속)")


def run_verify(
    target_url: str,
    auth_header: str,
    api_base_url: str,
    max_wait_seconds: int,
) -> list:
    if api_base_url:
        print(f"      Swagger/OpenAPI Spec + ZAP 병행 스캔 모드: {api_base_url}")

    print(f"\n스캔 실행: {target_url}")

    def progress(phase: str, pct: int) -> None:
        print(f"      [{phase}] {pct}%", end="\r", flush=True)

    findings = run_scan(
        target_url,
        max_wait_seconds=max_wait_seconds,
        custom_header=auth_header or None,
        progress_callback=progress,
        api_base_url=api_base_url,
    )
    print()  # 줄바꿈

    confirmed = [f for f in findings if f.is_vulnerable]
    high_count = sum(1 for f in confirmed if f.severity == "HIGH")
    medium_count = sum(1 for f in confirmed if f.severity == "MEDIUM")

    print("\n결과 요약")
    print(f"  검토 항목:    {len(findings)}")
    print(f"  확정 취약점:  {len(confirmed)} (HIGH: {high_count}, MEDIUM: {medium_count})")

    if confirmed:
        print("\n  ─── 확정 Findings ───")
        for f in confirmed:
            print(f"  [{f.severity:6}] {f.anomaly_type}")
            print(f"           URL:   {f.method} {f.url}")
            print(f"           Param: {f.param_name} = {f.payload_used!r}")
            print()
    else:
        print("\n  [!] 확정 취약점 0건 — 체크리스트:")
        print("      1) [Phase 1] 로그에서 수집된 파라미터 수가 0인지 확인 (크롤링 자체 실패 가능)")
        print("      2) [Phase 2] 위험 파라미터(SAFE 제외) 수가 0인지 확인 (분류 규칙에 안 걸림)")
        print("      3) [Phase 3] 1차 이상 탐지 건수가 0인지 확인 (실제로 안전하거나 탐지 규칙 미스)")
        print("      4) [Phase 4] LLM이 1차 탐지를 검토 후 취약점 아니라고 판단했을 수 있음 (--verbose로 상세 로그 확인)")
        print("      5) OpenAPI 스펙 경로(/openapi.json 등)가 있다면 --api-base 옵션으로 재시도")

    return findings


def save_result(findings: list) -> str:
    import os
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"verify_scan_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(finding) for finding in findings], f, ensure_ascii=False, indent=2)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="파라미터 조작 스캔 엔진 독립 검증 스크립트 (Postgres/Redis/Celery 불필요)"
    )
    parser.add_argument("--url",      required=True,  help="진단 대상 URL")
    parser.add_argument("--api-url",  default=None,   help="ZAP REST API URL (기본: .env ZAP_API_URL)")
    parser.add_argument("--api-key",  default=None,   help="ZAP API Key (기본: .env ZAP_API_KEY)")
    parser.add_argument("--auth",     default="",     help='Authorization/Cookie 헤더 (예: "Bearer TOKEN")')
    parser.add_argument("--api-base", default="",     help="백엔드 API base URL (SPA 와 분리된 경우)")
    parser.add_argument("--max-wait", type=int, default=120, help="Ajax Spider 완료 대기 최대 시간(초)")
    parser.add_argument("--verbose",  action="store_true", help="상세 로그 출력")
    args = parser.parse_args()

    setup_logging(args.verbose)

    api_url = args.api_url or settings.ZAP_API_URL
    api_key = args.api_key or settings.ZAP_API_KEY

    print("=" * 60)
    print(" Argus — 파라미터 조작 스캔 엔진 독립 검증")
    print("=" * 60)
    print(f"  대상 URL:  {args.url}")
    print(f"  ZAP URL:   {api_url}")
    print(f"  Auth:      {'설정됨' if args.auth else '없음'}")
    print()

    # 사전 체크 — Phase 1(collector.py)이 이 ZAP 데몬을 그대로 사용한다.
    if not check_zap_reachable(api_url, api_key):
        sys.exit(1)
    check_chrome_headless(api_url, api_key)
    print()

    # 스캔 실행
    findings = run_verify(
        target_url=args.url,
        auth_header=args.auth,
        api_base_url=args.api_base,
        max_wait_seconds=args.max_wait,
    )

    # 결과 저장
    path = save_result(findings)
    print(f"\n[✓] 결과 저장: {path}")


if __name__ == "__main__":
    main()
