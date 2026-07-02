"""
verify_scan.py — Postgres/Redis/Celery 없이 ZAP 파이프라인만 검증하는 독립 스크립트

실제 작업에서 쓴 방법: FastAPI + Celery 를 전부 올리지 않아도
ZapScanner 만 직접 인스턴스화해서 스캔을 돌리고 결과를 확인할 수 있다.

─────────────────────────────── 실행 방법 ──────────────────────────────────
# Poetry 환경 (pyproject.toml 기준)
poetry run python verify_scan.py --url https://target.com

# 또는 가상환경 직접 활성화 후
python verify_scan.py --url https://target.com --auth "Bearer TOKEN" --verbose

# 선택 옵션
#   --url        진단 대상 URL (필수)
#   --api-url    ZAP REST API URL (기본: .env 의 ZAP_API_URL)
#   --api-key    ZAP API Key (기본: .env 의 ZAP_API_KEY)
#   --auth       Authorization 헤더값 (e.g. "Bearer xxx" 또는 "Cookie: SESSION=yyy")
#   --api-base   백엔드 API base URL (SPA 와 API 서버가 분리된 경우)
#   --verbose    ZAP 로그를 stdout 에 출력
─────────────────────────────────────────────────────────────────────────────

주의:
- ZAP 이 포트 8090 으로 실행 중이어야 합니다.
- AJAX Spider 는 chrome-headless 를 사용하므로 Chrome 이 설치되어 있어야 합니다.
- ZAP_JVM.properties 한글 인코딩 설정(-Dfile.encoding=UTF-8)을 적용한 뒤
  ZAP 을 재시작해야 결과 JSON 의 한글이 깨지지 않습니다.
"""

import argparse
import json
import logging
import sys
from datetime import datetime

# ZapScanner 는 argus 패키지 안에 있으므로, 프로젝트 루트에서 실행해야 임포트가 된다.
# (poetry run python verify_scan.py 또는 PYTHONPATH=. python verify_scan.py)
from argus.core.config import settings
from argus.services.scan.zap import ZapScanner


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


def check_encoding(api_url: str, api_key: str) -> None:
    """
    ZAP_JVM.properties 인코딩 설정 확인.
    ZAP 경고 로그에 'file.encoding' 관련 내용이 없는지 간접 확인한다.
    실제로는 ZAP 설치 경로의 ZAP_JVM.properties 파일에
        -Dfile.encoding=UTF-8
    한 줄이 있어야 하며, 변경 후 반드시 ZAP 을 재시작해야 한다.
    """
    print("[i] 한글 인코딩 체크리스트:")
    print("    ZAP 설치 경로(예: C:\\Program Files\\ZAP\\Zed Attack Proxy\\ZAP_JVM.properties)")
    print("    파일에 다음 줄이 있는지 확인:")
    print("        -Dfile.encoding=UTF-8")
    print("    없으면 추가 후 ZAP 을 완전히 종료 후 재시작해야 합니다.")


def run_verify(
    target_url: str,
    api_url: str,
    api_key: str,
    auth_header: str,
    api_base_url: str,
) -> dict:
    scanner = ZapScanner(zap_api_url=api_url, api_key=api_key or None)

    print("\n[1/3] 스캔 정책 초기화 (커스텀 diff 스크립트 로드 포함)...")
    scanner.setup_replacer_header(auth_header or None)
    scanner.setup_parameter_tampering_policy()
    print("[✓] 정책 설정 완료")

    print(f"\n[2/3] 스캔 실행: {target_url}")
    if api_base_url:
        print(f"      백엔드 API: {api_base_url}")

    def progress(phase: str, pct: int) -> None:
        print(f"      {phase}: {pct}%", end="\r", flush=True)

    result = scanner.run_scan(
        target_url=target_url,
        progress_callback=progress,
        api_base_url=api_base_url or None,
    )
    print()  # 줄바꿈

    print("\n[3/3] 결과 요약")
    print(f"  전체 Alert:              {result['total_alerts']}")
    print(f"  Parameter Tampering:     {len(result['parameter_tampering_alerts'])}")

    tampering = result["parameter_tampering_alerts"]
    if tampering:
        print("\n  ─── Parameter Tampering Alerts ───")
        for a in tampering:
            risk = a.get("risk", "?")
            name = a.get("alert", "?")
            url  = a.get("url", "?")
            param = a.get("param", "-")
            print(f"  [{risk:6}] {name}")
            print(f"           URL:   {url}")
            print(f"           Param: {param}")
            print()
    else:
        print("\n  [!] Parameter Tampering Alert 0건 — 체크리스트:")
        print("      1) ZAP 사이트 트리에 대상 URL 이 보이는지 확인 (URL 접근 자체 실패 가능)")
        print("      2) Alert 탭에 'GENERIC_ERROR' 만 있으면 커스텀 스크립트 로드 실패 의심")
        print("         → ZAP Scripts 탭에서 ArgusParamDiff 가 enabled=true 인지 확인")
        print("      3) High risk 0건 — 실제 취약점이 없거나, 진단 대상에 파라미터가 없을 수 있음")
        print("         → OpenAPI 스펙 경로(/openapi.json 등)가 있는지 직접 확인 후 --api-base 옵션 시도")
        print("      4) 한글 깨짐 — ZAP_JVM.properties 에 -Dfile.encoding=UTF-8 적용 후 ZAP 재시작")

    return result


def save_result(result: dict) -> str:
    import os
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"verify_scan_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZAP 파이프라인 독립 검증 스크립트 (Postgres/Redis/Celery 불필요)"
    )
    parser.add_argument("--url",      required=True,  help="진단 대상 URL")
    parser.add_argument("--api-url",  default=None,   help="ZAP REST API URL (기본: .env ZAP_API_URL)")
    parser.add_argument("--api-key",  default=None,   help="ZAP API Key (기본: .env ZAP_API_KEY)")
    parser.add_argument("--auth",     default="",     help='Authorization 헤더 (예: "Bearer TOKEN")')
    parser.add_argument("--api-base", default="",     help="백엔드 API base URL (SPA 와 분리된 경우)")
    parser.add_argument("--verbose",  action="store_true", help="상세 로그 출력")
    args = parser.parse_args()

    setup_logging(args.verbose)

    api_url = args.api_url or settings.ZAP_API_URL
    api_key = args.api_key or settings.ZAP_API_KEY

    print("=" * 60)
    print(" Argus — ZAP 파이프라인 독립 검증")
    print("=" * 60)
    print(f"  대상 URL:  {args.url}")
    print(f"  ZAP URL:   {api_url}")
    print(f"  Auth:      {'설정됨' if args.auth else '없음'}")
    print()

    # 사전 체크
    if not check_zap_reachable(api_url, api_key):
        sys.exit(1)
    check_chrome_headless(api_url, api_key)
    check_encoding(api_url, api_key)
    print()

    # 스캔 실행
    result = run_verify(
        target_url=args.url,
        api_url=api_url,
        api_key=api_key,
        auth_header=args.auth,
        api_base_url=args.api_base,
    )

    # 결과 저장
    path = save_result(result)
    print(f"\n[✓] 결과 저장: {path}")


if __name__ == "__main__":
    main()
