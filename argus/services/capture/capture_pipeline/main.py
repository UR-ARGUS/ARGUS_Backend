"""
파이프라인 전체 오케스트레이션

흐름:
  ZAP JSON 파일 경로 입력
    → CaptureJob 리스트 생성 (capture_job.py)
    → (선택) 로그인 인증 정보 획득 — 이전에 설계한 크리덴셜 입력 방식과 연결되는 지점
    → Selenium 3단계 캡처 실행 (selenium_capture.py)
    → CaptureResult 리스트 반환 → 다음 단계(PIL 어노테이션, STEP4)로 전달

이 파일은 STEP4(PIL 어노테이션) 이전까지만 책임진다.
STEP4~6(어노테이션/보고서 합치기/S3 업로드)은 별도 모듈에서 CaptureResult를 입력으로 받아 처리.
"""

import argparse
import json
import logging
from typing import Optional

from capture_job import load_zap_json, convert_to_capture_jobs
from selenium_capture import run_jobs, CaptureResult

logger = logging.getLogger("pipeline_main")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def get_auth_via_api(login_api_url: str, id_field: str, pw_field: str,
                      test_id: str, test_pw: str, token_json_key: str) -> dict:
    """
    JSON API 방식 로그인 — 이전 단계에서 설계한 '③ API 직접 호출' 방식.
    토큰을 발급받아 Selenium에 주입할 헤더 형태로 반환.
    """
    import requests

    response = requests.post(
        login_api_url,
        json={id_field: test_id, pw_field: test_pw},
        timeout=10,
    )
    response.raise_for_status()
    token = response.json().get(token_json_key)

    if not token:
        raise ValueError(
            f"응답 JSON에서 '{token_json_key}' 키를 찾지 못함. "
            f"실제 응답 키 목록: {list(response.json().keys())}"
        )

    logger.info("API 로그인 성공 — 토큰 획득 완료")
    return {"Authorization": f"Bearer {token}"}


def get_auth_via_form(login_url: str, id_field: str, pw_field: str,
                       test_id: str, test_pw: str) -> list:
    """
    Form 기반 로그인 — Selenium으로 로그인 폼을 직접 제출하고 세션 쿠키를 추출.
    이전 단계에서 설계한 '① Selenium 로그인 후 쿠키 추출' 방식.
    """
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(options=options)
    try:
        driver.get(login_url)
        driver.find_element(By.NAME, id_field).send_keys(test_id)
        driver.find_element(By.NAME, pw_field).send_keys(test_pw)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit'], input[type='submit']").click()

        import time
        time.sleep(2)  # 로그인 처리 및 리다이렉트 대기

        cookies = driver.get_cookies()
        logger.info("Form 로그인 성공 — 쿠키 %d개 획득", len(cookies))
        return cookies
    finally:
        driver.quit()


def run_pipeline(
    zap_json_path: str,
    output_dir: str = "./captures",
    only_risk: Optional[set] = None,
    auth_config: Optional[dict] = None,
    max_per_alert_group: Optional[int] = 5,
) -> list:
    """
    전체 파이프라인 실행 진입점.

    Args:
        zap_json_path: ZAP가 생성한 결과 JSON 파일 경로
        output_dir: 스크린샷 저장 경로
        only_risk: {"High", "Medium"} 등 캡처 대상 risk 필터
        auth_config: 사용자가 입력한 로그인 설정. 예:
            {
                "enabled": True,
                "method": "api",  # "api" | "form" | None
                "login_url": "https://example.com/api/v1/auth/login",
                "id_field": "email",
                "pw_field": "password",
                "test_id": "tester@example.com",
                "test_pw": "Test1234!",
                "token_json_key": "accessToken",  # method == "api"일 때만 필요
            }

    Returns:
        CaptureResult 리스트
    """
    # 1. ZAP JSON → CaptureJob 변환 (동일 alert 대량 중복 시 샘플링 적용)
    alerts = load_zap_json(zap_json_path)
    jobs = convert_to_capture_jobs(alerts, only_risk=only_risk, max_per_alert_group=max_per_alert_group)
    logger.info("ZAP JSON 파싱 완료 — %d개 CaptureJob 생성 (중복 샘플링 적용)", len(jobs))

    if not jobs:
        logger.warning("캡처할 job이 없음 (risk 필터 조건을 확인하세요)")
        return []

    # 2. 인증 정보 획득 (선택)
    auth_cookies, auth_headers = None, None
    if auth_config and auth_config.get("enabled"):
        method = auth_config.get("method")
        if method == "api":
            auth_headers = get_auth_via_api(
                login_api_url=auth_config["login_url"],
                id_field=auth_config["id_field"],
                pw_field=auth_config["pw_field"],
                test_id=auth_config["test_id"],
                test_pw=auth_config["test_pw"],
                token_json_key=auth_config["token_json_key"],
            )
        elif method == "form":
            auth_cookies = get_auth_via_form(
                login_url=auth_config["login_url"],
                id_field=auth_config["id_field"],
                pw_field=auth_config["pw_field"],
                test_id=auth_config["test_id"],
                test_pw=auth_config["test_pw"],
            )
        else:
            logger.warning("auth_config.enabled=True이지만 method가 'api'/'form'이 아님: %s", method)

    # 3. Selenium 3단계 캡처 실행
    results = run_jobs(
        jobs,
        output_dir=output_dir,
        auth_cookies=auth_cookies,
        auth_headers=auth_headers,
    )

    confirmed = sum(1 for r in results if r.confirmed)
    logger.info("파이프라인 완료 — 총 %d건 중 %d건 confirmed=True", len(results), confirmed)

    return results


def results_to_json(results: list, path: str):
    """STEP4(PIL 어노테이션) 모듈로 넘길 수 있도록 결과를 JSON으로 저장."""
    data = [
        {
            "job_id": r.job_id,
            "before_path": r.before_path,
            "input_path": r.input_path,
            "result_path": r.result_path,
            "confirmed": r.confirmed,
            "failure_reason": r.failure_reason,
            "highlight_box": r.highlight_box,
        }
        for r in results
    ]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    logger.info("결과 JSON 저장 완료 → %s", path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZAP JSON → Selenium 캡처 파이프라인")
    parser.add_argument("zap_json", help="ZAP 결과 JSON 파일 경로")
    parser.add_argument("--output-dir", default="./captures")
    parser.add_argument("--risk", nargs="*", default=["High", "Medium", "Low"],
                         help="캡처 대상 risk 레벨 (기본: High Medium Low — Low risk에도 "
                              "CSRF/정보노출 등 캡처할 가치가 있는 항목이 흔하므로 기본 포함)")
    parser.add_argument("--result-json", default="./captures/capture_results.json",
                         help="최종 결과를 저장할 JSON 경로 (기본값: captures/ 폴더 — "
                              "docker-compose volume 마운트 대상이라 컨테이너 종료 후에도 호스트에 남음)")
    parser.add_argument("--max-per-group", type=int, default=5,
                         help="동일 (alert, risk) 조합 중 'low-value' 카테고리(예: 무차별 버퍼오버플로우 "
                              "테스트)가 이 개수를 초과하면 샘플링. 0 이하 입력 시 제한 없음.")

    # 인증 옵션 (선택 입력 — 이전 단계에서 설계한 UI에 대응)
    parser.add_argument("--auth-method", choices=["api", "form"], default=None)
    parser.add_argument("--login-url")
    parser.add_argument("--id-field")
    parser.add_argument("--pw-field")
    parser.add_argument("--test-id")
    parser.add_argument("--test-pw")
    parser.add_argument("--token-json-key", default="accessToken")

    args = parser.parse_args()

    auth_config = None
    if args.auth_method:
        auth_config = {
            "enabled": True,
            "method": args.auth_method,
            "login_url": args.login_url,
            "id_field": args.id_field,
            "pw_field": args.pw_field,
            "test_id": args.test_id,
            "test_pw": args.test_pw,
            "token_json_key": args.token_json_key,
        }

    max_per_group = args.max_per_group if args.max_per_group > 0 else None

    results = run_pipeline(
        zap_json_path=args.zap_json,
        output_dir=args.output_dir,
        only_risk=set(args.risk) if args.risk else None,
        auth_config=auth_config,
        max_per_alert_group=max_per_group,
    )

    results_to_json(results, args.result_json)
