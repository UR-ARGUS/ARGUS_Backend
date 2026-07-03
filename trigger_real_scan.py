"""
trigger_real_scan.py — 로그인 후 획득한 토큰을 실어 Argus 스캔을 트리거하는 범용 스크립트

특정 서비스 주소를 하드코딩하지 않는다 — 진단 대상은 모두 CLI 인자로 받는다.
로그인 없이 진단하려면 --login-url을 생략하고 --custom-header로 직접 인증 헤더를 넘기면 된다.
"""
import argparse
import time

import requests


def _get_nested(data: dict, dotted_field: str):
    """'data.accessToken' 같은 점(dot) 경로로 중첩된 응답 필드를 찾는다."""
    value = data
    for key in dotted_field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def login(login_url: str, email_field: str, email: str, password_field: str, password: str, token_field: str) -> str | None:
    payload = {email_field: email, password_field: password}
    print(f"로그인 요청 대상: {login_url}")
    try:
        r = requests.post(login_url, json=payload, timeout=5)
        if r.status_code != 200:
            print(f"로그인 실패 (HTTP {r.status_code}): {r.text}")
            return None

        data = r.json()
        token = _get_nested(data, token_field)
        if not token:
            print(f"토큰 필드 '{token_field}'를 응답에서 찾지 못했습니다. 응답 바디: {data}")
            return None

        print(f"로그인 성공! 토큰 획득 완료. Token: {token[:30]}...")
        return token
    except Exception as e:
        print(f"로그인 요청 중 오류 발생: {e}")
        return None


def trigger_scan(argus_host: str, target_url: str, api_base_url: str | None, custom_header: str | None) -> None:
    scan_url = f"{argus_host.rstrip('/')}/api/v1/scan/"
    scan_payload = {
        "target_url": target_url,
        "api_base_url": api_base_url,
        "custom_header": custom_header,
        "login_config": None,
    }

    print("\n==============================================================")
    print(" Argus ASPM 스캔 트리거 요청")
    print("==============================================================")
    try:
        r = requests.post(scan_url, json=scan_payload, timeout=5)
        if r.status_code != 200:
            print(f"스캔 트리거 실패 (HTTP {r.status_code}): {r.text}")
            return

        res_data = r.json()
        task_id = res_data.get("task_id")
        print("스캔이 성공적으로 트리거되었습니다!")
        print(f"Task ID: {task_id}")
        print("\n실시간 진행 상태 모니터링을 시작합니다...")

        for _ in range(60):
            time.sleep(5)
            status_r = requests.get(f"{scan_url}{task_id}")
            if status_r.status_code != 200:
                continue
            status_data = status_r.json()
            state = status_data.get("state")
            print(f"[{time.strftime('%H:%M:%S')}] 상태: {state}")

            if state == "SUCCESS":
                result_path = status_data.get("result", {}).get("result_json_path")
                total_alerts = status_data.get("result", {}).get("results", {}).get("total_alerts", 0)
                print(f"\n진단 완료! 총 탐지된 이상 건수: {total_alerts}건")
                print(f"결과 JSON 경로: {result_path}")
                break
            elif state == "FAILURE":
                print(f"\n진단 작업 실패: {status_data.get('error')}")
                break
    except Exception as e:
        print(f"스캔 API 호출 실패: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="로그인 후 토큰을 실어 Argus 스캔을 트리거하는 범용 스크립트"
    )
    parser.add_argument("--target-url",   required=True, help="진단 대상 URL (프론트엔드 SPA 등)")
    parser.add_argument("--api-base-url", default=None,  help="백엔드 API base URL (SPA와 분리된 경우 Swagger 병행 수집)")
    parser.add_argument("--argus-host",   default="http://localhost:8085", help="Argus 백엔드 주소")

    parser.add_argument("--login-url",      default=None, help="로그인 API URL (생략 시 로그인 없이 --custom-header만 사용)")
    parser.add_argument("--email",          default=None, help="로그인 이메일/아이디")
    parser.add_argument("--password",       default=None, help="로그인 비밀번호")
    parser.add_argument("--email-field",    default="email",       help="로그인 요청 바디의 이메일 필드명")
    parser.add_argument("--password-field", default="password",    help="로그인 요청 바디의 비밀번호 필드명")
    parser.add_argument("--token-field",    default="accessToken", help="로그인 응답에서 토큰이 담긴 필드명 (중첩 시 'data.accessToken'처럼 점 표기)")
    parser.add_argument("--custom-header",  default=None, help='직접 지정할 인증 헤더 (예: "Authorization: Bearer TOKEN"). --login-url과 함께 쓰면 로그인 토큰이 우선됨')

    args = parser.parse_args()

    custom_header = args.custom_header
    if args.login_url:
        if not (args.email and args.password):
            parser.error("--login-url을 사용하려면 --email과 --password가 필요합니다.")
        token = login(args.login_url, args.email_field, args.email, args.password_field, args.password, args.token_field)
        if not token:
            return
        custom_header = f"Authorization: Bearer {token}"

    trigger_scan(args.argus_host, args.target_url, args.api_base_url, custom_header)


if __name__ == "__main__":
    main()
