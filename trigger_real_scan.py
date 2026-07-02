"""
trigger_real_scan.py — Onde 서비스 로그인 후 획득한 JWT 토큰을 실어 Argus 스캔 트리거
"""
import requests
import json
import time

ONDE_HOST = "http://localhost:8080"
ARGUS_HOST = "http://localhost:8085"

def main():
    print("==============================================================")
    print(" 1. Onde 서비스 로그인 및 JWT 토큰 획득 시도")
    print("==============================================================")
    
    # 1. 로그인 요청
    login_url = f"{ONDE_HOST}/api/v1/auth/login"
    login_payload = {
        "email": "jisu@travel.com",
        "password": "12341234a"  # 올바른 패스워드로 수정
    }
    
    print(f"로그인 요청 대상: {login_url}")
    try:
        r = requests.post(login_url, json=login_payload, timeout=5)
        if r.status_code != 200:
            # 혹시 다른 디폴트 패스워드 시도
            login_payload["password"] = "password123"
            r = requests.post(login_url, json=login_payload, timeout=5)
            
        if r.status_code != 200:
            print(f"로그인 실패 (HTTP {r.status_code}): {r.text}")
            return
            
        data = r.json()
        token = data.get("accessToken")
        if not token:
            print(f"액세스 토큰 획득 실패. 응답 바디: {data}")
            return
            
        print("로그인 성공! JWT 토큰 획득 완료.")
        print(f"Token: {token[:30]}...")
        
    except Exception as e:
        print(f"로그인 요청 중 오류 발생: {e}")
        return

    print("\n==============================================================")
    print(" 2. Argus ASPM 스캔 트리거 요청 (api_base_url + custom_header)")
    print("==============================================================")
    
    scan_url = f"{ARGUS_HOST}/api/v1/scan/"
    scan_payload = {
        "target_url": "http://localhost:8080",
        "api_base_url": "http://localhost:8080",
        "custom_header": f"Authorization: Bearer {token}",
        "login_config": None
    }
    
    try:
        r = requests.post(scan_url, json=scan_payload, timeout=5)
        if r.status_code == 200:
            res_data = r.json()
            task_id = res_data.get("task_id")
            print(f"스캔이 성공적으로 트리거되었습니다!")
            print(f"Task ID: {task_id}")
            print("\n실시간 진행 상태 모니터링을 시작합니다...")
            
            # 모니터링 루프
            for _ in range(60):
                time.sleep(5)
                status_r = requests.get(f"{scan_url}{task_id}")
                if status_r.status_code == 200:
                    status_data = status_r.json()
                    state = status_data.get("state")
                    print(f"[{time.strftime('%H:%M:%S')}] 상태: {state}")
                    
                    if state == "SUCCESS":
                        result_path = status_data.get("result", {}).get("result_json_path")
                        total_alerts = status_data.get("result", {}).get("results", {}).get("total_alerts", 0)
                        print(f"\n🎉 진단 완료! 총 탐지된 이상 건수: {total_alerts}건")
                        print(f"결과 JSON 경로: {result_path}")
                        break
                    elif state == "FAILURE":
                        print(f"\n❌ 진단 작업 실패: {status_data.get('error')}")
                        break
        else:
            print(f"스캔 트리거 실패 (HTTP {r.status_code}): {r.text}")
            
    except Exception as e:
        print(f"스캔 API 호출 실패: {e}")

if __name__ == "__main__":
    main()
