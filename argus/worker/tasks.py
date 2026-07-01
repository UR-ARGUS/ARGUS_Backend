from argus.core.celery_app import celery_app
from argus.core.config import settings
from argus.services.scan.zap import ZapScanner
import json
import logging
import os

logger = logging.getLogger("argus.tasks")

def save_scan_result_json(task_id: str, alerts: list) -> str:
    # capture_pipeline의 load_zap_json()이 그대로 읽을 수 있도록 zap.core.alerts() 평탄 리스트 형식으로 저장
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"{task_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    return path

@celery_app.task(bind=True)
def run_scan_task(self, target_url: str, login_config: dict = None, custom_header: str = None):
    logger.info(f"ZAP 스캔 작업 시작: {target_url}")
    try:
        scanner = ZapScanner(zap_api_url=settings.ZAP_API_URL, api_key=settings.ZAP_API_KEY or None)
        scanner.setup_parameter_tampering_policy()

        context_id = None
        if login_config:
            logger.info("자동 로그인 정보가 제공되어 ZAP 인증을 설정합니다.")
            context_id = scanner.setup_authentication(target_url, login_config)

        # ZAP API에 헤더/쿠키 주입 설정 적용.
        # custom_header가 없는 스캔이어도 항상 호출해야 한다 — Replacer 규칙은 ZAP 인스턴스에
        # 전역으로 남기 때문에, 여기서 호출하지 않으면 이전 스캔에서 설정한 인증 토큰이
        # 이번 스캔에도 계속 주입된다.
        if custom_header:
            logger.info(f"사용자 정의 헤더/쿠키 주입 적용: {custom_header}")
        scanner.setup_replacer_header(custom_header)

        def report_progress(phase: str, percent: int):
            self.update_state(state="PROGRESS", meta={"phase": phase, "percent": percent})

        results = scanner.run_scan(target_url, context_id=context_id, progress_callback=report_progress)
        result_json_path = save_scan_result_json(self.request.id, results.get("parameter_tampering_alerts", []))
        logger.info(f"ZAP 스캔 작업 완료. 발견된 취약점 개수: {results.get('total_alerts', 0)} (결과 JSON: {result_json_path})")
        return {"status": "completed", "target": target_url, "results": results, "result_json_path": result_json_path}
    except Exception as e:
        logger.error(f"ZAP 스캔 작업 실패: {e}")
        return {"status": "failed", "error": str(e), "target": target_url}

@celery_app.task
def run_capture_task(target_url: str):
    # Placeholder for Selenium capture replay
    return {"status": "completed", "target": target_url}

@celery_app.task
def generate_report_task(target_url: str):
    # Placeholder for reaching cross-validation & PDF generation
    return {"status": "completed", "target": target_url}
