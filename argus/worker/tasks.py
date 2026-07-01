from argus.core.celery_app import celery_app
from argus.core.config import settings
from argus.services.scan.zap import ZapScanner
import logging

logger = logging.getLogger("argus.tasks")

@celery_app.task
def run_scan_task(target_url: str, login_config: dict = None):
    logger.info(f"ZAP 스캔 작업 시작: {target_url}")
    try:
        scanner = ZapScanner(zap_api_url=settings.ZAP_API_URL, api_key=settings.ZAP_API_KEY or None)
        scanner.setup_parameter_tampering_policy()
        
        context_id = None
        if login_config:
            logger.info("자동 로그인 정보가 제공되어 ZAP 인증을 설정합니다.")
            context_id = scanner.setup_authentication(target_url, login_config)
            
        results = scanner.run_scan(target_url, context_id=context_id)
        logger.info(f"ZAP 스캔 작업 완료. 발견된 취약점 개수: {results.get('total_alerts', 0)}")
        return {"status": "completed", "target": target_url, "results": results}
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
