from argus.core.celery_app import celery_app
from argus.core.config import settings
from scanners.param_manipulation.engine import run_scan
from dataclasses import asdict
import json
import logging
import os

logger = logging.getLogger("argus.tasks")

def save_scan_result_json(task_id: str, findings: list) -> str:
    # capture_pipeline 등에서 읽을 수 있도록 dict 리스트 형태로 변환하여 저장.
    # findings는 Phase 4가 검토한 전체 항목(is_vulnerable=False 포함)이다 — LLM이
    # 왜 특정 항목을 취약점이 아니라고 판단했는지 파일에서 그대로 확인 가능하도록
    # 여기서 걸러내지 않는다.
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"{task_id}.json")
    findings_dict = [asdict(f) for f in findings]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings_dict, f, ensure_ascii=False, indent=2)
    return path

@celery_app.task(bind=True)
def run_scan_task(
    self,
    target_url: str,
    login_config: dict = None,
    custom_header: str = None,
    api_base_url: str = None,
    max_wait_seconds: int = 120,
):
    logger.info(f"파라미터 조작 스캔 작업 시작: {target_url}")
    try:
        # 만약 api_base_url이 제공되었다면 OpenAPI/Swagger Spec JSON을 가져오기 위한 스키마 주소로 변조
        # 예: http://localhost:8000 -> http://localhost:8000/openapi.json
        scan_target = target_url
        if api_base_url:
            # Swagger 자동 탐지 플래그를 붙여서 수집기로 포워딩
            scan_target = f"{api_base_url.rstrip('/')}?swagger_scan=true"
            logger.info(f"api_base_url이 주어졌으므로 Swagger Spec 스캔 모드로 전환합니다: {scan_target}")

        def report_progress(phase: str, percent: int):
            self.update_state(state="PROGRESS", meta={"phase": phase, "percent": percent})

        # ZAP API 및 LLM(Ollama/Claude) 파이프라인 통합 스캔 호출
        findings = run_scan(
            scan_target,
            max_wait_seconds=max_wait_seconds,
            login_config=login_config,
            custom_header=custom_header,
            progress_callback=report_progress,
        )
        
        result_json_path = save_scan_result_json(self.request.id, findings)
        confirmed = [f for f in findings if f.is_vulnerable]
        logger.info(
            f"스캔 작업 완료. 검토 {len(findings)}건 중 확정 취약점 {len(confirmed)}건 "
            f"(결과 JSON: {result_json_path})"
        )
        return {
            "status": "completed",
            "target": target_url,
            "results": {
                "total_alerts": len(confirmed),
                "findings": [asdict(f) for f in confirmed],
                "reviewed_total": len(findings),
            },
            "result_json_path": result_json_path
        }
    except Exception as e:
        logger.error(f"스캔 작업 실패: {e}")
        return {"status": "failed", "error": str(e), "target": target_url}

@celery_app.task
def run_capture_task(target_url: str):
    # Placeholder for Selenium capture replay
    return {"status": "completed", "target": target_url}

@celery_app.task
def generate_report_task(target_url: str):
    # Placeholder for reaching cross-validation & PDF generation
    return {"status": "completed", "target": target_url}
