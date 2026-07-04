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

def save_scan_coverage_json(task_id: str, coverage: list) -> str:
    # findings 파일은 이상 신호가 잡힌 항목만 담고 있어서, 그것만 보고는
    # "테스트했지만 이상없음"과 "애초에 수집조차 안 됨"(예: 크롤러가 예약 생성
    # POST 같은 다단계 플로우를 못 찾은 경우)을 구분할 수 없었다. Phase 2~3에서
    # 실제로 시도된 전체 후보 파라미터 목록(이상 유무 무관)을 별도 파일로 남겨
    # 이 구분이 가능하게 한다. 기존 결과 파일(findings)의 형식/소비자에는
    # 영향을 주지 않도록 사이드카 파일로 분리한다.
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"{task_id}_coverage.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(coverage, f, ensure_ascii=False, indent=2)
    return path

def save_scan_attempts_json(task_id: str, attempts: list) -> str:
    # coverage 파일은 "시도는 됐다"까지만 알려줘서, 서버가 400/404로 거절해 애초에
    # 비교 자체가 성립 안 한 경우("탐지 로직이 놓침")와 서버가 정상적으로 거절해서
    # 진짜 이상이 없는 경우("정상 동작")를 구분할 수 없었다. Phase 3에서 실제로
    # 전송한 (파라미터, 페이로드) 조합마다 baseline/test 상태 코드와 anomaly_type
    # 여부까지 남겨, 다음에 같은 의문이 들 때 celery 로그를 뒤지지 않고 이 파일만
    # 보면 바로 원인을 구분할 수 있게 한다.
    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    path = os.path.join(settings.SCAN_RESULTS_DIR, f"{task_id}_attempts.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(attempts, f, ensure_ascii=False, indent=2)
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
        if api_base_url:
            logger.info(f"api_base_url이 주어졌으므로 Swagger Spec + ZAP 크롤링을 병행합니다: {api_base_url}")

        def report_progress(phase: str, percent: int):
            self.update_state(state="PROGRESS", meta={"phase": phase, "percent": percent})

        coverage_holder: list = []
        attempts_holder: list = []

        def report_coverage(candidate_params: list):
            coverage_holder.extend(candidate_params)

        def report_attempt(entry: dict):
            attempts_holder.append(entry)

        # ZAP API 및 LLM(Ollama/Claude) 파이프라인 통합 스캔 호출
        findings = run_scan(
            target_url,
            max_wait_seconds=max_wait_seconds,
            login_config=login_config,
            custom_header=custom_header,
            progress_callback=report_progress,
            api_base_url=api_base_url,
            coverage_callback=report_coverage,
            attempt_callback=report_attempt,
        )

        result_json_path = save_scan_result_json(self.request.id, findings)
        coverage_json_path = save_scan_coverage_json(self.request.id, coverage_holder)
        attempts_json_path = save_scan_attempts_json(self.request.id, attempts_holder)
        confirmed = [f for f in findings if f.is_vulnerable]
        logger.info(
            f"스캔 작업 완료. 검토 {len(findings)}건 중 확정 취약점 {len(confirmed)}건 "
            f"(결과 JSON: {result_json_path}, 커버리지({len(coverage_holder)}건): {coverage_json_path}, "
            f"페이로드 시도 로그({len(attempts_holder)}건): {attempts_json_path})"
        )
        return {
            "status": "completed",
            "target": target_url,
            "results": {
                "total_alerts": len(confirmed),
                "findings": [asdict(f) for f in confirmed],
                "reviewed_total": len(findings),
            },
            "result_json_path": result_json_path,
            "coverage_json_path": coverage_json_path,
            "attempts_json_path": attempts_json_path,
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
