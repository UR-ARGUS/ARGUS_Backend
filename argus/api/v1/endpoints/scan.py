from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
from celery.result import AsyncResult
from argus.worker.tasks import run_scan_task
from argus.core.celery_app import celery_app

router = APIRouter()

class LoginConfigSchema(BaseModel):
    login_url: str = Field(..., description="로그인 페이지 URL")
    username_field: str = Field("username", description="로그인 ID input name 태그")
    password_field: str = Field("password", description="로그인 PW input name 태그")
    username: str = Field(..., description="사용자 아이디")
    password: str = Field(..., description="사용자 비밀번호")
    logged_in_indicator: Optional[str] = Field("Logout", description="로그인 성공 식별 문자열")

class ScanRequestSchema(BaseModel):
    # HttpUrl로 검증하지 않으면 "John Doe" 같은 값도 그대로 ZAP까지 흘러들어가 내부에서
    # 조용히 실패하고 total_alerts=0인 "성공" 응답을 돌려줘서 사용자를 혼란스럽게 만든다.
    target_url: HttpUrl = Field(..., description="진단 대상 URL (http/https 절대 URL)")
    login_config: Optional[LoginConfigSchema] = Field(None, description="자동 로그인 설정")
    custom_header: Optional[str] = Field(None, description="직접 주입할 쿠키/헤더 값 (예: Cookie: session=123)")
    api_base_url: Optional[HttpUrl] = Field(
        None,
        description="백엔드 API 서버 URL (예: http://localhost:8080). target_url이 프론트엔드 SPA일 때 "
                    "이 값을 함께 주면 해당 origin에서 OpenAPI/Swagger 스펙을 가져와 실제 API 파라미터 "
                    "기준으로 진단한다. SPA 크롤링만으로는 결제금액/권한/ID/상태값 같은 실제 비즈니스 "
                    "파라미터를 거의 발견할 수 없기 때문."
    )

@router.post("/")
def trigger_scan(payload: ScanRequestSchema):
    # Celery 비동기 작업으로 ZAP 스캔 트리거
    task = run_scan_task.delay(
        target_url=str(payload.target_url),
        login_config=payload.login_config.model_dump() if payload.login_config else None,
        custom_header=payload.custom_header,
        api_base_url=str(payload.api_base_url) if payload.api_base_url else None
    )
    return {"message": "Scan triggered successfully", "task_id": task.id}

@router.get("/{task_id}")
def get_scan_result(task_id: str):
    # 프론트엔드가 task_id로 스캔 진행 상태/결과를 조회하기 위한 엔드포인트
    task = AsyncResult(task_id, app=celery_app)
    response = {"task_id": task_id, "state": task.state}
    if task.state == "SUCCESS":
        response["result"] = task.result
    elif task.state == "FAILURE":
        response["error"] = str(task.result)
    elif task.state == "PROGRESS":
        response["progress"] = task.info
    return response
