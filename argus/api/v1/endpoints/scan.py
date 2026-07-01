from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
from argus.worker.tasks import run_scan_task

router = APIRouter()

class LoginConfigSchema(BaseModel):
    login_url: str = Field(..., description="로그인 페이지 URL")
    username_field: str = Field("username", description="로그인 ID input name 태그")
    password_field: str = Field("password", description="로그인 PW input name 태그")
    username: str = Field(..., description="사용자 아이디")
    password: str = Field(..., description="사용자 비밀번호")
    logged_in_indicator: Optional[str] = Field("Logout", description="로그인 성공 식별 문자열")

class ScanRequestSchema(BaseModel):
    target_url: str = Field(..., description="진단 대상 URL")
    login_config: Optional[LoginConfigSchema] = Field(None, description="자동 로그인 설정")

@router.post("/")
def trigger_scan(payload: ScanRequestSchema):
    # Celery 비동기 작업으로 ZAP 스캔 트리거
    task = run_scan_task.delay(
        target_url=payload.target_url,
        login_config=payload.login_config.model_dump() if payload.login_config else None
    )
    return {"message": "Scan triggered successfully", "task_id": task.id}
