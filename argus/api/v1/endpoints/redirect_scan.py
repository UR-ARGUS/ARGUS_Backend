"""
redirect_scan.py — 1-5(검증되지 않은 리다이렉트와 포워드, Reflected 전용) 진단 트리거 엔드포인트

scan.py(1-3)와 동일한 요청/조회 패턴을 따른다 — 프론트엔드가 이미 그 계약(POST로
트리거 → task_id 수령 → GET으로 폴링)에 맞춰 붙어 있으므로 그대로 재사용한다.
"""

from fastapi import APIRouter
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional
from celery.result import AsyncResult
from argus.worker.tasks import run_redirect_scan_task
from argus.core.celery_app import celery_app
from scanners.redirect_forward.payloads import DEFAULT_PAYLOAD_HOST

router = APIRouter()


class LoginConfigSchema(BaseModel):
    login_url: str = Field(..., description="로그인 페이지 URL")
    username_field: str = Field("username", description="로그인 ID input name 태그")
    password_field: str = Field("password", description="로그인 PW input name 태그")
    username: str = Field(..., description="사용자 아이디")
    password: str = Field(..., description="사용자 비밀번호")


class RedirectScanRequestSchema(BaseModel):
    target_url: HttpUrl = Field(..., description="진단 대상 URL (http/https 절대 URL)")
    login_config: Optional[LoginConfigSchema] = Field(None, description="자동 로그인 설정")
    custom_header: Optional[str] = Field(None, description="직접 주입할 쿠키/헤더 값 (예: Cookie: session=123)")
    api_base_url: Optional[HttpUrl] = Field(
        None,
        description="백엔드 API 서버 URL. 주어지면 Swagger Spec에서 리다이렉트/포워드 후보 "
                    "파라미터를 먼저 확보하고, target_url은 ZAP Ajax Spider로 별도 크롤링해 보완한다.",
    )
    payload_host: Optional[str] = Field(
        None,
        description=f"리다이렉트 목적지로 주입할 미검증 외부 호스트 (기본값: {DEFAULT_PAYLOAD_HOST}). "
                    "이 문자열이 대상 서비스의 실제 도메인과 겹치면 오탐이 발생하므로 필요 시 변경한다.",
    )
    max_wait_seconds: Optional[int] = Field(
        120,
        ge=10,
        le=600,
        description="ZAP Ajax Spider 크롤링 완료 대기 최대 시간(초). 기본값 120. "
                    "SPA 규모가 클수록 높게 설정한다 (최대 600).",
    )


@router.post("/")
def trigger_redirect_scan(payload: RedirectScanRequestSchema):
    task = run_redirect_scan_task.delay(
        target_url=str(payload.target_url),
        login_config=payload.login_config.model_dump() if payload.login_config else None,
        custom_header=payload.custom_header,
        api_base_url=str(payload.api_base_url) if payload.api_base_url else None,
        payload_host=payload.payload_host,
        max_wait_seconds=payload.max_wait_seconds,
    )
    return {"message": "1-5 Redirect/Forward(Reflected) scan triggered successfully", "task_id": task.id}


@router.get("/{task_id}")
def get_redirect_scan_result(task_id: str):
    task = AsyncResult(task_id, app=celery_app)
    response = {"task_id": task_id, "state": task.state}
    if task.state == "SUCCESS":
        response["result"] = task.result
    elif task.state == "FAILURE":
        response["error"] = str(task.result)
    elif task.state == "PROGRESS":
        response["progress"] = task.info
    return response
