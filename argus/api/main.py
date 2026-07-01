from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from argus.api.v1.api import api_router

app = FastAPI(
    title="Argus API",
    description="AI 기반 통합 보안 자동 진단 시스템 API",
    version="0.1.0"
)

# CORS 미들웨어 설정 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174", "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"message": "Welcome to Argus Security Platform API"}
