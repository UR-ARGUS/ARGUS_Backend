from fastapi import FastAPI

app = FastAPI(
    title="Argus API",
    description="AI 기반 통합 보안 자동 진단 시스템 API",
    version="0.1.0"
)

@app.get("/")
def read_root():
    return {"message": "Welcome to Argus Security Platform API"}
