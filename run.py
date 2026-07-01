import uvicorn

if __name__ == "__main__":
    # FastAPI 백엔드를 기본적으로 8085 포트로 실행하는 진입점 스크립트
    uvicorn.run("argus.api.main:app", host="0.0.0.0", port=8085, reload=True)
