from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/argus"
    REDIS_URL: str = "redis://localhost:6379/0"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    # ZAP REST API 기본 포트: 8090 (ZAP 설정에서 포트를 바꿨다면 .env에서 덮어쓴다)
    ZAP_API_URL: str = "http://127.0.0.1:8090"
    ZAP_API_KEY: str = ""
    SCAN_RESULTS_DIR: str = "results"
    # Ollama 로컬 LLM (ANTHROPIC_API_KEY 미설정 시 자동 사용)
    # Ollama 설치: https://ollama.com  /  모델: ollama pull qwen2.5:7b
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"

    class Config:
        env_file = ".env"

settings = Settings()
