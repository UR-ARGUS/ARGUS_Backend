from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/argus"
    REDIS_URL: str = "redis://localhost:6379/0"
    OPENAI_API_KEY: str = ""
    ZAP_API_URL: str = "http://127.0.0.1:8080"
    ZAP_API_KEY: str = ""
    SCAN_RESULTS_DIR: str = "results"

    class Config:
        env_file = ".env"

settings = Settings()
