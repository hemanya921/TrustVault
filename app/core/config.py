from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    secret_key: str = "CHANGE-ME-TO-A-LONG-RANDOM-SECRET"
    database_url: str = "sqlite:///./trustvault.db"
    storage_dir: str = "./private_storage"
    max_upload_bytes: int = 20_000_000
    class Config: env_file = ".env"
settings = Settings()
