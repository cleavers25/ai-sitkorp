import base64
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AI Infra & Website Security Assistant"
    environment: str = "development"

    database_url: str = "postgresql+psycopg://aiinfra:aiinfra@localhost:5432/aiinfra"
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    cookie_name: str = "aiinfra_session"
    cookie_secure: bool = False
    login_max_attempts: int = 5
    login_lockout_minutes: int = 15

    # Base64-encoded 32-byte key used by the local AES-GCM secret backend.
    secret_master_key: str

    # Only honour X-Forwarded-For when running behind our own reverse proxy.
    trust_proxy_headers: bool = False
    cors_origins: list[str] = []

    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None

    ssh_connect_timeout: int = 15
    ssh_command_timeout: int = 30
    ssh_max_output_bytes: int = 65536

    celery_task_always_eager: bool = False

    # Public URL of this app, used for links inside notifications (e.g. https://aiinfra.corp.local).
    app_base_url: str | None = None

    # Website backups (PRD 13): stored on this server's disk (docker volume mounted at /backups).
    backup_dir: str = "/backups"
    backup_retention: int = 7  # successful backups kept per website
    backup_max_bytes: int = 20 * 1024**3
    backup_timeout: int = 3 * 3600

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_secret_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return v

    @field_validator("secret_master_key")
    @classmethod
    def _master_key_length(cls, v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("SECRET_MASTER_KEY must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("SECRET_MASTER_KEY must decode to exactly 32 bytes")
        return v

    @property
    def master_key_bytes(self) -> bytes:
        return base64.b64decode(self.secret_master_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
