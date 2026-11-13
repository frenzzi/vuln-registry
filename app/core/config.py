from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

API_PREFIX = "/api/v1"
MIN_SECRET_KEY_BYTES = 32


class Settings(BaseSettings):
    """Параметры приложения. Читаются из переменных окружения с префиксом APP_ и из .env."""

    model_config = SettingsConfigDict(
        env_prefix="APP_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # Значения по умолчанию нет намеренно: без ключа приложение не стартует.
    secret_key: str
    token_ttl_minutes: int = Field(default=60, ge=1)
    database_url: str = "sqlite:///./vuln_registry.db"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    bcrypt_rounds: int = Field(default=12, ge=4, le=15)

    seed_admin_password: str | None = Field(default=None, validation_alias="SEED_ADMIN_PASSWORD")
    seed_analyst_password: str | None = Field(
        default=None, validation_alias="SEED_ANALYST_PASSWORD"
    )
    seed_owner1_password: str | None = Field(default=None, validation_alias="SEED_OWNER1_PASSWORD")
    seed_owner2_password: str | None = Field(default=None, validation_alias="SEED_OWNER2_PASSWORD")

    @field_validator("secret_key")
    @classmethod
    def _secret_key_long_enough(cls, value: str) -> str:
        if len(value.encode("utf-8")) < MIN_SECRET_KEY_BYTES:
            raise ValueError(f"APP_SECRET_KEY должен быть не короче {MIN_SECRET_KEY_BYTES} байт")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
