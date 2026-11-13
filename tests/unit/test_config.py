import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_secret_key_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_SECRET_KEY")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_short_secret_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_SECRET_KEY", "too-short")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_secret_key_has_no_default_and_defaults_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_SECRET_KEY", "x" * 32)
    monkeypatch.delenv("APP_DEBUG")
    monkeypatch.delenv("APP_TOKEN_TTL_MINUTES")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.debug is False
    assert settings.token_ttl_minutes == 60
    assert settings.host == "127.0.0.1"
