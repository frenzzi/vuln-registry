import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def _b64(data: dict[str, object]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_hash_differs_from_password_and_verifies() -> None:
    hashed = hash_password("Str0ngPass2026")
    assert hashed != "Str0ngPass2026"
    assert hashed.startswith("$2")
    assert verify_password("Str0ngPass2026", hashed)


def test_wrong_password_is_rejected() -> None:
    hashed = hash_password("Str0ngPass2026")
    assert not verify_password("str0ngpass2026", hashed)
    assert not verify_password("", hashed)


def test_long_and_unusual_passwords_are_supported() -> None:
    long_password = "Ж" * 128  # 256 байт в UTF-8, больше лимита bcrypt в 72 байта
    hashed = hash_password(long_password)
    assert verify_password(long_password, hashed)
    assert not verify_password("Ж" * 127, hashed)
    assert verify_password("pass\x00word", hash_password("pass\x00word"))


def test_jwt_roundtrip_has_expected_claims() -> None:
    token, expires_in = create_access_token(7, "analyst", "analyst")
    payload = decode_access_token(token)
    assert payload["sub"] == "7"
    assert payload["username"] == "analyst"
    assert payload["role"] == "analyst"
    assert payload["exp"] - payload["iat"] == expires_in == 3600


def test_expired_token_is_rejected() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": "1", "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)},
        get_settings().secret_key,
        algorithm="HS256",
    )
    with pytest.raises(AppError) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.code == "AUTH_INVALID_TOKEN"


def test_wrong_signature_is_rejected() -> None:
    now = datetime.now(UTC)
    forged = jwt.encode(
        {"sub": "1", "iat": now, "exp": now + timedelta(hours=1)},
        "another-secret-key-0123456789abcdef0123",
        algorithm="HS256",
    )
    with pytest.raises(AppError):
        decode_access_token(forged)

    genuine, _ = create_access_token(1, "admin", "admin")
    with pytest.raises(AppError):
        decode_access_token(genuine[:-2] + ("AA" if not genuine.endswith("AA") else "BB"))


def test_alg_none_is_rejected() -> None:
    exp = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    payload = {"sub": "1", "username": "admin", "role": "admin", "iat": exp - 3600, "exp": exp}
    unsigned = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(payload)}."
    with pytest.raises(AppError) as exc_info:
        decode_access_token(unsigned)
    assert exc_info.value.code == "AUTH_INVALID_TOKEN"


@pytest.mark.filterwarnings("ignore:The HMAC key is")
def test_other_hmac_algorithm_is_rejected() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": "1", "iat": now, "exp": now + timedelta(hours=1)},
        get_settings().secret_key,
        algorithm="HS512",
    )
    with pytest.raises(AppError):
        decode_access_token(token)


def test_token_without_required_claims_is_rejected() -> None:
    token = jwt.encode({"sub": "1"}, get_settings().secret_key, algorithm="HS256")
    with pytest.raises(AppError):
        decode_access_token(token)
