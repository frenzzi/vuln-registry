import base64
import hashlib
from datetime import timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import get_settings
from app.core.exceptions import AppError
from app.core.time import utcnow

ALGORITHM = "HS256"


def _prehash(password: str) -> bytes:
    # bcrypt учитывает только первые 72 байта и не принимает NUL, а пароль может быть
    # длиной до 128 символов (в UTF-8 больше 72 байт). SHA-256 + base64 даёт 44 байта.
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    rounds = get_settings().bcrypt_rounds
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode("ascii"))
    except ValueError:
        return False


def invalid_token() -> AppError:
    return AppError(
        401,
        "AUTH_INVALID_TOKEN",
        "Токен отсутствует, просрочен или недействителен",
        headers={"WWW-Authenticate": "Bearer"},
    )


def create_access_token(user_id: int, username: str, role: str) -> tuple[str, int]:
    """Выпускает JWT. Возвращает токен и время жизни в секундах."""
    settings = get_settings()
    now = utcnow()
    ttl = timedelta(minutes=settings.token_ttl_minutes)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + ttl,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)
    return token, int(ttl.total_seconds())


def decode_access_token(token: str) -> dict[str, Any]:
    """Разбирает JWT. Алгоритм задаётся явно, из заголовка токена он не берётся."""
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            get_settings().secret_key,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.PyJWTError as exc:
        raise invalid_token() from exc
    return payload
