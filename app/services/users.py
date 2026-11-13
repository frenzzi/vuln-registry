"""Регистрация, вход, смена пароля и администрирование пользователей (BR-1, BR-2)."""

from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, conflict
from app.core.security import hash_password, verify_password
from app.models.enums import Role
from app.models.user import User
from app.schemas.user import UserRegister, UserUpdate
from app.services.passwords import ensure_password_policy


@lru_cache
def _dummy_hash() -> str:
    """Хеш несуществующего пароля: проверяется при неизвестном логине, чтобы время ответа
    не выдавало, существует ли пользователь."""
    return hash_password("dummy-password-for-timing")


def create_user(
    db: Session,
    *,
    username: str,
    email: str,
    full_name: str,
    password: str,
    role: Role = Role.owner,
) -> User:
    ensure_password_policy(password, username)
    email = email.lower()
    if db.scalars(select(User).where(User.username == username)).first():
        raise conflict("USER_USERNAME_TAKEN", "Имя пользователя уже занято")
    if db.scalars(select(User).where(User.email == email)).first():
        raise conflict("USER_EMAIL_TAKEN", "Адрес электронной почты уже занят")
    user = User(
        username=username,
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def register(db: Session, data: UserRegister) -> User:
    """Самостоятельная регистрация: роль всегда owner, повысить может только администратор."""
    return create_user(
        db,
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        password=data.password,
        role=Role.owner,
    )


def authenticate(db: Session, username: str, password: str) -> User:
    """Проверяет логин и пароль. Для неверного пароля и неизвестного логина ответ одинаков."""
    user = db.scalars(select(User).where(User.username == username)).first()
    if user is None:
        verify_password(password, _dummy_hash())
        raise _invalid_credentials()
    if not verify_password(password, user.hashed_password):
        raise _invalid_credentials()
    if not user.is_active:
        raise AppError(403, "AUTH_USER_INACTIVE", "Учётная запись заблокирована")
    return user


def _invalid_credentials() -> AppError:
    return AppError(
        401,
        "AUTH_INVALID_CREDENTIALS",
        "Неверное имя пользователя или пароль",
        headers={"WWW-Authenticate": "Bearer"},
    )


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    if not verify_password(current_password, user.hashed_password):
        raise AppError(400, "AUTH_WRONG_CURRENT_PASSWORD", "Текущий пароль указан неверно")
    ensure_password_policy(new_password, user.username)
    user.hashed_password = hash_password(new_password)
    db.commit()


def update_user(db: Session, target: User, actor: User, data: UserUpdate) -> User:
    """Изменение роли, блокировки и имени. Администратор не может менять роль и
    активность самого себя, иначе система может остаться без администратора."""
    changes = data.model_dump(exclude_unset=True, exclude_none=True)
    if target.id == actor.id:
        for field in ("role", "is_active"):
            if field in changes and changes[field] != getattr(target, field):
                raise conflict(
                    "USER_SELF_MODIFICATION_FORBIDDEN",
                    "Нельзя изменить собственную роль или заблокировать себя",
                )
    for field, value in changes.items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    return target
