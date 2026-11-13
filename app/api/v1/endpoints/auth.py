from typing import Annotated

from fastapi import APIRouter, Depends, Response
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import API_PREFIX
from app.core.deps import CurrentUser, DbSession
from app.core.security import create_access_token
from app.schemas.auth import ChangePasswordRequest, TokenResponse
from app.schemas.common import Message
from app.schemas.user import UserOut, UserRegister
from app.services import users as users_service

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=201, summary="Регистрация")
def register(data: UserRegister, db: DbSession, response: Response) -> UserOut:
    """Самостоятельная регистрация. Роль всегда `owner`: повысить её может только администратор.

    Пароль должен соответствовать политике: 10–128 символов, строчная и прописная буквы,
    цифра, не совпадает с именем пользователя.
    """
    user = users_service.register(db, data)
    response.headers["Location"] = f"{API_PREFIX}/users/{user.id}"
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenResponse, summary="Вход")
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: DbSession) -> TokenResponse:
    """Вход по логину и паролю (форма `application/x-www-form-urlencoded`, OAuth2 Password Flow).

    Выдаёт JWT (HS256) со сроком жизни по настройке. На неверный пароль и несуществующего
    пользователя возвращается один и тот же ответ.
    """
    user = users_service.authenticate(db, form.username, form.password)
    token, expires_in = create_access_token(user.id, user.username, user.role.value)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.get("/me", response_model=UserOut, summary="Профиль текущего пользователя")
def me(user: CurrentUser) -> UserOut:
    """Возвращает профиль пользователя, которому принадлежит токен."""
    return UserOut.model_validate(user)


@router.post("/change-password", response_model=Message, summary="Смена пароля")
def change_password(data: ChangePasswordRequest, db: DbSession, user: CurrentUser) -> Message:
    """Меняет пароль. Требует текущий пароль; неверный текущий пароль — 400."""
    users_service.change_password(db, user, data.current_password, data.new_password)
    return Message(message="Пароль изменён")
