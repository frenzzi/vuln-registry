from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.core.deps import AdminUser, DbSession, Pagination
from app.core.exceptions import not_found
from app.models.enums import Role
from app.models.user import User
from app.schemas.common import Page
from app.schemas.user import UserOut, UserUpdate
from app.services import users as users_service
from app.services.queries import contains, paginate

router = APIRouter(tags=["users"])


@router.get("", response_model=Page[UserOut], summary="Список пользователей")
def list_users(
    _admin: AdminUser,
    db: DbSession,
    page: Pagination,
    role: Role | None = None,
    is_active: bool | None = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Поиск по логину, почте, имени")
    ] = None,
) -> Page[UserOut]:
    """Список пользователей с фильтрами. Только администратор."""
    stmt = select(User).order_by(User.id)
    if role is not None:
        stmt = stmt.where(User.role == role)
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)
    if q:
        stmt = stmt.where(
            contains(User.username, q) | contains(User.email, q) | contains(User.full_name, q)
        )
    items, total = paginate(db, stmt, page)
    return Page(
        items=[UserOut.model_validate(u) for u in items],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{user_id}", response_model=UserOut, summary="Профиль пользователя")
def get_user(user_id: int, _admin: AdminUser, db: DbSession) -> UserOut:
    """Профиль пользователя по идентификатору. Только администратор."""
    user = db.get(User, user_id)
    if user is None:
        raise not_found("USER_NOT_FOUND", "Пользователь не найден")
    return UserOut.model_validate(user)


@router.patch("/{user_id}", response_model=UserOut, summary="Изменение пользователя")
def update_user(user_id: int, data: UserUpdate, admin: AdminUser, db: DbSession) -> UserOut:
    """Изменение роли, блокировки и имени. Только администратор.

    Администратор не может изменить собственную роль или заблокировать себя (409).
    """
    user = db.get(User, user_id)
    if user is None:
        raise not_found("USER_NOT_FOUND", "Пользователь не найден")
    return UserOut.model_validate(users_service.update_user(db, user, admin, data))
