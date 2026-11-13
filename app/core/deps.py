from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, Query
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import API_PREFIX
from app.core.exceptions import forbidden_role, not_found
from app.core.security import decode_access_token, invalid_token
from app.db import session as db_session
from app.models.asset import Asset
from app.models.enums import Role
from app.models.finding import Finding
from app.models.user import User
from app.services.queries import PageParams

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{API_PREFIX}/auth/login", auto_error=False)


def get_db() -> Iterator[Session]:
    db = db_session.SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(db: DbSession, token: Annotated[str | None, Depends(oauth2_scheme)]) -> User:
    """Аутентификация: токен → пользователь. Активность проверяется при каждом запросе."""
    if not token:
        raise invalid_token()
    payload = decode_access_token(token)
    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise invalid_token() from exc
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise invalid_token()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: Role) -> Callable[[User], User]:
    """Ролевой уровень авторизации. Роль берётся из БД, а не из токена, чтобы
    понижение роли действовало сразу, а не после истечения токена."""

    def checker(user: CurrentUser) -> User:
        if user.role not in roles:
            raise forbidden_role()
        return user

    return checker


AdminUser = Annotated[User, Depends(require_roles(Role.admin))]
StaffUser = Annotated[User, Depends(require_roles(Role.admin, Role.analyst))]


def can_access_asset(user: User, asset: Asset) -> bool:
    """Объектный уровень: owner видит только свои активы, admin и analyst — все."""
    return user.role != Role.owner or asset.owner_id == user.id


def require_asset_access(asset_id: int, db: DbSession, user: CurrentUser) -> Asset:
    """Возвращает актив или 404. Чужой актив неотличим от несуществующего."""
    asset = db.get(Asset, asset_id)
    if asset is None or not can_access_asset(user, asset):
        raise not_found("ASSET_NOT_FOUND", "Актив не найден")
    return asset


AccessibleAsset = Annotated[Asset, Depends(require_asset_access)]


def require_finding_access(finding_id: int, db: DbSession, user: CurrentUser) -> Finding:
    """То же каскадно для обнаружений: доступ определяется владельцем актива."""
    finding = db.get(Finding, finding_id)
    if finding is None or not can_access_asset(user, finding.asset):
        raise not_found("FINDING_NOT_FOUND", "Обнаружение не найдено")
    return finding


AccessibleFinding = Annotated[Finding, Depends(require_finding_access)]


def get_page_params(
    limit: Annotated[int, Query(ge=1, le=100, description="Размер страницы")] = 20,
    offset: Annotated[int, Query(ge=0, description="Смещение")] = 0,
) -> PageParams:
    return PageParams(limit=limit, offset=offset)


Pagination = Annotated[PageParams, Depends(get_page_params)]
