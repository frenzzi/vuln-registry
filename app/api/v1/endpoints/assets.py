from typing import Annotated

from fastapi import APIRouter, Query, Response
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.core.config import API_PREFIX
from app.core.deps import (
    AccessibleAsset,
    AdminUser,
    CurrentUser,
    DbSession,
    Pagination,
    StaffUser,
)
from app.models.asset import Asset
from app.models.enums import AssetType, Criticality, Role
from app.schemas.asset import AssetCreate, AssetDetail, AssetOut, AssetUpdate
from app.schemas.common import Page
from app.services import assets as assets_service
from app.services.queries import apply_sort, contains, paginate

router = APIRouter(tags=["assets"])

_CRITICALITY_RANK = case(
    {
        Criticality.low.value: 1,
        Criticality.medium.value: 2,
        Criticality.high.value: 3,
        Criticality.critical.value: 4,
    },
    value=Asset.criticality,
)
SORT_FIELDS = {
    "name": Asset.name,
    "criticality": _CRITICALITY_RANK,
    "created_at": Asset.created_at,
}


def _detail(db: Session, asset: Asset) -> AssetDetail:
    base = AssetOut.model_validate(asset).model_dump()
    return AssetDetail(
        **base,
        group_name=asset.group.name,
        group_code=asset.group.code,
        findings_by_risk_level=assets_service.findings_summary(db, asset.id),
    )


@router.get("", response_model=Page[AssetOut], summary="Список активов")
def list_assets(
    user: CurrentUser,
    db: DbSession,
    page: Pagination,
    group_id: int | None = None,
    asset_type: AssetType | None = None,
    criticality: Criticality | None = None,
    owner_id: int | None = None,
    is_active: bool | None = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Поиск по названию, hostname")
    ] = None,
    sort: Annotated[
        str | None,
        Query(max_length=32, description="name, criticality, created_at; «-» — убывание"),
    ] = None,
) -> Page[AssetOut]:
    """Список активов с фильтрами, сортировкой и пагинацией.

    Владелец видит только свои активы: список фильтруется, а не отвечает 403.
    """
    stmt = select(Asset)
    if user.role == Role.owner:
        stmt = stmt.where(Asset.owner_id == user.id)
    if group_id is not None:
        stmt = stmt.where(Asset.group_id == group_id)
    if asset_type is not None:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if criticality is not None:
        stmt = stmt.where(Asset.criticality == criticality)
    if owner_id is not None:
        stmt = stmt.where(Asset.owner_id == owner_id)
    if is_active is not None:
        stmt = stmt.where(Asset.is_active == is_active)
    if q:
        stmt = stmt.where(contains(Asset.name, q) | contains(Asset.hostname, q))
    stmt = apply_sort(stmt, sort, SORT_FIELDS, default="name", tiebreak=Asset.id)
    items, total = paginate(db, stmt, page)
    return Page(
        items=[AssetOut.model_validate(a) for a in items],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("", response_model=AssetOut, status_code=201, summary="Создание актива")
def create_asset(
    data: AssetCreate, _staff: StaffUser, db: DbSession, response: Response
) -> AssetOut:
    """Создаёт актив. Администратор и аналитик. Дубль пары (группа, hostname) — 409,
    несуществующая группа или владелец — 422."""
    asset = assets_service.create_asset(db, data)
    response.headers["Location"] = f"{API_PREFIX}/assets/{asset.id}"
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetDetail, summary="Карточка актива")
def get_asset(asset: AccessibleAsset, db: DbSession) -> AssetDetail:
    """Карточка актива со сводкой открытых обнаружений по уровням риска.

    Чужой актив для владельца неотличим от несуществующего: 404, а не 403.
    """
    return _detail(db, asset)


@router.patch("/{asset_id}", response_model=AssetDetail, summary="Изменение актива")
def update_asset(
    data: AssetUpdate, asset: AccessibleAsset, user: CurrentUser, db: DbSession
) -> AssetDetail:
    """Администратор и аналитик меняют любые поля, владелец — только описание своего актива
    (иначе 403 `AUTHZ_FIELD_FORBIDDEN`). Смена критичности пересчитывает риск и срок
    открытых обнаружений.
    """
    asset = assets_service.update_asset(db, asset, user, data)
    return _detail(db, asset)


@router.delete("/{asset_id}", status_code=204, summary="Удаление актива")
def delete_asset(asset: AccessibleAsset, _admin: AdminUser, db: DbSession) -> Response:
    """Логическое удаление: актив помечается неактивным, его обнаружения переводятся в `closed`.
    Только администратор."""
    assets_service.delete_asset(db, asset)
    return Response(status_code=204)
