from fastapi import APIRouter, Response
from sqlalchemy import func, select

from app.core.config import API_PREFIX
from app.core.deps import AdminUser, CurrentUser, DbSession, Pagination, StaffUser
from app.models.asset import Asset
from app.models.asset_group import AssetGroup
from app.models.enums import Role
from app.schemas.asset_group import AssetGroupCreate, AssetGroupOut
from app.schemas.common import Page
from app.services import assets as assets_service
from app.services.queries import paginate

router = APIRouter(tags=["asset-groups"])


@router.get("", response_model=Page[AssetGroupOut], summary="Список групп активов")
def list_groups(user: CurrentUser, db: DbSession, page: Pagination) -> Page[AssetGroupOut]:
    """Список групп с количеством активов. Владелец видит число только своих активов."""
    count_stmt = select(Asset.group_id, func.count().label("n")).group_by(Asset.group_id)
    if user.role == Role.owner:
        count_stmt = count_stmt.where(Asset.owner_id == user.id)
    counts = {group_id: n for group_id, n in db.execute(count_stmt)}

    groups, total = paginate(db, select(AssetGroup).order_by(AssetGroup.name), page)
    items = []
    for group in groups:
        out = AssetGroupOut.model_validate(group)
        out.assets_count = counts.get(group.id, 0)
        items.append(out)
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=AssetGroupOut, status_code=201, summary="Создание группы")
def create_group(
    data: AssetGroupCreate, _staff: StaffUser, db: DbSession, response: Response
) -> AssetGroupOut:
    """Создаёт группу активов. Администратор и аналитик. Дубль названия или кода — 409."""
    group = assets_service.create_group(db, data)
    response.headers["Location"] = f"{API_PREFIX}/asset-groups/{group.id}"
    return AssetGroupOut.model_validate(group)


@router.delete("/{group_id}", status_code=204, summary="Удаление группы")
def delete_group(group_id: int, _admin: AdminUser, db: DbSession) -> Response:
    """Удаляет группу. Только администратор. Если в группе есть активы — 409."""
    group = db.get(AssetGroup, group_id)
    if group is None:
        raise assets_service.group_not_found()
    assets_service.delete_group(db, group)
    return Response(status_code=204)
