"""Активы и группы активов (BR-2, BR-4)."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, conflict, not_found
from app.models.asset import Asset
from app.models.asset_group import AssetGroup
from app.models.enums import CLOSED_STATUSES, Role, Severity
from app.models.finding import Finding
from app.models.user import User
from app.schemas.asset import AssetCreate, AssetUpdate
from app.schemas.asset_group import AssetGroupCreate
from app.services import findings as findings_service

# Поля, которые владелец актива изменять не вправе.
OWNER_EDITABLE_FIELDS = {"description"}
# Поля, которым допустимо присвоить null.
NULLABLE_FIELDS = {"hostname", "ip_address", "description"}


def _reference_error(field: str, message: str) -> AppError:
    return AppError(422, "REFERENCE_NOT_FOUND", message, {"field": field})


def ensure_group(db: Session, group_id: int) -> AssetGroup:
    group = db.get(AssetGroup, group_id)
    if group is None:
        raise _reference_error("group_id", "Группа активов не найдена")
    return group


def ensure_owner(db: Session, owner_id: int) -> User:
    owner = db.get(User, owner_id)
    if owner is None or not owner.is_active:
        raise _reference_error("owner_id", "Владелец не найден или заблокирован")
    return owner


def _ensure_hostname_free(
    db: Session, group_id: int, hostname: str | None, exclude_id: int | None = None
) -> None:
    if hostname is None:
        return
    stmt = select(Asset.id).where(Asset.group_id == group_id, Asset.hostname == hostname)
    if exclude_id is not None:
        stmt = stmt.where(Asset.id != exclude_id)
    if db.scalars(stmt).first() is not None:
        raise conflict("ASSET_HOSTNAME_TAKEN", "В этой группе уже есть актив с таким hostname")


def create_group(db: Session, data: AssetGroupCreate) -> AssetGroup:
    if db.scalars(select(AssetGroup).where(AssetGroup.name == data.name)).first():
        raise conflict("ASSET_GROUP_NAME_TAKEN", "Группа с таким названием уже существует")
    if db.scalars(select(AssetGroup).where(AssetGroup.code == data.code)).first():
        raise conflict("ASSET_GROUP_CODE_TAKEN", "Группа с таким кодом уже существует")
    group = AssetGroup(name=data.name, code=data.code)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group


def delete_group(db: Session, group: AssetGroup) -> None:
    has_assets = db.scalars(select(Asset.id).where(Asset.group_id == group.id)).first()
    if has_assets is not None:
        raise conflict("ASSET_GROUP_NOT_EMPTY", "В группе есть активы, удаление невозможно")
    db.delete(group)
    db.commit()


def create_asset(db: Session, data: AssetCreate) -> Asset:
    ensure_group(db, data.group_id)
    ensure_owner(db, data.owner_id)
    _ensure_hostname_free(db, data.group_id, data.hostname)
    asset = Asset(**data.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def update_asset(db: Session, asset: Asset, user: User, data: AssetUpdate) -> Asset:
    """Администратор и аналитик меняют любые поля, владелец — только описание."""
    changes = {
        field: value
        for field, value in data.model_dump(exclude_unset=True).items()
        if value is not None or field in NULLABLE_FIELDS
    }

    if user.role == Role.owner:
        forbidden = [
            field
            for field, value in changes.items()
            if field not in OWNER_EDITABLE_FIELDS and getattr(asset, field) != value
        ]
        if forbidden:
            raise AppError(
                403,
                "AUTHZ_FIELD_FORBIDDEN",
                "Владелец может изменять только описание актива",
                {"fields": forbidden},
            )

    if "group_id" in changes:
        ensure_group(db, changes["group_id"])
    if "owner_id" in changes:
        ensure_owner(db, changes["owner_id"])
    new_group = changes.get("group_id", asset.group_id)
    new_hostname = changes.get("hostname", asset.hostname)
    if "group_id" in changes or "hostname" in changes:
        _ensure_hostname_free(db, new_group, new_hostname, exclude_id=asset.id)

    criticality_changed = "criticality" in changes and changes["criticality"] != asset.criticality
    for field, value in changes.items():
        setattr(asset, field, value)
    if criticality_changed:
        findings_service.recalculate_for_asset(db, asset)
    db.commit()
    db.refresh(asset)
    return asset


def delete_asset(db: Session, asset: Asset) -> None:
    """Логическое удаление: актив остаётся в БД, его обнаружения закрываются."""
    asset.is_active = False
    findings_service.close_asset_findings(db, asset)
    db.commit()


def findings_summary(db: Session, asset_id: int) -> dict[str, int]:
    """Открытые обнаружения актива по уровням риска (все уровни присутствуют в ответе)."""
    summary = {level.value: 0 for level in Severity}
    rows = db.execute(
        select(Finding.risk_level, func.count())
        .where(Finding.asset_id == asset_id, Finding.status.not_in(CLOSED_STATUSES))
        .group_by(Finding.risk_level)
    )
    for level, count in rows:
        summary[level.value] = count
    return summary


def group_not_found() -> AppError:
    return not_found("ASSET_GROUP_NOT_FOUND", "Группа активов не найдена")
