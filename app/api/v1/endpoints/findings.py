from typing import Annotated

from fastapi import APIRouter, Query, Response
from sqlalchemy import select

from app.core.config import API_PREFIX
from app.core.deps import (
    AccessibleFinding,
    CurrentUser,
    DbSession,
    Pagination,
    StaffUser,
)
from app.core.exceptions import AppError, conflict, not_found
from app.core.time import utc_today
from app.models.asset import Asset
from app.models.enums import FindingStatus, Role, Severity
from app.models.finding import Finding
from app.models.vulnerability import Vulnerability
from app.schemas.common import Page
from app.schemas.finding import (
    FindingAssigneeChange,
    FindingCreate,
    FindingDetail,
    FindingImportError,
    FindingImportRequest,
    FindingImportResult,
    FindingOut,
    FindingStatusChange,
)
from app.services import findings as findings_service
from app.services import risk
from app.services.queries import apply_sort, paginate

router = APIRouter(tags=["findings"])

SORT_FIELDS = {
    "risk_score": Finding.risk_score,
    "due_date": Finding.due_date,
    "first_detected_at": Finding.first_detected_at,
}


@router.get("", response_model=Page[FindingOut], summary="Список обнаружений")
def list_findings(
    user: CurrentUser,
    db: DbSession,
    page: Pagination,
    status: FindingStatus | None = None,
    risk_level: Severity | None = None,
    asset_id: int | None = None,
    group_id: int | None = None,
    assignee_id: int | None = None,
    overdue: Annotated[
        bool | None, Query(description="Только просроченные / только непросроченные")
    ] = None,
    cve_id: Annotated[str | None, Query(max_length=20)] = None,
    sort: Annotated[
        str | None,
        Query(max_length=32, description="risk_score, due_date, first_detected_at; «-» — убывание"),
    ] = None,
) -> Page[FindingOut]:
    """Список обнаружений с фильтрами, сортировкой и пагинацией.

    Владелец видит только обнаружения по своим активам.
    """
    stmt = select(Finding).join(Asset, Finding.asset_id == Asset.id)
    if user.role == Role.owner:
        stmt = stmt.where(Asset.owner_id == user.id)
    if status is not None:
        stmt = stmt.where(Finding.status == status)
    if risk_level is not None:
        stmt = stmt.where(Finding.risk_level == risk_level)
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if group_id is not None:
        stmt = stmt.where(Asset.group_id == group_id)
    if assignee_id is not None:
        stmt = stmt.where(Finding.assignee_id == assignee_id)
    if cve_id:
        stmt = stmt.join(Vulnerability, Finding.vulnerability_id == Vulnerability.id).where(
            Vulnerability.cve_id == cve_id.upper()
        )
    if overdue is not None:
        is_overdue = (Finding.due_date < utc_today()) & Finding.status.not_in(
            risk.NOT_OVERDUE_STATUSES
        )
        stmt = stmt.where(is_overdue if overdue else ~is_overdue)
    stmt = apply_sort(stmt, sort, SORT_FIELDS, default="-first_detected_at", tiebreak=Finding.id)
    items, total = paginate(db, stmt, page)
    return Page(
        items=[FindingOut.model_validate(f) for f in items],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/import", response_model=FindingImportResult, summary="Импорт результатов сканера")
def import_findings(
    data: FindingImportRequest, _staff: StaffUser, db: DbSession
) -> FindingImportResult:
    """Массовая загрузка результатов внешнего сканера: список пар `{asset_id, cve_id}`.

    Дедупликация действует так же, как при создании одиночного обнаружения. Элементы с
    ошибкой (неизвестный CVE, актив) попадают в `errors`, остальные обрабатываются.
    """
    result = findings_service.import_detections(db, [(i.asset_id, i.cve_id) for i in data.items])
    return FindingImportResult(
        created=result.created,
        updated=result.updated,
        errors=[FindingImportError(**vars(e)) for e in result.errors],
    )


@router.post("", response_model=FindingOut, status_code=201, summary="Регистрация обнаружения")
def create_finding(
    data: FindingCreate, _staff: StaffUser, db: DbSession, response: Response
) -> FindingOut:
    """Регистрирует обнаружение с дедупликацией. Если по паре «актив + уязвимость» уже есть
    открытое обнаружение, новое не создаётся: растёт `detection_count`, обновляется
    `last_detected_at`, статус сохраняется (ответ 200 вместо 201).
    """
    asset = db.get(Asset, data.asset_id)
    if asset is None:
        raise AppError(422, "REFERENCE_NOT_FOUND", "Актив не найден", {"field": "asset_id"})
    if not asset.is_active:
        raise conflict("ASSET_INACTIVE", "Актив выведен из учёта")
    vulnerability = db.get(Vulnerability, data.vulnerability_id)
    if vulnerability is None:
        raise AppError(
            422, "REFERENCE_NOT_FOUND", "Запись каталога не найдена", {"field": "vulnerability_id"}
        )
    finding, created = findings_service.register_detection(db, asset, vulnerability)
    db.commit()
    db.refresh(finding)
    if created:
        response.headers["Location"] = f"{API_PREFIX}/findings/{finding.id}"
    else:
        response.status_code = 200
    return FindingOut.model_validate(finding)


@router.get("/{finding_id}", response_model=FindingDetail, summary="Карточка обнаружения")
def get_finding(finding: AccessibleFinding) -> FindingDetail:
    """Карточка обнаружения с активом, уязвимостью и признаком просрочки `is_overdue`.

    Чужое обнаружение для владельца — 404.
    """
    return FindingDetail.model_validate(finding)


@router.patch("/{finding_id}/status", response_model=FindingOut, summary="Смена статуса")
def change_status(
    data: FindingStatusChange, finding: AccessibleFinding, user: CurrentUser, db: DbSession
) -> FindingOut:
    """Единственный способ изменить статус обнаружения.

    Переход вне матрицы или в тот же статус — 409 `FINDING_INVALID_STATUS_TRANSITION` со
    списком допустимых в `details.allowed`. Переход в `fixed` требует `resolution_comment`
    не короче 10 символов. Переходы `confirmed`, `false_positive`, `closed` — только
    администратор и аналитик; `in_progress`, `fixed` — также владелец актива.
    """
    actor = findings_service.actor_for(user.role)
    updated = findings_service.change_status(
        db, finding, data.status, actor, data.resolution_comment
    )
    return FindingOut.model_validate(updated)


@router.patch("/{finding_id}/assignee", response_model=FindingOut, summary="Назначение исполнителя")
def change_assignee(
    finding_id: int, data: FindingAssigneeChange, _staff: StaffUser, db: DbSession
) -> FindingOut:
    """Назначает исполнителя или снимает его (`assignee_id: null`). Неактивный или
    несуществующий пользователь — 422. Администратор и аналитик."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise not_found("FINDING_NOT_FOUND", "Обнаружение не найдено")
    return FindingOut.model_validate(findings_service.assign(db, finding, data.assignee_id))
