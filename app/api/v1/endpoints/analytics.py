from fastapi import APIRouter
from sqlalchemy import func, select

from app.core.deps import CurrentUser, DbSession
from app.core.time import utc_today
from app.models.asset import Asset
from app.models.enums import UNRESOLVED_STATUSES, FindingStatus, Role, Severity
from app.models.finding import Finding
from app.schemas.analytics import AnalyticsSummary
from app.schemas.finding import FindingOut

router = APIRouter(tags=["analytics"])


@router.get("/summary", response_model=AnalyticsSummary, summary="Сводка")
def summary(user: CurrentUser, db: DbSession) -> AnalyticsSummary:
    """Сводка для дашборда. Владелец видит агрегаты только по своим активам.

    `assets_total` — число активных активов. `findings_by_status` считает все
    обнаружения; `findings_by_risk_level`, `findings_overdue` и `top_risk_findings` — только
    неустранённые (`new`, `confirmed`, `in_progress`).
    """
    assets_stmt = select(func.count()).select_from(Asset).where(Asset.is_active.is_(True))
    findings_filter = []
    if user.role == Role.owner:
        assets_stmt = assets_stmt.where(Asset.owner_id == user.id)
        findings_filter.append(Asset.owner_id == user.id)

    def scoped(stmt):  # type: ignore[no-untyped-def]
        return stmt.join(Asset, Finding.asset_id == Asset.id).where(*findings_filter)

    by_status = {s.value: 0 for s in FindingStatus}
    for status, count in db.execute(
        scoped(select(Finding.status, func.count())).group_by(Finding.status)
    ):
        by_status[status.value] = count

    unresolved = Finding.status.in_(UNRESOLVED_STATUSES)
    by_level = {level.value: 0 for level in Severity}
    for level, count in db.execute(
        scoped(select(Finding.risk_level, func.count()))
        .where(unresolved)
        .group_by(Finding.risk_level)
    ):
        by_level[level.value] = count

    overdue = db.scalar(
        scoped(select(func.count()).select_from(Finding)).where(
            unresolved, Finding.due_date < utc_today()
        )
    )
    top = db.scalars(
        scoped(select(Finding))
        .where(unresolved)
        .order_by(Finding.risk_score.desc(), Finding.due_date.asc(), Finding.id.asc())
        .limit(5)
    ).unique()

    return AnalyticsSummary(
        assets_total=db.scalar(assets_stmt) or 0,
        findings_by_status=by_status,
        findings_by_risk_level=by_level,
        findings_overdue=overdue or 0,
        top_risk_findings=[FindingOut.model_validate(f) for f in top],
    )
