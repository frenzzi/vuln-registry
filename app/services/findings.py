"""Жизненный цикл обнаружения (BR-6), дедупликация (BR-5), пересчёт риска (BR-4)."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, conflict
from app.core.time import utcnow
from app.models.asset import Asset
from app.models.enums import CLOSED_STATUSES, FindingStatus, Role
from app.models.finding import Finding
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services import risk

Actor = Literal["staff", "owner"]

MIN_RESOLUTION_COMMENT = 10

S = FindingStatus

# Из какого статуса в какой можно перейти и кто вправе: staff — admin и analyst,
# owner — владелец актива.
TRANSITIONS: dict[FindingStatus, dict[FindingStatus, frozenset[Actor]]] = {
    S.new: {
        S.confirmed: frozenset({"staff"}),
        S.false_positive: frozenset({"staff"}),
    },
    S.confirmed: {
        S.in_progress: frozenset({"staff", "owner"}),
        S.false_positive: frozenset({"staff"}),
    },
    S.in_progress: {
        S.fixed: frozenset({"staff", "owner"}),
        S.confirmed: frozenset({"staff", "owner"}),
    },
    S.fixed: {
        S.closed: frozenset({"staff"}),
        S.confirmed: frozenset({"staff"}),
    },
    S.false_positive: {
        S.closed: frozenset({"staff"}),
    },
    S.closed: {},
}


def actor_for(role: Role) -> Actor:
    return "owner" if role == Role.owner else "staff"


def allowed_transitions(current: FindingStatus, actor: Actor) -> list[FindingStatus]:
    """Переходы из текущего состояния, доступные данному типу пользователя."""
    return [target for target, who in TRANSITIONS[current].items() if actor in who]


def check_transition(current: FindingStatus, target: FindingStatus, actor: Actor) -> None:
    """Проверяет переход по матрице BR-6.

    Переход вне матрицы (включая переход в тот же статус) — 409 со списком допустимых.
    Переход есть, но этому пользователю не разрешён — 403.
    """
    if target not in TRANSITIONS[current]:
        allowed = [s.value for s in allowed_transitions(current, actor)]
        raise conflict(
            "FINDING_INVALID_STATUS_TRANSITION",
            f"Переход {current.value} → {target.value} недопустим",
            {"allowed": allowed},
        )
    if actor not in TRANSITIONS[current][target]:
        raise AppError(
            403,
            "AUTHZ_ROLE_FORBIDDEN",
            f"Переход {current.value} → {target.value} вам недоступен",
        )


def change_status(
    db: Session,
    finding: Finding,
    target: FindingStatus,
    actor: Actor,
    resolution_comment: str | None,
) -> Finding:
    check_transition(finding.status, target, actor)
    comment = (resolution_comment or "").strip()
    if target == FindingStatus.fixed and len(comment) < MIN_RESOLUTION_COMMENT:
        raise AppError(
            422,
            "FINDING_RESOLUTION_COMMENT_REQUIRED",
            f"Для перехода в fixed нужен комментарий не короче {MIN_RESOLUTION_COMMENT} символов",
        )
    finding.status = target
    if comment:
        finding.resolution_comment = comment
    if target == FindingStatus.closed:
        finding.closed_at = utcnow()
    db.commit()
    db.refresh(finding)
    return finding


def recalculate(finding: Finding, asset: Asset, vulnerability: Vulnerability) -> None:
    """Пересчитывает risk_score, risk_level и due_date. Вызывается явно, не триггером БД."""
    finding.risk_score = risk.risk_score(vulnerability.cvss_base_score, asset.criticality)
    finding.risk_level = risk.risk_level(finding.risk_score)
    finding.due_date = risk.due_date(finding.first_detected_at, finding.risk_level)


def _recalculable(db: Session, *conditions: object) -> list[Finding]:
    stmt = select(Finding).where(Finding.status.not_in(CLOSED_STATUSES), *conditions)  # type: ignore[arg-type]
    return list(db.scalars(stmt))


def recalculate_for_asset(db: Session, asset: Asset) -> None:
    for finding in _recalculable(db, Finding.asset_id == asset.id):
        recalculate(finding, asset, finding.vulnerability)


def recalculate_for_vulnerability(db: Session, vulnerability: Vulnerability) -> None:
    for finding in _recalculable(db, Finding.vulnerability_id == vulnerability.id):
        recalculate(finding, finding.asset, vulnerability)


def find_open(db: Session, asset_id: int, vulnerability_id: int) -> Finding | None:
    return db.scalars(
        select(Finding).where(
            Finding.asset_id == asset_id,
            Finding.vulnerability_id == vulnerability_id,
            Finding.status.not_in(CLOSED_STATUSES),
        )
    ).first()


def register_detection(
    db: Session, asset: Asset, vulnerability: Vulnerability, now: datetime | None = None
) -> tuple[Finding, bool]:
    """Регистрирует обнаружение с дедупликацией. Возвращает (обнаружение, создано_ли_новое).

    Коммит выполняет вызывающий код.
    """
    now = now or utcnow()
    existing = find_open(db, asset.id, vulnerability.id)
    if existing is not None:
        existing.last_detected_at = now
        existing.detection_count += 1
        db.flush()
        return existing, False

    finding = Finding(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=FindingStatus.new,
        first_detected_at=now,
        last_detected_at=now,
        detection_count=1,
    )
    finding.asset = asset
    finding.vulnerability = vulnerability
    recalculate(finding, asset, vulnerability)
    db.add(finding)
    db.flush()
    return finding, True


def close_asset_findings(db: Session, asset: Asset) -> None:
    """При выводе актива из учёта закрывает все его ещё не закрытые обнаружения."""
    now = utcnow()
    stmt = select(Finding).where(
        Finding.asset_id == asset.id, Finding.status != FindingStatus.closed
    )
    for finding in db.scalars(stmt):
        finding.status = FindingStatus.closed
        finding.closed_at = now
        if not finding.resolution_comment:
            finding.resolution_comment = "Актив выведен из учёта"


def assign(db: Session, finding: Finding, assignee_id: int | None) -> Finding:
    if assignee_id is not None:
        user = db.get(User, assignee_id)
        if user is None or not user.is_active:
            raise AppError(
                422,
                "FINDING_ASSIGNEE_INVALID",
                "Исполнитель не найден или заблокирован",
                {"field": "assignee_id"},
            )
    finding.assignee_id = assignee_id
    db.commit()
    db.refresh(finding)
    return finding


@dataclass
class ImportItemError:
    index: int
    asset_id: int
    cve_id: str
    code: str
    message: str


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    errors: list[ImportItemError] = field(default_factory=list)


def import_detections(db: Session, items: list[tuple[int, str]]) -> ImportResult:
    """Массовая регистрация обнаружений из внешнего сканера.

    Ошибка в одном элементе не прерывает обработку остальных.
    """
    result = ImportResult()
    for index, (asset_id, cve_id) in enumerate(items):
        asset = db.get(Asset, asset_id)
        if asset is None:
            result.errors.append(
                ImportItemError(index, asset_id, cve_id, "ASSET_NOT_FOUND", "Актив не найден")
            )
            continue
        if not asset.is_active:
            result.errors.append(
                ImportItemError(index, asset_id, cve_id, "ASSET_INACTIVE", "Актив выведен из учёта")
            )
            continue
        vulnerability = db.scalars(
            select(Vulnerability).where(Vulnerability.cve_id == cve_id.strip().upper())
        ).first()
        if vulnerability is None:
            result.errors.append(
                ImportItemError(
                    index, asset_id, cve_id, "VULN_NOT_FOUND", "Уязвимость отсутствует в каталоге"
                )
            )
            continue
        _, created = register_detection(db, asset, vulnerability)
        if created:
            result.created += 1
        else:
            result.updated += 1
    db.commit()
    return result
