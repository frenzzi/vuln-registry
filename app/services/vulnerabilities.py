"""Каталог уязвимостей (BR-3, BR-4)."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import conflict
from app.models.finding import Finding
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityUpdate
from app.services import cvss
from app.services import findings as findings_service

NULLABLE_FIELDS = {"cve_id", "bdu_id", "cwe_id", "published_date"}


def _ensure_ids_free(
    db: Session, cve_id: str | None, bdu_id: str | None, exclude_id: int | None = None
) -> None:
    for column, value, code, label in (
        (Vulnerability.cve_id, cve_id, "VULN_CVE_TAKEN", "CVE"),
        (Vulnerability.bdu_id, bdu_id, "VULN_BDU_TAKEN", "BDU"),
    ):
        if value is None:
            continue
        stmt = select(Vulnerability.id).where(column == value)
        if exclude_id is not None:
            stmt = stmt.where(Vulnerability.id != exclude_id)
        if db.scalars(stmt).first() is not None:
            raise conflict(code, f"Запись с таким идентификатором {label} уже есть в каталоге")


def create_vulnerability(db: Session, data: VulnerabilityCreate) -> Vulnerability:
    """Балл и уровень считает сервер по вектору; переданные клиентом значения не используются."""
    result = cvss.calculate(data.cvss_vector)
    _ensure_ids_free(db, data.cve_id, data.bdu_id)
    vulnerability = Vulnerability(
        **data.model_dump(),
        cvss_base_score=result.base_score,
        cvss_severity=result.severity,
    )
    db.add(vulnerability)
    db.commit()
    db.refresh(vulnerability)
    return vulnerability


def update_vulnerability(
    db: Session, vulnerability: Vulnerability, data: VulnerabilityUpdate
) -> Vulnerability:
    changes = {
        field: value
        for field, value in data.model_dump(exclude_unset=True).items()
        if value is not None or field in NULLABLE_FIELDS
    }
    if "cve_id" in changes or "bdu_id" in changes:
        _ensure_ids_free(
            db,
            changes.get("cve_id", vulnerability.cve_id),
            changes.get("bdu_id", vulnerability.bdu_id),
            exclude_id=vulnerability.id,
        )

    vector_changed = (
        "cvss_vector" in changes and changes["cvss_vector"] != vulnerability.cvss_vector
    )
    if "cvss_vector" in changes:
        result = cvss.calculate(changes["cvss_vector"])
        vulnerability.cvss_base_score = result.base_score
        vulnerability.cvss_severity = result.severity
    for field, value in changes.items():
        setattr(vulnerability, field, value)
    if vector_changed:
        findings_service.recalculate_for_vulnerability(db, vulnerability)
    db.commit()
    db.refresh(vulnerability)
    return vulnerability


def findings_count(db: Session, vulnerability_id: int) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.vulnerability_id == vulnerability_id)
        )
        or 0
    )


def delete_vulnerability(db: Session, vulnerability: Vulnerability) -> None:
    if findings_count(db, vulnerability.id) > 0:
        raise conflict("VULN_HAS_FINDINGS", "По записи есть обнаружения, удаление невозможно")
    db.delete(vulnerability)
    db.commit()
