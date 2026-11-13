from typing import Annotated

from fastapi import APIRouter, Query, Response
from sqlalchemy import select

from app.core.config import API_PREFIX
from app.core.deps import AdminUser, CurrentUser, DbSession, Pagination, StaffUser
from app.core.exceptions import not_found
from app.models.enums import Severity
from app.models.vulnerability import Vulnerability
from app.schemas.common import Page
from app.schemas.vulnerability import (
    CvssCalculateRequest,
    CvssCalculation,
    VulnerabilityCreate,
    VulnerabilityDetail,
    VulnerabilityOut,
    VulnerabilityUpdate,
)
from app.services import cvss
from app.services import vulnerabilities as vuln_service
from app.services.queries import apply_sort, contains, paginate

router = APIRouter(tags=["vulnerabilities"])
cvss_router = APIRouter(tags=["cvss"])

SORT_FIELDS = {
    "cvss_base_score": Vulnerability.cvss_base_score,
    "published_date": Vulnerability.published_date,
    "cve_id": Vulnerability.cve_id,
}


def _get_or_404(db: DbSession, vuln_id: int) -> Vulnerability:
    vulnerability = db.get(Vulnerability, vuln_id)
    if vulnerability is None:
        raise not_found("VULN_NOT_FOUND", "Запись каталога не найдена")
    return vulnerability


def _calculation(vector: str) -> CvssCalculation:
    result = cvss.calculate(vector)
    return CvssCalculation(
        base_score=result.base_score,
        severity=result.severity,
        impact=result.impact,
        exploitability=result.exploitability,
        metrics=result.metrics,
    )


@router.get("", response_model=Page[VulnerabilityOut], summary="Список уязвимостей")
def list_vulnerabilities(
    _user: CurrentUser,
    db: DbSession,
    page: Pagination,
    severity: Severity | None = None,
    cwe_id: Annotated[str | None, Query(max_length=16)] = None,
    min_score: Annotated[float | None, Query(ge=0, le=10)] = None,
    max_score: Annotated[float | None, Query(ge=0, le=10)] = None,
    q: Annotated[
        str | None, Query(max_length=100, description="Поиск по названию и идентификаторам")
    ] = None,
    sort: Annotated[
        str | None,
        Query(max_length=32, description="cvss_base_score, published_date, cve_id; «-» — убывание"),
    ] = None,
) -> Page[VulnerabilityOut]:
    """Каталог уязвимостей с фильтрами, сортировкой и пагинацией."""
    stmt = select(Vulnerability)
    if severity is not None:
        stmt = stmt.where(Vulnerability.cvss_severity == severity)
    if cwe_id:
        stmt = stmt.where(Vulnerability.cwe_id == cwe_id)
    if min_score is not None:
        stmt = stmt.where(Vulnerability.cvss_base_score >= min_score)
    if max_score is not None:
        stmt = stmt.where(Vulnerability.cvss_base_score <= max_score)
    if q:
        stmt = stmt.where(
            contains(Vulnerability.title, q)
            | contains(Vulnerability.cve_id, q)
            | contains(Vulnerability.bdu_id, q)
        )
    stmt = apply_sort(
        stmt, sort, SORT_FIELDS, default="-cvss_base_score", tiebreak=Vulnerability.id
    )
    items, total = paginate(db, stmt, page)
    return Page(
        items=[VulnerabilityOut.model_validate(v) for v in items],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("", response_model=VulnerabilityOut, status_code=201, summary="Создание записи")
def create_vulnerability(
    data: VulnerabilityCreate, _staff: StaffUser, db: DbSession, response: Response
) -> VulnerabilityOut:
    """Создаёт запись каталога. Передаётся вектор CVSS v3.1; балл и уровень считает сервер,
    переданный клиентом `cvss_base_score` игнорируется. Дубль `cve_id` / `bdu_id` — 409,
    неверный вектор — 422 `VULN_INVALID_CVSS_VECTOR`.
    """
    vulnerability = vuln_service.create_vulnerability(db, data)
    response.headers["Location"] = f"{API_PREFIX}/vulnerabilities/{vulnerability.id}"
    return VulnerabilityOut.model_validate(vulnerability)


@router.get("/{vuln_id}", response_model=VulnerabilityDetail, summary="Карточка уязвимости")
def get_vulnerability(vuln_id: int, _user: CurrentUser, db: DbSession) -> VulnerabilityDetail:
    """Карточка с разбором вектора CVSS и количеством обнаружений."""
    vulnerability = _get_or_404(db, vuln_id)
    base = VulnerabilityOut.model_validate(vulnerability).model_dump()
    return VulnerabilityDetail(
        **base,
        cvss=_calculation(vulnerability.cvss_vector),
        findings_count=vuln_service.findings_count(db, vulnerability.id),
    )


@router.patch("/{vuln_id}", response_model=VulnerabilityOut, summary="Изменение записи")
def update_vulnerability(
    vuln_id: int, data: VulnerabilityUpdate, _staff: StaffUser, db: DbSession
) -> VulnerabilityOut:
    """Изменяет запись каталога. Смена `cvss_vector` пересчитывает балл записи и риск
    связанных открытых обнаружений."""
    vulnerability = vuln_service.update_vulnerability(db, _get_or_404(db, vuln_id), data)
    return VulnerabilityOut.model_validate(vulnerability)


@router.delete("/{vuln_id}", status_code=204, summary="Удаление записи")
def delete_vulnerability(vuln_id: int, _admin: AdminUser, db: DbSession) -> Response:
    """Удаляет запись каталога. Только администратор. Если по записи есть обнаружения —
    409 `VULN_HAS_FINDINGS`."""
    vuln_service.delete_vulnerability(db, _get_or_404(db, vuln_id))
    return Response(status_code=204)


@cvss_router.post("/calculate", response_model=CvssCalculation, summary="Калькулятор CVSS")
def calculate_cvss(data: CvssCalculateRequest, _user: CurrentUser) -> CvssCalculation:
    """Считает базовый балл CVSS v3.1 по вектору без сохранения."""
    return _calculation(data.vector)
