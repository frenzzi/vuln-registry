from datetime import date

from pydantic import BaseModel, Field, computed_field

from app.core.time import utc_today
from app.models.enums import Criticality, FindingStatus, Severity
from app.schemas.common import ORMModel, UTCDatetime
from app.services import risk


class FindingOut(ORMModel):
    id: int
    asset_id: int
    vulnerability_id: int
    status: FindingStatus
    risk_score: float
    risk_level: Severity
    first_detected_at: UTCDatetime
    last_detected_at: UTCDatetime
    detection_count: int
    due_date: date
    assignee_id: int | None
    resolution_comment: str | None
    closed_at: UTCDatetime | None
    created_at: UTCDatetime
    updated_at: UTCDatetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_overdue(self) -> bool:
        return risk.is_overdue(self.due_date, self.status, utc_today())


class FindingAssetBrief(ORMModel):
    id: int
    name: str
    hostname: str | None
    criticality: Criticality
    owner_id: int
    is_active: bool


class FindingVulnerabilityBrief(ORMModel):
    id: int
    cve_id: str | None
    bdu_id: str | None
    title: str
    cvss_base_score: float
    cvss_severity: Severity


class FindingDetail(FindingOut):
    asset: FindingAssetBrief
    vulnerability: FindingVulnerabilityBrief


class FindingCreate(BaseModel):
    asset_id: int
    vulnerability_id: int


class FindingImportItem(BaseModel):
    asset_id: int
    cve_id: str = Field(max_length=20)


class FindingImportRequest(BaseModel):
    items: list[FindingImportItem] = Field(max_length=1000)


class FindingImportError(BaseModel):
    index: int
    asset_id: int
    cve_id: str
    code: str
    message: str


class FindingImportResult(BaseModel):
    created: int
    updated: int
    errors: list[FindingImportError]


class FindingStatusChange(BaseModel):
    status: FindingStatus
    resolution_comment: str | None = Field(default=None, max_length=2000)


class FindingAssigneeChange(BaseModel):
    assignee_id: int | None
