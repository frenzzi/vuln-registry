from pydantic import BaseModel

from app.schemas.finding import FindingOut


class AnalyticsSummary(BaseModel):
    assets_total: int
    findings_by_status: dict[str, int]
    findings_by_risk_level: dict[str, int]
    findings_overdue: int
    top_risk_findings: list[FindingOut]
