from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator

from app.models.enums import AssetType, Criticality
from app.schemas.common import ORMModel, UTCDatetime


def _validate_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise ValueError("Некорректный IP-адрес") from exc


class AssetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    hostname: str | None = Field(default=None, min_length=1, max_length=253)
    ip_address: str | None = Field(default=None, max_length=45)
    asset_type: AssetType
    criticality: Criticality = Criticality.medium
    group_id: int
    owner_id: int
    description: str | None = Field(default=None, max_length=1000)

    _check_ip = field_validator("ip_address")(_validate_ip)


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    hostname: str | None = Field(default=None, min_length=1, max_length=253)
    ip_address: str | None = Field(default=None, max_length=45)
    asset_type: AssetType | None = None
    criticality: Criticality | None = None
    group_id: int | None = None
    owner_id: int | None = None
    description: str | None = Field(default=None, max_length=1000)

    _check_ip = field_validator("ip_address")(_validate_ip)


class AssetOut(ORMModel):
    id: int
    name: str
    hostname: str | None
    ip_address: str | None
    asset_type: AssetType
    criticality: Criticality
    group_id: int
    owner_id: int
    is_active: bool
    description: str | None
    created_at: UTCDatetime
    updated_at: UTCDatetime


class AssetDetail(AssetOut):
    group_name: str
    group_code: str
    findings_by_risk_level: dict[str, int] = Field(
        description="Открытые обнаружения по уровням риска"
    )
