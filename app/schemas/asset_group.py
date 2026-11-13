from pydantic import BaseModel, Field

from app.schemas.common import ORMModel, UTCDatetime


class AssetGroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    code: str = Field(min_length=2, max_length=16, pattern=r"^[A-Z0-9-]+$")


class AssetGroupOut(ORMModel):
    id: int
    name: str
    code: str
    assets_count: int = 0
    created_at: UTCDatetime
    updated_at: UTCDatetime
