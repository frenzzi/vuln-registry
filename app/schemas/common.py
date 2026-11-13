from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, PlainSerializer, WithJsonSchema


def _to_utc_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


# Все datetime в API — UTC, ISO 8601 с суффиксом Z.
UTCDatetime = Annotated[
    datetime,
    PlainSerializer(_to_utc_z, return_type=str, when_used="json"),
    WithJsonSchema({"type": "string", "format": "date-time"}),
]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class Message(BaseModel):
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
