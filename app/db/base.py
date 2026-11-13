from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.core.time import utcnow


class UTCDateTime(TypeDecorator[datetime]):
    """DateTime, который хранит UTC и всегда возвращает значение с tzinfo=UTC.

    SQLite теряет часовой пояс, поэтому приводим к UTC на входе и восстанавливаем на выходе.
    """

    impl = DateTime(timezone=False)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Ожидался datetime с часовым поясом")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    """created_at / updated_at заполняются сервером и в API только читаются."""

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class IdMixin:
    id: Mapped[int] = mapped_column(primary_key=True)
