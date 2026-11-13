from datetime import date, datetime

from sqlalchemy import Date, Enum, Float, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.time import utcnow
from app.db.base import Base, IdMixin, TimestampMixin, UTCDateTime
from app.models.asset import Asset
from app.models.enums import FindingStatus, Severity
from app.models.user import User
from app.models.vulnerability import Vulnerability


def _enum(enum_cls: type) -> Enum:
    return Enum(
        enum_cls, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e]
    )


class Finding(IdMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        # Одно открытое обнаружение на пару «актив + уязвимость».
        Index(
            "uq_finding_open_pair",
            "asset_id",
            "vulnerability_id",
            unique=True,
            sqlite_where=text("status NOT IN ('closed', 'false_positive')"),
        ),
    )

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    status: Mapped[FindingStatus] = mapped_column(_enum(FindingStatus), default=FindingStatus.new)
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[Severity] = mapped_column(_enum(Severity))
    first_detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    detection_count: Mapped[int] = mapped_column(Integer, default=1)
    due_date: Mapped[date] = mapped_column(Date)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    resolution_comment: Mapped[str | None] = mapped_column(String(2000))
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    asset: Mapped[Asset] = relationship(lazy="joined")
    vulnerability: Mapped[Vulnerability] = relationship(lazy="joined")
    assignee: Mapped[User | None] = relationship(lazy="select")
