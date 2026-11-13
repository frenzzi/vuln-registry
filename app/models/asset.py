from sqlalchemy import Boolean, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TimestampMixin
from app.models.asset_group import AssetGroup
from app.models.enums import AssetType, Criticality
from app.models.user import User


def _enum(enum_cls: type) -> Enum:
    return Enum(
        enum_cls, native_enum=False, length=16, values_callable=lambda e: [m.value for m in e]
    )


class Asset(IdMixin, TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("group_id", "hostname", name="uq_asset_group_hostname"),)

    name: Mapped[str] = mapped_column(String(120))
    hostname: Mapped[str | None] = mapped_column(String(253))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    asset_type: Mapped[AssetType] = mapped_column(_enum(AssetType))
    criticality: Mapped[Criticality] = mapped_column(_enum(Criticality), default=Criticality.medium)
    group_id: Mapped[int] = mapped_column(ForeignKey("asset_groups.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(String(1000))

    group: Mapped[AssetGroup] = relationship(lazy="joined")
    owner: Mapped[User] = relationship(lazy="select")
