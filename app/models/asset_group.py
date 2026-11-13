from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TimestampMixin


class AssetGroup(IdMixin, TimestampMixin, Base):
    __tablename__ = "asset_groups"

    name: Mapped[str] = mapped_column(String(100), unique=True)
    code: Mapped[str] = mapped_column(String(16), unique=True)
