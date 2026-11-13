from pydantic import BaseModel, EmailStr, Field

from app.models.enums import Role
from app.schemas.common import ORMModel, UTCDatetime

USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]+$"


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_PATTERN)
    email: EmailStr = Field(max_length=255)
    full_name: str = Field(min_length=1, max_length=120)
    # Длину и состав проверяет парольная политика (services/passwords.py).
    password: str = Field(max_length=128)


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    full_name: str
    role: Role
    is_active: bool
    created_at: UTCDatetime
    updated_at: UTCDatetime


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=120)
