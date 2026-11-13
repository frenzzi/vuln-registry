import os

# Окружение задаётся до первого импорта приложения: настройки читаются при импорте.
os.environ["APP_SECRET_KEY"] = "test-secret-key-only-for-pytest-0123456789"
os.environ["APP_BCRYPT_ROUNDS"] = "4"
os.environ["APP_DATABASE_URL"] = "sqlite://"
os.environ["APP_DEBUG"] = "false"
os.environ["APP_TOKEN_TTL_MINUTES"] = "60"
for _name in (
    "SEED_ADMIN_PASSWORD",
    "SEED_ANALYST_PASSWORD",
    "SEED_OWNER1_PASSWORD",
    "SEED_OWNER2_PASSWORD",
):
    os.environ.pop(_name, None)

from collections.abc import AsyncIterator, Callable, Iterator  # noqa: E402
from contextlib import AbstractContextManager  # noqa: E402
from dataclasses import dataclass  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import Engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core.deps import get_db  # noqa: E402
from app.core.security import create_access_token  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import create_db_engine  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models.enums import Role  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.users import create_user  # noqa: E402

PASSWORDS = {
    "admin": "Admin-Test-2026",
    "analyst": "Analyst-Test-2026",
    "owner1": "Owner1-Test-2026",
    "owner2": "Owner2-Test-2026",
}
ROLES = {
    "admin": Role.admin,
    "analyst": Role.analyst,
    "owner1": Role.owner,
    "owner2": Role.owner,
}

SessionCtx = Callable[[], AbstractContextManager[Session]]


@pytest.fixture
def engine() -> Iterator[Engine]:
    """Отдельная БД SQLite в памяти на каждый тест."""
    engine = create_db_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as session:
        yield session


@pytest.fixture
def app(session_factory: sessionmaker[Session]) -> Iterator[FastAPI]:
    def override_get_db() -> Iterator[Session]:
        with session_factory() as session:
            yield session

    fastapi_app.dependency_overrides[get_db] = override_get_db
    yield fastapi_app
    fastapi_app.dependency_overrides.clear()


@dataclass
class Accounts:
    ids: dict[str, int]
    tokens: dict[str, str]


@pytest.fixture
def accounts(db: Session) -> Accounts:
    """Четыре пользователя, как в сид-данных, и их токены."""
    ids: dict[str, int] = {}
    tokens: dict[str, str] = {}
    for username, role in ROLES.items():
        user: User = create_user(
            db,
            username=username,
            email=f"{username}@example.com",
            full_name=f"Тест {username}",
            password=PASSWORDS[username],
            role=role,
        )
        ids[username] = user.id
        tokens[username], _ = create_access_token(user.id, username, role.value)
    return Accounts(ids=ids, tokens=tokens)


def _client(app: FastAPI, token: str | None = None) -> AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
        headers=headers,
    )


@pytest.fixture
async def anon(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with _client(app) as client:
        yield client


@pytest.fixture
async def admin(app: FastAPI, accounts: Accounts) -> AsyncIterator[AsyncClient]:
    async with _client(app, accounts.tokens["admin"]) as client:
        yield client


@pytest.fixture
async def analyst(app: FastAPI, accounts: Accounts) -> AsyncIterator[AsyncClient]:
    async with _client(app, accounts.tokens["analyst"]) as client:
        yield client


@pytest.fixture
async def owner1(app: FastAPI, accounts: Accounts) -> AsyncIterator[AsyncClient]:
    async with _client(app, accounts.tokens["owner1"]) as client:
        yield client


@pytest.fixture
async def owner2(app: FastAPI, accounts: Accounts) -> AsyncIterator[AsyncClient]:
    async with _client(app, accounts.tokens["owner2"]) as client:
        yield client


@pytest.fixture
def make_client(app: FastAPI) -> Callable[[str | None], AsyncClient]:
    """Клиент с произвольным токеном (или без него)."""
    return lambda token=None: _client(app, token)
