"""Служебное поведение: формат ошибок, схема OpenAPI, миграции, сид-данные."""

from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from alembic import command
from app.core.exceptions import register_exception_handlers
from app.db.base import Base
from app.db.seed import DEBUG_PASSWORDS, seed_database
from app.models.asset import Asset
from app.models.enums import FindingStatus, Role
from app.models.finding import Finding
from app.models.user import User
from tests.helpers import API

ROOT = Path(__file__).resolve().parents[2]


async def test_health_reveals_nothing(anon: AsyncClient) -> None:
    response = await anon.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_unknown_route_and_method_use_error_format(anon: AsyncClient) -> None:
    missing = await anon.get(f"{API}/nothing-here")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "NOT_FOUND"

    wrong_method = await anon.delete("/health")
    assert wrong_method.status_code == 405
    assert wrong_method.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


async def test_unhandled_exception_returns_generic_500() -> None:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("секрет: /srv/app/config.py password=hunter2")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "INTERNAL_ERROR", "message": "Внутренняя ошибка сервера", "details": None}
    }
    assert "hunter2" not in response.text
    assert "RuntimeError" not in response.text
    assert "Traceback" not in response.text


def test_openapi_describes_28_application_endpoints(app: FastAPI) -> None:
    schema = app.openapi()
    operations = [
        (method, path)
        for path, item in schema["paths"].items()
        if path.startswith(API)
        for method in item
    ]
    assert len(operations) == 28
    assert "/health" in schema["paths"]
    assert "OAuth2PasswordBearer" in schema["components"]["securitySchemes"]
    for _method, path in operations:
        for item in schema["paths"][path].values():
            assert item.get("description"), f"нет docstring у {path}"


async def test_responses_never_contain_password_hash(admin: AsyncClient, accounts) -> None:
    listing = await admin.get(f"{API}/users")
    detail = await admin.get(f"{API}/users/{accounts.ids['owner1']}")
    for response in (listing, detail):
        assert "hashed_password" not in response.text
        assert "$2b$" not in response.text


async def test_sql_injection_strings_are_inert(analyst: AsyncClient, admin: AsyncClient) -> None:
    for payload in (
        "' OR 1=1--",
        "';DROP TABLE assets;--",
        '" UNION SELECT hashed_password FROM users--',
    ):
        for path in ("assets", "vulnerabilities", "users"):
            client = admin if path == "users" else analyst
            response = await client.get(f"{API}/{path}", params={"q": payload})
            assert response.status_code == 200
            assert response.json()["total"] == 0
            assert "$2b$" not in response.text
    assert (await analyst.get(f"{API}/assets")).status_code == 200


def _alembic_config(url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_migrations_create_the_schema_described_by_models(tmp_path: Path) -> None:
    url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    command.upgrade(_alembic_config(url), "head")

    engine = create_engine(url)
    assert set(inspect(engine).get_table_names()) >= set(Base.metadata.tables)
    with engine.connect() as connection:
        diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    assert diff == []

    command.downgrade(_alembic_config(url), "base")
    assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    engine.dispose()


def test_seed_is_idempotent_and_covers_all_statuses(db: Session) -> None:
    seed_database(db, DEBUG_PASSWORDS)
    snapshot = {
        "users": db.scalars(select(User)).all(),
        "assets": db.scalars(select(Asset)).all(),
        "findings": db.scalars(select(Finding)).all(),
    }
    assert len(snapshot["users"]) == 4
    assert len(snapshot["assets"]) == 10
    assert {u.role for u in snapshot["users"]} == {Role.admin, Role.analyst, Role.owner}

    owners = {u.id: u.username for u in snapshot["users"]}
    per_owner: dict[str, int] = {}
    for asset in snapshot["assets"]:
        per_owner[owners[asset.owner_id]] = per_owner.get(owners[asset.owner_id], 0) + 1
    assert per_owner == {"owner1": 6, "owner2": 4}

    findings: list[Finding] = snapshot["findings"]  # type: ignore[assignment]
    assert {f.status for f in findings} == set(FindingStatus)

    seed_database(db, DEBUG_PASSWORDS)
    assert len(db.scalars(select(User)).all()) == 4
    assert len(db.scalars(select(Asset)).all()) == 10
    assert len(db.scalars(select(Finding)).all()) == len(findings)


async def test_seeded_users_can_login_and_owner_isolation_holds(
    anon: AsyncClient, db: Session
) -> None:
    seed_database(db, DEBUG_PASSWORDS)

    async def token(username: str) -> str:
        response = await anon.post(
            f"{API}/auth/login", data={"username": username, "password": DEBUG_PASSWORDS[username]}
        )
        assert response.status_code == 200
        return response.json()["access_token"]

    owner1 = {"Authorization": f"Bearer {await token('owner1')}"}
    admin = {"Authorization": f"Bearer {await token('admin')}"}

    assets = (await anon.get(f"{API}/assets", params={"limit": 100}, headers=owner1)).json()
    assert assets["total"] == 6
    summary = (await anon.get(f"{API}/analytics/summary", headers=owner1)).json()
    assert summary["assets_total"] == 6
    assert (await anon.get(f"{API}/analytics/summary", headers=admin)).json()["assets_total"] == 10

    overdue = (await anon.get(f"{API}/findings", params={"overdue": "true"}, headers=admin)).json()
    assert overdue["total"] == 1
    assert overdue["items"][0]["status"] == "confirmed"


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
async def test_documentation_is_available(anon: AsyncClient, path: str) -> None:
    assert (await anon.get(path)).status_code == 200
