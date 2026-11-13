"""Матрица прав BR-2: ролевой и объектный уровни авторизации."""

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session, sessionmaker

from tests.conftest import Accounts
from tests.helpers import API, V_CRITICAL, World, build_world, insert_finding


@pytest.fixture
async def world(analyst: AsyncClient, accounts: Accounts) -> World:
    return await build_world(analyst, accounts.ids)


async def test_users_endpoints_are_admin_only(
    admin: AsyncClient, analyst: AsyncClient, owner1: AsyncClient, accounts: Accounts
) -> None:
    target = accounts.ids["owner1"]
    for client, allowed in ((admin, True), (analyst, False), (owner1, False)):
        listing = await client.get(f"{API}/users")
        detail = await client.get(f"{API}/users/{target}")
        patch = await client.patch(f"{API}/users/{target}", json={"full_name": "Новое Имя"})
        if allowed:
            assert (listing.status_code, detail.status_code, patch.status_code) == (200, 200, 200)
        else:
            for response in (listing, detail, patch):
                assert response.status_code == 403
                assert response.json()["error"]["code"] == "AUTHZ_ROLE_FORBIDDEN"
    # Аналитик не смог повысить владельца до администратора
    assert (await admin.get(f"{API}/users/{target}")).json()["role"] == "owner"


async def test_admin_can_change_roles_and_filter_users(
    admin: AsyncClient, accounts: Accounts
) -> None:
    response = await admin.patch(f"{API}/users/{accounts.ids['owner2']}", json={"role": "analyst"})
    assert response.status_code == 200
    assert response.json()["role"] == "analyst"

    analysts = await admin.get(f"{API}/users", params={"role": "analyst"})
    assert analysts.json()["total"] == 2
    found = await admin.get(f"{API}/users", params={"q": "OWNER1"})
    assert [u["username"] for u in found.json()["items"]] == ["owner1"]
    assert (await admin.get(f"{API}/users/99999")).status_code == 404


async def test_admin_cannot_modify_own_role_or_activity(
    admin: AsyncClient, accounts: Accounts
) -> None:
    me = f"{API}/users/{accounts.ids['admin']}"
    for body in ({"role": "owner"}, {"is_active": False}):
        response = await admin.patch(me, json=body)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "USER_SELF_MODIFICATION_FORBIDDEN"
    current = (await admin.get(me)).json()
    assert current["role"] == "admin"
    assert current["is_active"] is True
    # Своё имя менять можно, а повторная отправка той же роли ничего не меняет
    assert (await admin.patch(me, json={"full_name": "Главный Админ"})).status_code == 200
    assert (await admin.patch(me, json={"role": "admin"})).status_code == 200


async def test_role_matrix_for_groups_assets_and_catalog(
    admin: AsyncClient, analyst: AsyncClient, owner1: AsyncClient, world: World, accounts: Accounts
) -> None:
    owner_id = accounts.ids["owner1"]
    asset_body = {
        "name": "Новый актив",
        "asset_type": "server",
        "group_id": world.groups["OFFICE"],
        "owner_id": owner_id,
    }
    vuln_body = {"cve_id": "CVE-2026-20000", "title": "Тестовая запись", "cvss_vector": V_CRITICAL}

    # Создание групп: admin и analyst, но не owner
    assert (
        await owner1.post(f"{API}/asset-groups", json={"name": "Г1", "code": "G1"})
    ).status_code == 403
    assert (
        await analyst.post(f"{API}/asset-groups", json={"name": "Г2", "code": "G2"})
    ).status_code == 201
    assert (
        await admin.post(f"{API}/asset-groups", json={"name": "Г3", "code": "G3"})
    ).status_code == 201

    # Создание активов
    denied = await owner1.post(f"{API}/assets", json=asset_body)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert (
        await analyst.post(f"{API}/assets", json={**asset_body, "hostname": "h1"})
    ).status_code == 201
    assert (
        await admin.post(f"{API}/assets", json={**asset_body, "hostname": "h2"})
    ).status_code == 201

    # Удаление актива: только admin; владелец своего актива тоже получает 403
    own = world.assets["a1"]
    assert (await owner1.delete(f"{API}/assets/{own}")).status_code == 403
    assert (await analyst.delete(f"{API}/assets/{own}")).status_code == 403
    assert (await admin.delete(f"{API}/assets/{own}")).status_code == 204

    # Каталог: ведут admin и analyst; удаляет только admin
    assert (await owner1.post(f"{API}/vulnerabilities", json=vuln_body)).status_code == 403
    created = await analyst.post(f"{API}/vulnerabilities", json=vuln_body)
    assert created.status_code == 201
    vuln_id = created.json()["id"]
    assert (
        await owner1.patch(f"{API}/vulnerabilities/{vuln_id}", json={"title": "Новое имя записи"})
    ).status_code == 403
    assert (await analyst.delete(f"{API}/vulnerabilities/{vuln_id}")).status_code == 403
    assert (await admin.delete(f"{API}/vulnerabilities/{vuln_id}")).status_code == 204

    # Удаление группы — только admin
    group = (await analyst.post(f"{API}/asset-groups", json={"name": "Г4", "code": "G4"})).json()[
        "id"
    ]
    assert (await analyst.delete(f"{API}/asset-groups/{group}")).status_code == 403
    assert (await admin.delete(f"{API}/asset-groups/{group}")).status_code == 204


async def test_owner_sees_only_own_assets(
    owner1: AsyncClient,
    owner2: AsyncClient,
    analyst: AsyncClient,
    world: World,
    accounts: Accounts,
) -> None:
    mine = await owner1.get(f"{API}/assets", params={"limit": 100})
    assert mine.status_code == 200
    ids = {a["id"] for a in mine.json()["items"]}
    assert ids == {world.assets["a1"], world.assets["a2"]}
    assert mine.json()["total"] == 2

    # Фильтр по чужому владельцу не открывает чужое
    spoof = await owner1.get(f"{API}/assets", params={"owner_id": accounts.ids["owner2"]})
    assert spoof.json()["total"] == 0

    assert (await owner2.get(f"{API}/assets")).json()["total"] == 1
    assert (await analyst.get(f"{API}/assets")).json()["total"] == 3


async def test_foreign_asset_is_not_found_not_forbidden(
    owner1: AsyncClient, owner2: AsyncClient, world: World
) -> None:
    foreign = world.assets["a3"]  # принадлежит owner2
    missing = 999999

    for method, kwargs in (
        ("get", {}),
        ("patch", {"json": {"description": "чужое"}}),
    ):
        foreign_response = await getattr(owner1, method)(f"{API}/assets/{foreign}", **kwargs)
        missing_response = await getattr(owner1, method)(f"{API}/assets/{missing}", **kwargs)
        assert foreign_response.status_code == missing_response.status_code == 404
        assert foreign_response.json() == missing_response.json()

    assert (await owner2.get(f"{API}/assets/{foreign}")).status_code == 200


async def test_owner_edits_description_but_not_protected_fields(
    owner1: AsyncClient, analyst: AsyncClient, world: World, accounts: Accounts
) -> None:
    url = f"{API}/assets/{world.assets['a1']}"

    for body in (
        {"criticality": "critical"},
        {"owner_id": accounts.ids["owner2"]},
        {"name": "Переименован", "description": "заодно описание"},
    ):
        response = await owner1.patch(url, json=body)
        assert response.status_code == 403, body
        assert response.json()["error"]["code"] == "AUTHZ_FIELD_FORBIDDEN"

    current = (await owner1.get(url)).json()
    assert current["criticality"] == "low"
    assert current["description"] is None

    ok = await owner1.patch(url, json={"description": "Обновлено владельцем"})
    assert ok.status_code == 200
    assert ok.json()["description"] == "Обновлено владельцем"

    # Аналитик может менять и критичность, и владельца
    changed = await analyst.patch(url, json={"criticality": "high"})
    assert changed.status_code == 200
    assert changed.json()["criticality"] == "high"


async def test_owner_scope_for_findings_and_analytics(
    owner1: AsyncClient,
    owner2: AsyncClient,
    admin: AsyncClient,
    world: World,
    session_factory: sessionmaker[Session],
) -> None:
    own = insert_finding(session_factory, world.assets["a1"], world.vulns["v_crit"])
    insert_finding(session_factory, world.assets["a2"], world.vulns["v_med"])
    foreign = insert_finding(session_factory, world.assets["a3"], world.vulns["v_crit"])

    listing = await owner1.get(f"{API}/findings", params={"limit": 100})
    assert listing.json()["total"] == 2
    assert foreign not in {f["id"] for f in listing.json()["items"]}

    assert (await owner1.get(f"{API}/findings/{own}")).status_code == 200
    denied = await owner1.get(f"{API}/findings/{foreign}")
    assert denied.status_code == 404
    assert denied.json()["error"]["code"] == "FINDING_NOT_FOUND"
    assert (await owner2.get(f"{API}/findings/{foreign}")).status_code == 200

    # Статус чужого обнаружения тоже скрыт
    response = await owner1.patch(
        f"{API}/findings/{foreign}/status", json={"status": "in_progress"}
    )
    assert response.status_code == 404

    mine = (await owner1.get(f"{API}/analytics/summary")).json()
    everyone = (await admin.get(f"{API}/analytics/summary")).json()
    assert mine["assets_total"] == 2
    assert everyone["assets_total"] == 3
    assert sum(mine["findings_by_status"].values()) == 2
    assert sum(everyone["findings_by_status"].values()) == 3
    assert {f["asset_id"] for f in mine["top_risk_findings"]} <= {
        world.assets["a1"],
        world.assets["a2"],
    }


async def test_findings_status_transitions_by_role(
    owner1: AsyncClient,
    analyst: AsyncClient,
    world: World,
    session_factory: sessionmaker[Session],
) -> None:
    finding = insert_finding(session_factory, world.assets["a1"], world.vulns["v_crit"])
    url = f"{API}/findings/{finding}/status"

    forbidden = await owner1.patch(url, json={"status": "confirmed"})
    assert forbidden.status_code == 403
    assert (await analyst.patch(url, json={"status": "confirmed"})).status_code == 200
    assert (await owner1.patch(url, json={"status": "in_progress"})).status_code == 200

    # Владелец не может ни закрыть, ни назначить исполнителя
    assert (await owner1.patch(url, json={"status": "false_positive"})).status_code == 409
    response = await owner1.patch(f"{API}/findings/{finding}/assignee", json={"assignee_id": None})
    assert response.status_code == 403


async def test_changed_role_applies_immediately_to_existing_token(
    admin: AsyncClient, analyst: AsyncClient, accounts: Accounts
) -> None:
    assert (
        await analyst.post(f"{API}/asset-groups", json={"name": "Группа", "code": "GRP"})
    ).status_code == 201
    await admin.patch(f"{API}/users/{accounts.ids['analyst']}", json={"role": "owner"})
    response = await analyst.post(f"{API}/asset-groups", json={"name": "Другая", "code": "GR2"})
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/auth/me"),
        ("post", "/auth/change-password"),
        ("get", "/users"),
        ("get", "/asset-groups"),
        ("post", "/asset-groups"),
        ("get", "/assets"),
        ("get", "/assets/1"),
        ("post", "/assets"),
        ("get", "/vulnerabilities"),
        ("post", "/vulnerabilities"),
        ("post", "/cvss/calculate"),
        ("get", "/findings"),
        ("get", "/findings/1"),
        ("post", "/findings"),
        ("post", "/findings/import"),
        ("patch", "/findings/1/status"),
        ("patch", "/findings/1/assignee"),
        ("get", "/analytics/summary"),
    ],
)
async def test_protected_endpoints_require_authentication(
    anon: AsyncClient, method: str, path: str
) -> None:
    response = await getattr(anon, method)(f"{API}{path}")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_TOKEN"
