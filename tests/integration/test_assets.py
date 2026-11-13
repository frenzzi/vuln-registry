from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import FindingStatus
from tests.conftest import Accounts
from tests.helpers import API, World, build_world, get_finding, insert_finding


@pytest.fixture
async def world(analyst: AsyncClient, accounts: Accounts) -> World:
    return await build_world(analyst, accounts.ids)


def asset_body(world: World, accounts: Accounts, **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": "Тестовый сервер",
        "hostname": "srv-test-01",
        "ip_address": "192.168.1.10",
        "asset_type": "server",
        "group_id": world.groups["IT-INFRA"],
        "owner_id": accounts.ids["owner1"],
    }
    body.update(overrides)
    return body


async def test_asset_crud(
    analyst: AsyncClient, admin: AsyncClient, world: World, accounts: Accounts
) -> None:
    created = await analyst.post(f"{API}/assets", json=asset_body(world, accounts))
    assert created.status_code == 201
    asset = created.json()
    assert created.headers["Location"] == f"{API}/assets/{asset['id']}"
    assert asset["criticality"] == "medium"
    assert asset["is_active"] is True

    card = await analyst.get(f"{API}/assets/{asset['id']}")
    assert card.status_code == 200
    assert card.json()["group_code"] == "IT-INFRA"
    assert card.json()["findings_by_risk_level"] == {
        "none": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }

    updated = await analyst.patch(
        f"{API}/assets/{asset['id']}",
        json={"name": "Переименованный сервер", "ip_address": "::1", "description": "Описание"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Переименованный сервер"
    assert updated.json()["ip_address"] == "::1"
    assert updated.json()["updated_at"] >= asset["updated_at"]

    cleared = await analyst.patch(f"{API}/assets/{asset['id']}", json={"description": None})
    assert cleared.json()["description"] is None

    assert (await admin.delete(f"{API}/assets/{asset['id']}")).status_code == 204
    after = await admin.get(f"{API}/assets/{asset['id']}")
    assert after.status_code == 200
    assert after.json()["is_active"] is False
    assert (await admin.get(f"{API}/assets/999999")).status_code == 404


async def test_asset_validation_and_references(
    analyst: AsyncClient, world: World, accounts: Accounts
) -> None:
    bad_ip = await analyst.post(
        f"{API}/assets", json=asset_body(world, accounts, ip_address="999.1.1.1")
    )
    assert bad_ip.status_code == 422
    assert bad_ip.json()["error"]["details"]["errors"][0]["field"] == "ip_address"

    for field, value in (("group_id", 99999), ("owner_id", 99999)):
        response = await analyst.post(
            f"{API}/assets", json=asset_body(world, accounts, **{field: value})
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "REFERENCE_NOT_FOUND"
        assert response.json()["error"]["details"]["field"] == field

    too_long = await analyst.post(
        f"{API}/assets", json=asset_body(world, accounts, name="x" * 10_000)
    )
    assert too_long.status_code == 422

    bad_type = await analyst.post(
        f"{API}/assets", json=asset_body(world, accounts, asset_type="toaster")
    )
    assert bad_type.status_code == 422


async def test_asset_list_filters_pagination_and_sorting(
    analyst: AsyncClient, world: World, accounts: Accounts
) -> None:
    listing = await analyst.get(f"{API}/assets")
    assert set(listing.json()) == {"items", "total", "limit", "offset"}
    assert listing.json()["total"] == 3

    critical = await analyst.get(f"{API}/assets", params={"criticality": "critical"})
    assert [a["hostname"] for a in critical.json()["items"]] == ["srv-crit-01"]

    by_group = await analyst.get(f"{API}/assets", params={"group_id": world.groups["OFFICE"]})
    assert by_group.json()["total"] == 1

    search = await analyst.get(f"{API}/assets", params={"q": "HIGH"})
    assert [a["hostname"] for a in search.json()["items"]] == ["srv-high-01"]
    percent = await analyst.get(f"{API}/assets", params={"q": "%"})
    assert percent.json()["total"] == 0  # символы шаблона LIKE экранируются

    first = await analyst.get(f"{API}/assets", params={"limit": 2, "offset": 0})
    second = await analyst.get(f"{API}/assets", params={"limit": 2, "offset": 2})
    ids = [a["id"] for a in first.json()["items"]] + [a["id"] for a in second.json()["items"]]
    assert len(ids) == len(set(ids)) == 3
    assert first.json()["total"] == second.json()["total"] == 3

    by_criticality = await analyst.get(f"{API}/assets", params={"sort": "-criticality"})
    assert [a["criticality"] for a in by_criticality.json()["items"]] == ["critical", "high", "low"]
    by_name = await analyst.get(f"{API}/assets", params={"sort": "name"})
    names = [a["name"] for a in by_name.json()["items"]]
    assert names == sorted(names)

    bad_sort = await analyst.get(f"{API}/assets", params={"sort": "hashed_password"})
    assert bad_sort.status_code == 422
    assert bad_sort.json()["error"]["code"] == "INVALID_SORT_FIELD"
    assert "name" in bad_sort.json()["error"]["details"]["allowed"]


async def test_pagination_bounds(analyst: AsyncClient, world: World) -> None:
    for params in ({"limit": 0}, {"limit": 101}, {"limit": -1}, {"limit": "abc"}, {"offset": -5}):
        response = await analyst.get(f"{API}/assets", params=params)
        assert response.status_code == 422, params
    far = await analyst.get(f"{API}/assets", params={"offset": 100000})
    assert far.status_code == 200
    assert far.json()["items"] == []
    assert far.json()["total"] == 3


async def test_hostname_unique_within_group(
    analyst: AsyncClient, world: World, accounts: Accounts
) -> None:
    assert (
        await analyst.post(f"{API}/assets", json=asset_body(world, accounts))
    ).status_code == 201

    duplicate = await analyst.post(f"{API}/assets", json=asset_body(world, accounts))
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "ASSET_HOSTNAME_TAKEN"

    other_group = await analyst.post(
        f"{API}/assets", json=asset_body(world, accounts, group_id=world.groups["OFFICE"])
    )
    assert other_group.status_code == 201

    # Перенос в группу, где такой hostname уже есть, тоже конфликт
    moved = await analyst.patch(
        f"{API}/assets/{other_group.json()['id']}", json={"group_id": world.groups["IT-INFRA"]}
    )
    assert moved.status_code == 409

    no_hostname = {"hostname": None}
    assert (
        await analyst.post(f"{API}/assets", json=asset_body(world, accounts, **no_hostname))
    ).status_code == 201
    assert (
        await analyst.post(f"{API}/assets", json=asset_body(world, accounts, **no_hostname))
    ).status_code == 201


async def test_soft_delete_closes_findings(
    admin: AsyncClient,
    world: World,
    session_factory: sessionmaker[Session],
) -> None:
    asset = world.assets["a2"]
    open_ids = [
        insert_finding(session_factory, asset, world.vulns["v_crit"]),
        insert_finding(session_factory, asset, world.vulns["v_med"], status=FindingStatus.fixed),
    ]
    marked = insert_finding(
        session_factory, asset, world.vulns["v_low"], status=FindingStatus.false_positive
    )

    assert (await admin.delete(f"{API}/assets/{asset}")).status_code == 204

    listing = await admin.get(f"{API}/findings", params={"asset_id": asset})
    assert listing.json()["total"] == 3
    assert {f["status"] for f in listing.json()["items"]} == {"closed"}
    for finding_id in [*open_ids, marked]:
        assert get_finding(session_factory, finding_id).closed_at is not None

    # Нового обнаружения на выведенном из учёта активе не создать
    response = await admin.post(
        f"{API}/findings", json={"asset_id": asset, "vulnerability_id": world.vulns["v_crit"]}
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ASSET_INACTIVE"


async def test_criticality_change_recalculates_risk_and_due_date(
    analyst: AsyncClient,
    world: World,
    session_factory: sessionmaker[Session],
) -> None:
    # a1 — low, уязвимость 9.8: риск 4.9 (medium), срок 90 дней
    finding_id = insert_finding(
        session_factory, world.assets["a1"], world.vulns["v_crit"], days_ago=10
    )
    before = (await analyst.get(f"{API}/findings/{finding_id}")).json()
    assert (before["risk_score"], before["risk_level"]) == (4.9, "medium")

    changed = await analyst.patch(
        f"{API}/assets/{world.assets['a1']}", json={"criticality": "critical"}
    )
    assert changed.status_code == 200
    assert changed.json()["findings_by_risk_level"]["critical"] == 1

    after = (await analyst.get(f"{API}/findings/{finding_id}")).json()
    assert (after["risk_score"], after["risk_level"]) == (10.0, "critical")
    first_detected = get_finding(session_factory, finding_id).first_detected_at
    assert after["due_date"] == (first_detected + timedelta(days=7)).date().isoformat()
    assert after["is_overdue"] is True  # 10 дней назад + 7 дней SLA


async def test_asset_groups(
    analyst: AsyncClient, admin: AsyncClient, owner1: AsyncClient, world: World
) -> None:
    listing = await analyst.get(f"{API}/asset-groups")
    counts = {g["code"]: g["assets_count"] for g in listing.json()["items"]}
    assert counts == {"IT-INFRA": 2, "OFFICE": 1}

    # Владелец видит число только своих активов
    own = await owner1.get(f"{API}/asset-groups")
    assert {g["code"]: g["assets_count"] for g in own.json()["items"]} == {
        "IT-INFRA": 2,
        "OFFICE": 0,
    }

    duplicate_name = await analyst.post(f"{API}/asset-groups", json={"name": "Офис", "code": "NEW"})
    assert duplicate_name.status_code == 409
    assert duplicate_name.json()["error"]["code"] == "ASSET_GROUP_NAME_TAKEN"
    duplicate_code = await analyst.post(
        f"{API}/asset-groups", json={"name": "Новая", "code": "OFFICE"}
    )
    assert duplicate_code.status_code == 409
    assert duplicate_code.json()["error"]["code"] == "ASSET_GROUP_CODE_TAKEN"
    bad_code = await analyst.post(f"{API}/asset-groups", json={"name": "Новая", "code": "bad code"})
    assert bad_code.status_code == 422

    created = await analyst.post(f"{API}/asset-groups", json={"name": "Пустая", "code": "EMPTY"})
    assert created.status_code == 201
    assert created.headers["Location"].endswith(f"/asset-groups/{created.json()['id']}")

    not_empty = await admin.delete(f"{API}/asset-groups/{world.groups['IT-INFRA']}")
    assert not_empty.status_code == 409
    assert not_empty.json()["error"]["code"] == "ASSET_GROUP_NOT_EMPTY"
    assert (await admin.delete(f"{API}/asset-groups/{created.json()['id']}")).status_code == 204
    assert (await admin.delete(f"{API}/asset-groups/{created.json()['id']}")).status_code == 404
