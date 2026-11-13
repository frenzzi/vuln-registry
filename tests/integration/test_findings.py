import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import FindingStatus
from tests.conftest import Accounts
from tests.helpers import API, World, build_world, get_finding, insert_finding


@pytest.fixture
async def world(analyst: AsyncClient, accounts: Accounts) -> World:
    return await build_world(analyst, accounts.ids)


async def create_finding(
    client: AsyncClient, world: World, asset: str = "a2", vuln: str = "v_crit"
):
    return await client.post(
        f"{API}/findings",
        json={"asset_id": world.assets[asset], "vulnerability_id": world.vulns[vuln]},
    )


async def set_status(client: AsyncClient, finding_id: int, status: str, comment: str | None = None):
    body: dict[str, object] = {"status": status}
    if comment is not None:
        body["resolution_comment"] = comment
    return await client.patch(f"{API}/findings/{finding_id}/status", json=body)


async def test_full_lifecycle_over_http(analyst: AsyncClient, world: World) -> None:
    created = await create_finding(analyst, world)
    assert created.status_code == 201
    finding = created.json()
    assert created.headers["Location"] == f"{API}/findings/{finding['id']}"
    assert finding["status"] == "new"
    assert finding["detection_count"] == 1
    assert finding["risk_score"] == 9.8  # 9.8 на активе high
    assert finding["risk_level"] == "critical"
    assert finding["is_overdue"] is False
    fid = finding["id"]

    assert (await set_status(analyst, fid, "confirmed")).json()["status"] == "confirmed"
    assert (await set_status(analyst, fid, "in_progress")).json()["status"] == "in_progress"
    fixed = await set_status(analyst, fid, "fixed", "Обновлён пакет до версии 1.25.3")
    assert fixed.status_code == 200
    assert fixed.json()["resolution_comment"] == "Обновлён пакет до версии 1.25.3"
    assert fixed.json()["closed_at"] is None
    closed = await set_status(analyst, fid, "closed")
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"].endswith("Z")

    card = (await analyst.get(f"{API}/findings/{fid}")).json()
    assert card["status"] == "closed"
    assert card["asset"]["id"] == world.assets["a2"]
    assert card["vulnerability"]["cve_id"] == "CVE-2026-10001"


async def test_other_paths_through_the_state_machine(analyst: AsyncClient, world: World) -> None:
    # new → false_positive → closed
    first = (await create_finding(analyst, world, "a1", "v_med")).json()["id"]
    assert (await set_status(analyst, first, "false_positive")).status_code == 200
    assert (await set_status(analyst, first, "closed")).status_code == 200

    # fixed → confirmed («проверка не подтвердила устранение»), затем снова вперёд
    second = (await create_finding(analyst, world, "a1", "v_low")).json()["id"]
    for status, comment in (
        ("confirmed", None),
        ("in_progress", None),
        ("fixed", "Применён патч поставщика"),
    ):
        assert (await set_status(analyst, second, status, comment)).status_code == 200
    assert (await set_status(analyst, second, "confirmed")).json()["status"] == "confirmed"
    assert (await set_status(analyst, second, "in_progress")).status_code == 200


async def test_forbidden_transitions_return_409_with_allowed(
    analyst: AsyncClient, world: World, session_factory: sessionmaker[Session]
) -> None:
    new_id = (await create_finding(analyst, world)).json()["id"]
    closed_id = insert_finding(
        session_factory, world.assets["a1"], world.vulns["v_crit"], status=FindingStatus.closed
    )

    to_closed = await set_status(analyst, new_id, "closed")
    assert to_closed.status_code == 409
    error = to_closed.json()["error"]
    assert error["code"] == "FINDING_INVALID_STATUS_TRANSITION"
    assert error["details"]["allowed"] == ["confirmed", "false_positive"]

    same = await set_status(analyst, new_id, "new")
    assert same.status_code == 409

    terminal = await set_status(analyst, closed_id, "confirmed")
    assert terminal.status_code == 409
    assert terminal.json()["error"]["details"]["allowed"] == []

    assert (await analyst.get(f"{API}/findings/{new_id}")).json()["status"] == "new"
    assert (await set_status(analyst, new_id, "archived")).status_code == 422


async def test_fixed_requires_resolution_comment(
    analyst: AsyncClient, world: World, session_factory: sessionmaker[Session]
) -> None:
    fid = insert_finding(
        session_factory, world.assets["a2"], world.vulns["v_crit"], status=FindingStatus.in_progress
    )
    for comment in (None, "коротко"):
        response = await set_status(analyst, fid, "fixed", comment)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "FINDING_RESOLUTION_COMMENT_REQUIRED"
    assert get_finding(session_factory, fid).status == FindingStatus.in_progress
    assert (
        await set_status(analyst, fid, "fixed", "Достаточно длинный комментарий")
    ).status_code == 200


async def test_deduplication_increments_counter_instead_of_creating(
    analyst: AsyncClient, admin: AsyncClient, world: World
) -> None:
    first = await create_finding(analyst, world)
    assert first.status_code == 201
    fid = first.json()["id"]
    await set_status(analyst, fid, "confirmed")

    second = await create_finding(analyst, world)
    assert second.status_code == 200
    assert "Location" not in second.headers
    body = second.json()
    assert body["id"] == fid
    assert body["detection_count"] == 2
    assert body["status"] == "confirmed"
    assert body["first_detected_at"] == first.json()["first_detected_at"]
    assert body["last_detected_at"] >= first.json()["last_detected_at"]
    assert body["due_date"] == first.json()["due_date"]
    assert (await admin.get(f"{API}/findings")).json()["total"] == 1

    # После закрытия возвращённая уязвимость создаёт новое обнаружение, старое не трогается
    for status, comment in (
        ("in_progress", None),
        ("fixed", "Исправлено обновлением"),
        ("closed", None),
    ):
        await set_status(analyst, fid, status, comment)
    again = await create_finding(analyst, world)
    assert again.status_code == 201
    assert again.json()["id"] != fid
    assert again.json()["detection_count"] == 1
    assert (await admin.get(f"{API}/findings")).json()["total"] == 2
    assert (await admin.get(f"{API}/findings/{fid}")).json()["status"] == "closed"


async def test_redetection_after_false_positive_creates_new_finding(
    analyst: AsyncClient, world: World
) -> None:
    fid = (await create_finding(analyst, world)).json()["id"]
    await set_status(analyst, fid, "false_positive")
    again = await create_finding(analyst, world)
    assert again.status_code == 201
    assert again.json()["id"] != fid


async def test_create_finding_validates_references(analyst: AsyncClient, world: World) -> None:
    for body, field in (
        ({"asset_id": 99999, "vulnerability_id": world.vulns["v_crit"]}, "asset_id"),
        ({"asset_id": world.assets["a1"], "vulnerability_id": 99999}, "vulnerability_id"),
    ):
        response = await analyst.post(f"{API}/findings", json=body)
        assert response.status_code == 422
        assert response.json()["error"]["details"]["field"] == field


async def test_import_is_partial_on_unknown_cve(
    analyst: AsyncClient, admin: AsyncClient, world: World
) -> None:
    payload = {
        "items": [
            {"asset_id": world.assets["a1"], "cve_id": "CVE-2026-10001"},
            {"asset_id": world.assets["a2"], "cve_id": "cve-2026-10002"},  # регистр не важен
            {"asset_id": world.assets["a1"], "cve_id": "CVE-1999-99999"},
            {"asset_id": 99999, "cve_id": "CVE-2026-10001"},
            {
                "asset_id": world.assets["a1"],
                "cve_id": "CVE-2026-10001",
            },  # повтор в этой же загрузке
        ]
    }
    response = await analyst.post(f"{API}/findings/import", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert (body["created"], body["updated"]) == (2, 1)
    assert [(e["index"], e["code"]) for e in body["errors"]] == [
        (2, "VULN_NOT_FOUND"),
        (3, "ASSET_NOT_FOUND"),
    ]
    listing = await admin.get(f"{API}/findings")
    assert listing.json()["total"] == 2
    counts = {f["asset_id"]: f["detection_count"] for f in listing.json()["items"]}
    assert counts[world.assets["a1"]] == 2

    too_many = {"items": [{"asset_id": 1, "cve_id": "CVE-2026-1000"}] * 1001}
    assert (await analyst.post(f"{API}/findings/import", json=too_many)).status_code == 422


async def test_overdue_filter_and_flag(
    analyst: AsyncClient, world: World, session_factory: sessionmaker[Session]
) -> None:
    # 9.8 на critical → риск 10.0, срок 7 дней
    overdue = insert_finding(
        session_factory, world.assets["a3"], world.vulns["v_crit"],
        status=FindingStatus.confirmed, days_ago=30,
    )  # fmt: skip
    insert_finding(
        session_factory, world.assets["a3"], world.vulns["v_med"],
        status=FindingStatus.fixed, days_ago=300,
    )  # fmt: skip
    insert_finding(session_factory, world.assets["a3"], world.vulns["v_low"], days_ago=1)

    only_overdue = await analyst.get(f"{API}/findings", params={"overdue": "true"})
    assert [f["id"] for f in only_overdue.json()["items"]] == [overdue]
    assert only_overdue.json()["items"][0]["is_overdue"] is True

    not_overdue = await analyst.get(f"{API}/findings", params={"overdue": "false"})
    assert overdue not in {f["id"] for f in not_overdue.json()["items"]}
    assert not_overdue.json()["total"] == 2
    assert all(f["is_overdue"] is False for f in not_overdue.json()["items"])


async def test_assignee_set_clear_and_validate(
    analyst: AsyncClient, admin: AsyncClient, world: World, accounts: Accounts
) -> None:
    fid = (await create_finding(analyst, world)).json()["id"]
    url = f"{API}/findings/{fid}/assignee"

    assigned = await analyst.patch(url, json={"assignee_id": accounts.ids["owner1"]})
    assert assigned.status_code == 200
    assert assigned.json()["assignee_id"] == accounts.ids["owner1"]
    by_assignee = await analyst.get(
        f"{API}/findings", params={"assignee_id": accounts.ids["owner1"]}
    )
    assert by_assignee.json()["total"] == 1

    cleared = await analyst.patch(url, json={"assignee_id": None})
    assert cleared.status_code == 200
    assert cleared.json()["assignee_id"] is None

    missing = await analyst.patch(url, json={"assignee_id": 99999})
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "FINDING_ASSIGNEE_INVALID"

    await admin.patch(f"{API}/users/{accounts.ids['owner2']}", json={"is_active": False})
    inactive = await analyst.patch(url, json={"assignee_id": accounts.ids["owner2"]})
    assert inactive.status_code == 422

    assert (
        await analyst.patch(f"{API}/findings/99999/assignee", json={"assignee_id": None})
    ).status_code == 404
    assert (await analyst.patch(url, json={})).status_code == 422


async def test_list_filters_and_sorting(
    analyst: AsyncClient, world: World, session_factory: sessionmaker[Session]
) -> None:
    f_crit = insert_finding(session_factory, world.assets["a1"], world.vulns["v_crit"], days_ago=3)
    f_med = insert_finding(
        session_factory, world.assets["a3"], world.vulns["v_med"],
        status=FindingStatus.confirmed, days_ago=2,
    )  # fmt: skip
    f_low = insert_finding(session_factory, world.assets["a2"], world.vulns["v_low"], days_ago=1)

    def ids(response) -> list[int]:
        return [f["id"] for f in response.json()["items"]]

    assert ids(await analyst.get(f"{API}/findings", params={"status": "confirmed"})) == [f_med]
    assert ids(await analyst.get(f"{API}/findings", params={"asset_id": world.assets["a2"]})) == [
        f_low
    ]
    by_group = await analyst.get(f"{API}/findings", params={"group_id": world.groups["OFFICE"]})
    assert ids(by_group) == [f_med]
    by_cve = await analyst.get(f"{API}/findings", params={"cve_id": "cve-2026-10001"})
    assert ids(by_cve) == [f_crit]
    by_level = await analyst.get(f"{API}/findings", params={"risk_level": "medium"})
    assert f_crit in ids(by_level)  # 9.8 на low → 4.9 medium

    by_risk = await analyst.get(f"{API}/findings", params={"sort": "-risk_score"})
    scores = [f["risk_score"] for f in by_risk.json()["items"]]
    assert scores == sorted(scores, reverse=True)
    by_age = await analyst.get(f"{API}/findings", params={"sort": "first_detected_at"})
    assert ids(by_age) == [f_crit, f_med, f_low]
    assert (await analyst.get(f"{API}/findings", params={"sort": "asset_id"})).status_code == 422
    assert (await analyst.get(f"{API}/findings", params={"status": "bogus"})).status_code == 422


async def test_analytics_summary(
    analyst: AsyncClient, world: World, session_factory: sessionmaker[Session]
) -> None:
    insert_finding(
        session_factory, world.assets["a3"], world.vulns["v_crit"], days_ago=30
    )  # просрочено
    insert_finding(
        session_factory, world.assets["a2"], world.vulns["v_med"], status=FindingStatus.confirmed
    )
    insert_finding(
        session_factory, world.assets["a2"], world.vulns["v_low"], status=FindingStatus.fixed
    )
    insert_finding(
        session_factory, world.assets["a1"], world.vulns["v_low"], status=FindingStatus.closed
    )

    body = (await analyst.get(f"{API}/analytics/summary")).json()
    assert body["assets_total"] == 3
    assert body["findings_by_status"] == {
        "new": 1,
        "confirmed": 1,
        "in_progress": 0,
        "fixed": 1,
        "false_positive": 0,
        "closed": 1,
    }
    assert sum(body["findings_by_risk_level"].values()) == 2  # только неустранённые
    assert body["findings_overdue"] == 1
    scores = [f["risk_score"] for f in body["top_risk_findings"]]
    assert scores == sorted(scores, reverse=True)
    assert len(body["top_risk_findings"]) == 2
