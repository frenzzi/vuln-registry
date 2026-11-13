from datetime import date, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session, sessionmaker

from tests.conftest import Accounts
from tests.helpers import (
    API,
    V_CRITICAL,
    V_LOW,
    V_MEDIUM,
    V_NONE,
    World,
    build_world,
    insert_finding,
)


@pytest.fixture
async def world(analyst: AsyncClient, accounts: Accounts) -> World:
    return await build_world(analyst, accounts.ids)


def vuln(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "cve_id": "CVE-2026-10001",
        "title": "Тестовая уязвимость",
        "cvss_vector": V_CRITICAL,
    }
    body.update(overrides)
    return body


async def test_server_calculates_score_and_severity(analyst: AsyncClient) -> None:
    response = await analyst.post(f"{API}/vulnerabilities", json=vuln())
    assert response.status_code == 201
    body = response.json()
    assert response.headers["Location"] == f"{API}/vulnerabilities/{body['id']}"
    assert body["cvss_base_score"] == 9.8
    assert body["cvss_severity"] == "critical"


async def test_client_supplied_score_is_ignored(analyst: AsyncClient) -> None:
    response = await analyst.post(
        f"{API}/vulnerabilities",
        json=vuln(cvss_vector=V_LOW, cvss_base_score=10.0, cvss_severity="critical"),
    )
    assert response.status_code == 201
    assert response.json()["cvss_base_score"] == 1.6
    assert response.json()["cvss_severity"] == "low"


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "",
    ],
)
async def test_invalid_vector_is_rejected(analyst: AsyncClient, vector: str) -> None:
    response = await analyst.post(f"{API}/vulnerabilities", json=vuln(cvss_vector=vector))
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VULN_INVALID_CVSS_VECTOR"
    assert error["details"]["metric"]
    assert (await analyst.get(f"{API}/vulnerabilities")).json()["total"] == 0


async def test_other_field_validation(analyst: AsyncClient) -> None:
    tomorrow = (date.today() + timedelta(days=2)).isoformat()
    cases = [
        vuln(cve_id="CVE-26-1"),
        vuln(cve_id="CVE-٢٠٢٦-١٢٣٤"),  # арабо-индийские цифры не проходят
        vuln(cve_id=None, bdu_id="BDU:2026-1"),
        vuln(cve_id=None),  # нет ни одного идентификатора
        vuln(title="abc"),
        vuln(cwe_id="CWE-ABC"),
        vuln(published_date=tomorrow),
    ]
    for body in cases:
        response = await analyst.post(f"{API}/vulnerabilities", json=body)
        assert response.status_code == 422, body
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    ok = await analyst.post(
        f"{API}/vulnerabilities",
        json=vuln(
            cve_id=None, bdu_id="BDU:2026-00001", cwe_id="CWE-79", published_date="2026-01-31"
        ),
    )
    assert ok.status_code == 201
    assert ok.json()["bdu_id"] == "BDU:2026-00001"


async def test_duplicates_and_delete_with_findings(
    analyst: AsyncClient,
    admin: AsyncClient,
    world: World,
    session_factory: sessionmaker[Session],
) -> None:
    duplicate = await analyst.post(f"{API}/vulnerabilities", json=vuln(cve_id="CVE-2026-10001"))
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "VULN_CVE_TAKEN"

    first = await analyst.post(
        f"{API}/vulnerabilities", json=vuln(cve_id=None, bdu_id="BDU:2026-00007")
    )
    assert first.status_code == 201
    second = await analyst.post(
        f"{API}/vulnerabilities", json=vuln(cve_id="CVE-2026-55555", bdu_id="BDU:2026-00007")
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "VULN_BDU_TAKEN"

    insert_finding(session_factory, world.assets["a1"], world.vulns["v_crit"])
    blocked = await admin.delete(f"{API}/vulnerabilities/{world.vulns['v_crit']}")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "VULN_HAS_FINDINGS"
    assert (await admin.get(f"{API}/vulnerabilities/{world.vulns['v_crit']}")).status_code == 200

    free = await admin.delete(f"{API}/vulnerabilities/{world.vulns['v_low']}")
    assert free.status_code == 204
    assert (await admin.get(f"{API}/vulnerabilities/{world.vulns['v_low']}")).status_code == 404


async def test_vector_change_recalculates_related_findings(
    analyst: AsyncClient,
    world: World,
    session_factory: sessionmaker[Session],
) -> None:
    vuln_id = world.vulns["v_med"]  # 5.4
    finding_ids = {
        key: insert_finding(session_factory, world.assets[key], vuln_id, days_ago=1)
        for key in ("a1", "a2", "a3")  # low, high, critical
    }
    before = {
        key: (await analyst.get(f"{API}/findings/{fid}")).json() for key, fid in finding_ids.items()
    }
    assert {k: v["risk_score"] for k, v in before.items()} == {"a1": 2.7, "a2": 5.4, "a3": 6.8}

    patched = await analyst.patch(
        f"{API}/vulnerabilities/{vuln_id}", json={"cvss_vector": V_CRITICAL}
    )
    assert patched.status_code == 200
    assert patched.json()["cvss_base_score"] == 9.8
    assert patched.json()["cvss_severity"] == "critical"

    after = {
        key: (await analyst.get(f"{API}/findings/{fid}")).json() for key, fid in finding_ids.items()
    }
    assert {k: v["risk_score"] for k, v in after.items()} == {"a1": 4.9, "a2": 9.8, "a3": 10.0}
    assert {k: v["risk_level"] for k, v in after.items()} == {
        "a1": "medium",
        "a2": "critical",
        "a3": "critical",
    }
    # Срок пересчитан по новому уровню риска, но от первого обнаружения
    assert before["a2"]["first_detected_at"] == after["a2"]["first_detected_at"]
    assert before["a2"]["due_date"] != after["a2"]["due_date"]

    bad = await analyst.patch(
        f"{API}/vulnerabilities/{vuln_id}", json={"cvss_vector": "CVSS:3.1/AV:N"}
    )
    assert bad.status_code == 422
    assert (await analyst.get(f"{API}/vulnerabilities/{vuln_id}")).json()["cvss_base_score"] == 9.8


async def test_patch_other_fields_and_uniqueness(analyst: AsyncClient, world: World) -> None:
    url = f"{API}/vulnerabilities/{world.vulns['v_low']}"
    changed = await analyst.patch(url, json={"title": "Новое название", "cwe_id": "CWE-200"})
    assert changed.status_code == 200
    assert changed.json()["title"] == "Новое название"
    assert changed.json()["cvss_base_score"] == 1.6

    clash = await analyst.patch(url, json={"cve_id": "CVE-2026-10001"})
    assert clash.status_code == 409
    own = await analyst.patch(url, json={"cve_id": "CVE-2026-10003"})
    assert own.status_code == 200
    assert (
        await analyst.patch(f"{API}/vulnerabilities/99999", json={"title": "Нет такой"})
    ).status_code == 404


async def test_catalog_filters_sorting_and_detail(analyst: AsyncClient, world: World) -> None:
    all_items = await analyst.get(f"{API}/vulnerabilities")
    scores = [v["cvss_base_score"] for v in all_items.json()["items"]]
    assert scores == [9.8, 5.4, 1.6]  # по умолчанию — по убыванию балла

    high = await analyst.get(f"{API}/vulnerabilities", params={"min_score": 5, "max_score": 9})
    assert [v["cvss_base_score"] for v in high.json()["items"]] == [5.4]
    by_severity = await analyst.get(f"{API}/vulnerabilities", params={"severity": "low"})
    assert by_severity.json()["total"] == 1
    search = await analyst.get(f"{API}/vulnerabilities", params={"q": "cve-2026-10002"})
    assert search.json()["total"] == 1
    ascending = await analyst.get(f"{API}/vulnerabilities", params={"sort": "cve_id"})
    ids = [v["cve_id"] for v in ascending.json()["items"]]
    assert ids == sorted(ids)
    assert (
        await analyst.get(f"{API}/vulnerabilities", params={"sort": "title"})
    ).status_code == 422
    assert (
        await analyst.get(f"{API}/vulnerabilities", params={"min_score": 11})
    ).status_code == 422

    detail = await analyst.get(f"{API}/vulnerabilities/{world.vulns['v_med']}")
    body = detail.json()
    assert body["findings_count"] == 0
    assert body["cvss"]["base_score"] == 5.4
    assert body["cvss"]["metrics"]["UI"] == "R"


async def test_cvss_calculator(analyst: AsyncClient, owner1: AsyncClient) -> None:
    for client in (analyst, owner1):
        response = await client.post(f"{API}/cvss/calculate", json={"vector": V_MEDIUM})
        assert response.status_code == 200
        body = response.json()
        assert (body["base_score"], body["severity"]) == (5.4, "medium")
        assert set(body) == {"base_score", "severity", "impact", "exploitability", "metrics"}

    none = await analyst.post(f"{API}/cvss/calculate", json={"vector": V_NONE})
    assert (none.json()["base_score"], none.json()["severity"]) == (0.0, "none")

    bad = await analyst.post(f"{API}/cvss/calculate", json={"vector": "CVSS:3.1/AV:N"})
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "VULN_INVALID_CVSS_VECTOR"
