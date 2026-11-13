"""Общие данные и помощники для тестов."""

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from httpx import AsyncClient
from sqlalchemy.orm import Session, sessionmaker

from app.core.time import utcnow
from app.models.asset import Asset
from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.models.vulnerability import Vulnerability
from app.services import findings as findings_service

API = "/api/v1"

V_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
V_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"  # 5.4
V_LOW = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"  # 1.6
V_NONE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # 0.0


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class World:
    """Небольшой набор данных, созданный через API."""

    groups: dict[str, int] = field(default_factory=dict)
    assets: dict[str, int] = field(default_factory=dict)
    vulns: dict[str, int] = field(default_factory=dict)


async def build_world(analyst: AsyncClient, user_ids: dict[str, int]) -> World:
    """Группы IT-INFRA и OFFICE; активы a1 (low, owner1), a2 (high, owner1),
    a3 (critical, owner2); уязвимости v_crit (9.8), v_med (5.4), v_low (1.6)."""
    world = World()
    for name, code in (("Серверная инфраструктура", "IT-INFRA"), ("Офис", "OFFICE")):
        response = await analyst.post(f"{API}/asset-groups", json={"name": name, "code": code})
        assert response.status_code == 201, response.text
        world.groups[code] = response.json()["id"]

    assets: list[tuple[str, str, str, str, str]] = [
        ("a1", "srv-low-01", "low", "owner1", "IT-INFRA"),
        ("a2", "srv-high-01", "high", "owner1", "IT-INFRA"),
        ("a3", "srv-crit-01", "critical", "owner2", "OFFICE"),
    ]
    for key, hostname, criticality, owner, group in assets:
        response = await analyst.post(
            f"{API}/assets",
            json={
                "name": f"Актив {key}",
                "hostname": hostname,
                "ip_address": "10.0.0.1",
                "asset_type": "server",
                "criticality": criticality,
                "group_id": world.groups[group],
                "owner_id": user_ids[owner],
            },
        )
        assert response.status_code == 201, response.text
        world.assets[key] = response.json()["id"]

    vulns = [
        ("v_crit", "CVE-2026-10001", V_CRITICAL),
        ("v_med", "CVE-2026-10002", V_MEDIUM),
        ("v_low", "CVE-2026-10003", V_LOW),
    ]
    for key, cve, vector in vulns:
        response = await analyst.post(
            f"{API}/vulnerabilities",
            json={"cve_id": cve, "title": f"Уязвимость {key}", "cvss_vector": vector},
        )
        assert response.status_code == 201, response.text
        world.vulns[key] = response.json()["id"]
    return world


def insert_finding(
    session_factory: sessionmaker[Session],
    asset_id: int,
    vuln_id: int,
    *,
    status: FindingStatus = FindingStatus.new,
    days_ago: int = 0,
    **extra: Any,
) -> int:
    """Создаёт обнаружение напрямую в БД с заданным возрастом и статусом."""
    with session_factory() as session:
        asset = session.get(Asset, asset_id)
        vuln = session.get(Vulnerability, vuln_id)
        assert asset is not None and vuln is not None
        finding, _ = findings_service.register_detection(
            session, asset, vuln, now=utcnow() - timedelta(days=days_ago)
        )
        finding.status = status
        for name, value in extra.items():
            setattr(finding, name, value)
        session.commit()
        return finding.id


def get_finding(session_factory: sessionmaker[Session], finding_id: int) -> Finding:
    with session_factory() as session:
        finding = session.get(Finding, finding_id)
        assert finding is not None
        return finding
