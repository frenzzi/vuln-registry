"""Демо-данные. Запуск: python -m app.db.seed (после alembic upgrade head). Идемпотентно."""

import sys
from datetime import date, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.time import utcnow
from app.models.asset import Asset
from app.models.asset_group import AssetGroup
from app.models.enums import AssetType, Criticality, FindingStatus, Role
from app.models.finding import Finding
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services import cvss
from app.services import findings as findings_service
from app.services.users import create_user

# Пароли по умолчанию применяются только при APP_DEBUG=true.
DEBUG_PASSWORDS = {
    "admin": "Admin-Debug-2026",
    "analyst": "Analyst-Debug-2026",
    "owner1": "Owner1-Debug-2026",
    "owner2": "Owner2-Debug-2026",
}

USERS = [
    ("admin", "admin@example.com", "Администратор Системы", Role.admin),
    ("analyst", "analyst@example.com", "Аналитик Безопасности", Role.analyst),
    ("owner1", "owner1@example.com", "Владелец Первый", Role.owner),
    ("owner2", "owner2@example.com", "Владелец Второй", Role.owner),
]

GROUPS = [
    ("Серверная инфраструктура", "IT-INFRA"),
    ("Офисные рабочие места", "OFFICE"),
    ("Периметр и DMZ", "DMZ"),
]

# hostname, название, тип, критичность, группа, владелец
ASSETS = [
    ("srv-db-01", "Сервер БД учёта", AssetType.database, Criticality.critical, "IT-INFRA", "owner1"),
    ("srv-web-01", "Веб-сервер портала", AssetType.server, Criticality.high, "DMZ", "owner1"),
    ("srv-file-01", "Файловый сервер", AssetType.server, Criticality.medium, "IT-INFRA", "owner1"),
    ("ws-acc-01", "АРМ бухгалтера", AssetType.workstation, Criticality.low, "OFFICE", "owner1"),
    ("sw-core-01", "Коммутатор ядра", AssetType.network_device, Criticality.high, "IT-INFRA", "owner1"),
    ("app-crm", "CRM-система", AssetType.application, Criticality.medium, "DMZ", "owner1"),
    ("srv-mail-01", "Почтовый сервер", AssetType.server, Criticality.high, "DMZ", "owner2"),
    ("ws-hr-01", "АРМ отдела кадров", AssetType.workstation, Criticality.low, "OFFICE", "owner2"),
    ("srv-db-02", "Сервер БД отчётности", AssetType.database, Criticality.critical, "IT-INFRA", "owner2"),
    ("fw-edge-01", "Пограничный межсетевой экран", AssetType.network_device, Criticality.critical, "DMZ", "owner2"),
]  # fmt: skip

# Векторы приближены к опубликованным, идентификаторы БДУ в демо-записях условные.
# cve_id, bdu_id, название, вектор, CWE, дата публикации
VULNERABILITIES = [
    ("CVE-2021-44228", "BDU:2021-05969", "Log4Shell: удалённое выполнение кода в Apache Log4j",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CWE-502", date(2021, 12, 10)),
    ("CVE-2019-0708", None, "BlueKeep: удалённое выполнение кода в службе RDP",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-416", date(2019, 5, 16)),
    ("CVE-2017-0144", "BDU:2017-00741", "EternalBlue: удалённое выполнение кода в SMBv1",
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-20", date(2017, 3, 16)),
    ("CVE-2022-0847", None, "Dirty Pipe: перезапись файлов, повышение привилегий в Linux",
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "CWE-665", date(2022, 3, 10)),
    ("CVE-2023-44487", "BDU:2023-06444", "HTTP/2 Rapid Reset: отказ в обслуживании",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "CWE-400", date(2023, 10, 10)),
    ("CVE-2014-0160", None, "Heartbleed: утечка памяти процесса OpenSSL",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-119", date(2014, 4, 7)),
    ("CVE-2020-11022", None, "Межсайтовый скриптинг в jQuery",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-79", date(2020, 4, 29)),
    (None, "BDU:2024-00101", "Хранимый XSS в веб-интерфейсе управления (демо-запись)",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-79", date(2024, 1, 15)),
    ("CVE-2015-4000", None, "Logjam: ослабление обмена ключами Диффи — Хеллмана",
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", "CWE-310", date(2015, 5, 20)),
    (None, "BDU:2024-00102", "Выход за пределы каталога в модуле выгрузки (демо-запись)",
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", "CWE-22", date(2024, 2, 1)),
    (None, "BDU:2024-00103", "Утечка фрагмента данных через временный файл (демо-запись)",
     "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "CWE-377", date(2024, 3, 5)),
    (None, "BDU:2024-00104", "Раскрытие версии службы в баннере (информационная, демо-запись)",
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "CWE-200", date(2024, 3, 6)),
]  # fmt: skip

# hostname актива, ключ уязвимости (cve или bdu), статус, дней назад, исполнитель, комментарий
FINDINGS = [
    ("ws-acc-01", "CVE-2019-0708", FindingStatus.confirmed, 12, None, None),
    ("srv-db-01", "CVE-2021-44228", FindingStatus.new, 2, None, None),
    ("srv-web-01", "CVE-2017-0144", FindingStatus.confirmed, 45, "analyst", None),  # просрочено
    ("app-crm", "CVE-2022-0847", FindingStatus.fixed, 100, "owner1", "Обновлено ядро до 5.16.11"),
    ("srv-file-01", "BDU:2024-00104", FindingStatus.new, 5, None, None),
    ("srv-file-01", "BDU:2024-00103", FindingStatus.new, 6, None, None),
    ("srv-db-01", "BDU:2024-00101", FindingStatus.new, 3, None, None),
    ("srv-web-01", "BDU:2024-00101", FindingStatus.confirmed, 4, None, None),
    ("app-crm", "BDU:2024-00101", FindingStatus.new, 1, None, None),
    ("ws-hr-01", "CVE-2020-11022", FindingStatus.new, 3, None, None),
    ("srv-mail-01", "CVE-2014-0160", FindingStatus.in_progress, 8, "owner2", None),
    ("srv-db-02", "CVE-2023-44487", FindingStatus.confirmed, 4, "analyst", None),
    ("fw-edge-01", "CVE-2015-4000", FindingStatus.closed, 60, None, "Отключены экспортные шифры"),
    ("sw-core-01", "CVE-2014-0160", FindingStatus.false_positive, 20, None, "Узел не использует OpenSSL"),
]  # fmt: skip


def _passwords(settings: Settings) -> dict[str, str]:
    configured = {
        "admin": settings.seed_admin_password,
        "analyst": settings.seed_analyst_password,
        "owner1": settings.seed_owner1_password,
        "owner2": settings.seed_owner2_password,
    }
    result: dict[str, str] = {}
    for username, value in configured.items():
        if value:
            result[username] = value
        elif settings.debug:
            result[username] = DEBUG_PASSWORDS[username]
        else:
            raise SystemExit(
                f"Не задан пароль для {username}: укажите SEED_{username.upper()}_PASSWORD "
                "(значения по умолчанию действуют только при APP_DEBUG=true)"
            )
    return result


def seed_users(db: Session, passwords: dict[str, str]) -> dict[str, User]:
    users: dict[str, User] = {}
    for username, email, full_name, role in USERS:
        user = db.scalars(select(User).where(User.username == username)).first()
        if user is None:
            user = create_user(
                db,
                username=username,
                email=email,
                full_name=full_name,
                password=passwords[username],
                role=role,
            )
        users[username] = user
    return users


def seed_groups(db: Session) -> dict[str, AssetGroup]:
    groups: dict[str, AssetGroup] = {}
    for name, code in GROUPS:
        group = db.scalars(select(AssetGroup).where(AssetGroup.code == code)).first()
        if group is None:
            group = AssetGroup(name=name, code=code)
            db.add(group)
            db.flush()
        groups[code] = group
    return groups


def seed_assets(
    db: Session, groups: dict[str, AssetGroup], users: dict[str, User]
) -> dict[str, Asset]:
    assets: dict[str, Asset] = {}
    for hostname, name, asset_type, criticality, group_code, owner in ASSETS:
        group = groups[group_code]
        asset = db.scalars(
            select(Asset).where(Asset.hostname == hostname, Asset.group_id == group.id)
        ).first()
        if asset is None:
            asset = Asset(
                name=name,
                hostname=hostname,
                ip_address=f"10.0.{len(assets) + 1}.10",
                asset_type=asset_type,
                criticality=criticality,
                group_id=group.id,
                owner_id=users[owner].id,
            )
            db.add(asset)
            db.flush()
        assets[hostname] = asset
    return assets


def seed_vulnerabilities(db: Session) -> dict[str, Vulnerability]:
    catalog: dict[str, Vulnerability] = {}
    for cve_id, bdu_id, title, vector, cwe_id, published in VULNERABILITIES:
        key = cve_id if cve_id is not None else bdu_id
        if key is None:
            continue
        column = Vulnerability.cve_id if cve_id else Vulnerability.bdu_id
        vulnerability = db.scalars(select(Vulnerability).where(column == key)).first()
        if vulnerability is None:
            result = cvss.calculate(vector)
            vulnerability = Vulnerability(
                cve_id=cve_id,
                bdu_id=bdu_id,
                title=title,
                description=f"Демонстрационная запись каталога: {title}.",
                cvss_vector=vector,
                cvss_base_score=result.base_score,
                cvss_severity=result.severity,
                cwe_id=cwe_id,
                published_date=published,
            )
            db.add(vulnerability)
            db.flush()
        catalog[key] = vulnerability
    return catalog


def seed_findings(
    db: Session,
    assets: dict[str, Asset],
    catalog: dict[str, Vulnerability],
    users: dict[str, User],
) -> None:
    # Обнаружения наполняются один раз: даты считаются от момента запуска.
    if db.scalar(select(func.count()).select_from(Finding)):
        return
    now = utcnow()
    for hostname, key, status, days_ago, assignee, comment in FINDINGS:
        detected = now - timedelta(days=days_ago)
        finding, _ = findings_service.register_detection(
            db, assets[hostname], catalog[key], now=detected
        )
        finding.status = status
        finding.resolution_comment = comment
        if assignee:
            finding.assignee_id = users[assignee].id
        if status == FindingStatus.closed:
            finding.closed_at = detected + timedelta(days=40)


def seed_database(db: Session, passwords: dict[str, str]) -> None:
    users = seed_users(db, passwords)
    groups = seed_groups(db)
    assets = seed_assets(db, groups, users)
    catalog = seed_vulnerabilities(db)
    seed_findings(db, assets, catalog, users)
    db.commit()


def main() -> None:
    from app.db.session import SessionLocal

    passwords = _passwords(get_settings())
    with SessionLocal() as db:
        seed_database(db, passwords)
    print("Демо-данные загружены.", file=sys.stderr)


if __name__ == "__main__":
    main()
