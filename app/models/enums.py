from enum import StrEnum


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"
    owner = "owner"


class AssetType(StrEnum):
    server = "server"
    workstation = "workstation"
    network_device = "network_device"
    application = "application"
    database = "database"


class Criticality(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Severity(StrEnum):
    """Качественная шкала CVSS; используется и для cvss_severity, и для risk_level."""

    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(StrEnum):
    new = "new"
    confirmed = "confirmed"
    in_progress = "in_progress"
    fixed = "fixed"
    false_positive = "false_positive"
    closed = "closed"


# Обнаружение считается открытым, пока оно не closed и не false_positive.
CLOSED_STATUSES = (FindingStatus.closed, FindingStatus.false_positive)
# Статусы, в которых срок устранения ещё «горит».
UNRESOLVED_STATUSES = (FindingStatus.new, FindingStatus.confirmed, FindingStatus.in_progress)
