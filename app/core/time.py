from datetime import UTC, date, datetime


def utcnow() -> datetime:
    """Текущий момент в UTC (с tzinfo)."""
    return datetime.now(UTC)


def utc_today() -> date:
    """Сегодняшняя дата по UTC."""
    return utcnow().date()
