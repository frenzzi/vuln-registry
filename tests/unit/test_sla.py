from datetime import UTC, date, datetime

import pytest

from app.models.enums import FindingStatus, Severity
from app.services.risk import due_date, is_overdue

FIRST_DETECTED = datetime(2026, 1, 10, 23, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("level", "days"),
    [
        (Severity.critical, 7),
        (Severity.high, 30),
        (Severity.medium, 90),
        (Severity.low, 180),
        (Severity.none, 180),
    ],
)
def test_due_date_by_sla(level: Severity, days: int) -> None:
    result = due_date(FIRST_DETECTED, level)
    assert (result - FIRST_DETECTED.date()).days == days


def test_due_date_counts_from_first_detection_date() -> None:
    assert due_date(FIRST_DETECTED, Severity.critical) == date(2026, 1, 17)


def test_overdue_before_and_after_due_date() -> None:
    due = date(2026, 3, 1)
    assert not is_overdue(due, FindingStatus.confirmed, today=date(2026, 3, 1))
    assert is_overdue(due, FindingStatus.confirmed, today=date(2026, 3, 2))
    assert not is_overdue(due, FindingStatus.new, today=date(2026, 2, 28))


@pytest.mark.parametrize(
    "status", [FindingStatus.fixed, FindingStatus.closed, FindingStatus.false_positive]
)
def test_resolved_findings_are_never_overdue(status: FindingStatus) -> None:
    assert not is_overdue(date(2020, 1, 1), status, today=date(2026, 1, 1))
