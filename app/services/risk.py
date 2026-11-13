"""Риск и срок устранения (BR-4)."""

import math
from datetime import date, datetime, timedelta

from app.models.enums import CLOSED_STATUSES, Criticality, FindingStatus, Severity
from app.services.cvss import severity_for

CRITICALITY_WEIGHT = {
    Criticality.low: 0.50,
    Criticality.medium: 0.75,
    Criticality.high: 1.00,
    Criticality.critical: 1.25,
}

SLA_DAYS = {
    Severity.critical: 7,
    Severity.high: 30,
    Severity.medium: 90,
    Severity.low: 180,
    Severity.none: 180,
}

# Статусы, при которых просрочка не считается.
NOT_OVERDUE_STATUSES = (FindingStatus.fixed, *CLOSED_STATUSES)


def roundup_1(value: float) -> float:
    """Округление вверх до десятых; эпсилон гасит ошибку двоичного представления."""
    return math.ceil(value * 10 - 1e-9) / 10


def risk_score(cvss_base_score: float, criticality: Criticality) -> float:
    return roundup_1(min(cvss_base_score * CRITICALITY_WEIGHT[criticality], 10.0))


def risk_level(score: float) -> Severity:
    return severity_for(score)


def due_date(first_detected_at: datetime, level: Severity) -> date:
    """Срок считается от первого обнаружения и повторным обнаружением не продлевается."""
    return first_detected_at.date() + timedelta(days=SLA_DAYS[level])


def is_overdue(due: date, status: FindingStatus, today: date) -> bool:
    return due < today and status not in NOT_OVERDUE_STATUSES
