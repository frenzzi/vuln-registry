import pytest

from app.models.enums import Criticality, Severity
from app.services.risk import risk_level, risk_score, roundup_1

# Таблица 4.9 ТЗ: базовый балл → риск для каждой критичности актива.
RISK_TABLE = [
    (9.8, {"low": 4.9, "medium": 7.4, "high": 9.8, "critical": 10.0}),
    (7.8, {"low": 3.9, "medium": 5.9, "high": 7.8, "critical": 9.8}),
    (5.4, {"low": 2.7, "medium": 4.1, "high": 5.4, "critical": 6.8}),
]


@pytest.mark.parametrize(
    ("base", "criticality", "expected"),
    [(base, Criticality(name), value) for base, row in RISK_TABLE for name, value in row.items()],
)
def test_risk_score_table(base: float, criticality: Criticality, expected: float) -> None:
    assert risk_score(base, criticality) == expected


def test_risk_score_is_capped_at_ten() -> None:
    assert risk_score(10.0, Criticality.critical) == 10.0
    assert risk_score(9.8, Criticality.critical) == 10.0


def test_level_can_drop_below_cvss_severity() -> None:
    # 7.8 (high по CVSS) на малокритичном активе — уже low
    assert risk_level(risk_score(7.8, Criticality.low)) == Severity.low


def test_risk_level_boundaries() -> None:
    assert risk_level(0.0) == Severity.none
    assert risk_level(3.9) == Severity.low
    assert risk_level(4.0) == Severity.medium
    assert risk_level(6.9) == Severity.medium
    assert risk_level(7.0) == Severity.high
    assert risk_level(9.0) == Severity.critical


def test_roundup_1_ignores_binary_noise() -> None:
    assert roundup_1(9.8 * 0.75) == 7.4  # в double получается 7.3500000000000005
    assert roundup_1(5.4 * 0.75) == 4.1  # обычное округление дало бы 4.0
    assert roundup_1(4.0) == 4.0
