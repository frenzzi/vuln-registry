import pytest

from app.models.enums import Severity
from app.services.cvss import CvssVectorError, calculate, parse_vector, roundup, severity_for

REFERENCE_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.critical),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severity.critical),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.none),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, Severity.high),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, Severity.high),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4, Severity.medium),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9, Severity.medium),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, Severity.medium),
    ("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N", 6.2, Severity.medium),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, Severity.low),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.6, Severity.low),
]


@pytest.mark.parametrize(("vector", "score", "severity"), REFERENCE_VECTORS)
def test_reference_vectors(vector: str, score: float, severity: Severity) -> None:
    result = calculate(vector)
    assert result.base_score == score
    assert result.severity == severity


@pytest.mark.parametrize(
    ("vector", "metric"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "A"),  # нет метрики A
        ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV"),  # неизвестное значение
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS"),  # другая версия
        ("", "CVSS"),  # пустая строка
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F", "E"),  # временная метрика
        ("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV"),  # метрика дважды
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A", "A"),  # нет двоеточия
        ("CVSS:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h", "av"),  # регистр важен
    ],
)
def test_invalid_vectors_are_rejected(vector: str, metric: str) -> None:
    with pytest.raises(CvssVectorError) as exc_info:
        calculate(vector)
    error = exc_info.value
    assert error.status_code == 422
    assert error.code == "VULN_INVALID_CVSS_VECTOR"
    assert error.details == {"metric": metric}


def test_metric_order_is_arbitrary() -> None:
    shuffled = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
    assert calculate(shuffled).base_score == 9.8


def test_roundup_follows_specification() -> None:
    assert roundup(4.02) == 4.1
    assert roundup(4.0) == 4.0
    assert roundup(1.7) == 1.7
    assert roundup(1.70001) == 1.8


def test_severity_boundaries() -> None:
    assert severity_for(0.0) == Severity.none
    assert severity_for(0.1) == Severity.low
    assert severity_for(3.9) == Severity.low
    assert severity_for(4.0) == Severity.medium
    assert severity_for(6.9) == Severity.medium
    assert severity_for(7.0) == Severity.high
    assert severity_for(8.9) == Severity.high
    assert severity_for(9.0) == Severity.critical
    assert severity_for(10.0) == Severity.critical


def test_parse_vector_returns_metrics() -> None:
    metrics = parse_vector("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")
    assert metrics == {
        "AV": "A",
        "AC": "H",
        "PR": "L",
        "UI": "R",
        "S": "C",
        "C": "H",
        "I": "L",
        "A": "N",
    }
