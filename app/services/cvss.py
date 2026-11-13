"""Разбор вектора и расчёт базового балла CVSS v3.1 (BR-3)."""

from dataclasses import dataclass

from app.core.exceptions import AppError
from app.models.enums import Severity

PREFIX = "CVSS:3.1"

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
S = {"U": None, "C": None}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Допустимые значения каждой базовой метрики.
ALLOWED: dict[str, set[str]] = {
    "AV": set(AV),
    "AC": set(AC),
    "PR": set(PR_UNCHANGED),
    "UI": set(UI),
    "S": set(S),
    "C": set(CIA),
    "I": set(CIA),
    "A": set(CIA),
}


class CvssVectorError(AppError):
    """Вектор не соответствует формату CVSS v3.1."""

    def __init__(self, message: str, metric: str | None = None) -> None:
        super().__init__(
            422,
            "VULN_INVALID_CVSS_VECTOR",
            message,
            {"metric": metric} if metric else None,
        )


@dataclass(frozen=True)
class CvssResult:
    base_score: float
    severity: Severity
    impact: float
    exploitability: float
    metrics: dict[str, str]


def roundup(value: float) -> float:
    """Roundup из спецификации CVSS v3.1: до одного знака вверх, без ошибок float."""
    i = int(round(value * 100_000))
    if i % 10_000 == 0:
        return i / 100_000.0
    return (i // 10_000 + 1) / 10.0


def severity_for(score: float) -> Severity:
    """Качественная шкала: 0.0 — none, 0.1–3.9 — low, 4.0–6.9 — medium, 7.0–8.9 — high."""
    if score <= 0.0:
        return Severity.none
    if score < 4.0:
        return Severity.low
    if score < 7.0:
        return Severity.medium
    if score < 9.0:
        return Severity.high
    return Severity.critical


def parse_vector(vector: str) -> dict[str, str]:
    """Разбирает вектор в словарь метрика → значение. Любое отклонение — CvssVectorError."""
    parts = vector.split("/")
    if parts[0] != PREFIX:
        raise CvssVectorError(f"Вектор должен начинаться с «{PREFIX}»", "CVSS")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        name, sep, value = part.partition(":")
        if not sep:
            raise CvssVectorError(f"Метрика «{part}» записана не в виде имя:значение", part)
        if name not in ALLOWED:
            raise CvssVectorError(f"Неизвестная метрика «{name}»", name)
        if name in metrics:
            raise CvssVectorError(f"Метрика «{name}» указана дважды", name)
        if value not in ALLOWED[name]:
            raise CvssVectorError(f"Недопустимое значение «{value}» метрики {name}", name)
        metrics[name] = value
    missing = [name for name in ALLOWED if name not in metrics]
    if missing:
        raise CvssVectorError(f"Не указаны метрики: {', '.join(missing)}", missing[0])
    return metrics


def calculate(vector: str) -> CvssResult:
    """Считает базовый балл по вектору. Балл от клиента нигде не принимается."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr_table = PR_CHANGED if scope_changed else PR_UNCHANGED
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr_table[m["PR"]] * UI[m["UI"]]

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = roundup(min(impact + exploitability, 10.0))

    return CvssResult(
        base_score=base,
        severity=severity_for(base),
        impact=round(max(impact, 0.0), 1),
        exploitability=round(exploitability, 1),
        metrics=m,
    )
