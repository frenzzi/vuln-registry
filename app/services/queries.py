"""Общие помощники для списочных запросов: пагинация, сортировка, поиск."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, Select, func, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError


@dataclass(frozen=True)
class PageParams:
    limit: int = 20
    offset: int = 0


def apply_sort(
    stmt: Select[Any],
    sort: str | None,
    allowed: dict[str, Any],
    default: str,
    tiebreak: Any,
) -> Select[Any]:
    """Сортировка по белому списку полей: «field» — по возрастанию, «-field» — по убыванию.

    Имя поля в SQL не подставляется, оно только выбирает готовый столбец из словаря.
    """
    spec = sort or default
    descending = spec.startswith("-")
    name = spec.lstrip("-")
    column = allowed.get(name)
    if column is None:
        raise AppError(
            422,
            "INVALID_SORT_FIELD",
            f"Сортировка по полю «{name}» не поддерживается",
            {"allowed": sorted(allowed)},
        )
    order = column.desc() if descending else column.asc()
    return stmt.order_by(order, tiebreak.desc() if descending else tiebreak.asc())


def paginate(db: Session, stmt: Select[Any], page: PageParams) -> tuple[list[Any], int]:
    """Возвращает страницу результатов и общее количество строк до пагинации."""
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    items = list(db.scalars(stmt.limit(page.limit).offset(page.offset)).unique())
    return items, total


def contains(column: ColumnElement[Any], query: str) -> ColumnElement[bool]:
    """Поиск подстроки без учёта регистра; символы шаблона LIKE экранируются."""
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.ilike(f"%{escaped}%", escape="\\")
