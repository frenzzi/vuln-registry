from unittest.mock import MagicMock

import pytest

from app.core.exceptions import AppError
from app.models.enums import FindingStatus, Role
from app.models.finding import Finding
from app.services.findings import (
    TRANSITIONS,
    actor_for,
    allowed_transitions,
    change_status,
    check_transition,
)

S = FindingStatus

# Матрица BR-6, записанная независимо от кода.
ALLOWED = {
    S.new: {S.confirmed, S.false_positive},
    S.confirmed: {S.in_progress, S.false_positive},
    S.in_progress: {S.fixed, S.confirmed},
    S.fixed: {S.closed, S.confirmed},
    S.false_positive: {S.closed},
    S.closed: set(),
}


@pytest.mark.parametrize(
    ("current", "target"), [(c, t) for c, targets in ALLOWED.items() for t in targets]
)
def test_allowed_transitions_pass_for_staff(current: FindingStatus, target: FindingStatus) -> None:
    check_transition(current, target, "staff")


@pytest.mark.parametrize(
    ("current", "target"),
    [(c, t) for c in S for t in S if t not in ALLOWED[c]],
)
def test_forbidden_transitions_give_409_with_allowed_list(
    current: FindingStatus, target: FindingStatus
) -> None:
    with pytest.raises(AppError) as exc_info:
        check_transition(current, target, "staff")
    error = exc_info.value
    assert error.status_code == 409
    assert error.code == "FINDING_INVALID_STATUS_TRANSITION"
    assert error.details is not None
    assert set(error.details["allowed"]) == {s.value for s in ALLOWED[current]}


def test_transition_to_the_same_status_is_forbidden() -> None:
    for status in S:
        with pytest.raises(AppError) as exc_info:
            check_transition(status, status, "staff")
        assert exc_info.value.code == "FINDING_INVALID_STATUS_TRANSITION"


def test_every_status_is_reachable_from_new() -> None:
    reached = {S.new}
    frontier = [S.new]
    while frontier:
        for target in TRANSITIONS[frontier.pop()]:
            if target not in reached:
                reached.add(target)
                frontier.append(target)
    assert reached == set(S)


def test_owner_may_only_take_into_work_and_fix() -> None:
    assert allowed_transitions(S.confirmed, "owner") == [S.in_progress]
    assert S.fixed in allowed_transitions(S.in_progress, "owner")
    assert allowed_transitions(S.new, "owner") == []
    with pytest.raises(AppError) as exc_info:
        check_transition(S.new, S.confirmed, "owner")
    assert exc_info.value.status_code == 403


def test_actor_is_derived_from_role() -> None:
    assert actor_for(Role.admin) == "staff"
    assert actor_for(Role.analyst) == "staff"
    assert actor_for(Role.owner) == "owner"


def _finding(status: FindingStatus) -> Finding:
    finding = Finding()
    finding.status = status
    return finding


@pytest.mark.parametrize("comment", [None, "", "   ", "коротко"])
def test_fixed_requires_a_comment_of_ten_characters(comment: str | None) -> None:
    finding = _finding(S.in_progress)
    with pytest.raises(AppError) as exc_info:
        change_status(MagicMock(), finding, S.fixed, "staff", comment)
    assert exc_info.value.status_code == 422
    assert exc_info.value.code == "FINDING_RESOLUTION_COMMENT_REQUIRED"
    assert finding.status == S.in_progress


def test_fixed_with_comment_and_closed_sets_timestamp() -> None:
    db = MagicMock()
    finding = _finding(S.in_progress)
    change_status(db, finding, S.fixed, "owner", "Обновлён пакет до версии 1.25.3")
    assert finding.status == S.fixed
    assert finding.resolution_comment == "Обновлён пакет до версии 1.25.3"
    assert finding.closed_at is None

    change_status(db, finding, S.closed, "staff", None)
    assert finding.status == S.closed
    assert finding.closed_at is not None
