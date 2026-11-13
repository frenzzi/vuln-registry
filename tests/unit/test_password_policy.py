import pytest

from app.core.exceptions import AppError
from app.services.passwords import ensure_password_policy, password_violations


def test_valid_password_has_no_violations() -> None:
    assert password_violations("Str0ngPass2026", "user") == []


def test_too_short() -> None:
    assert any("Длина" in p for p in password_violations("Ab1", "user"))


def test_too_long() -> None:
    assert any("Длина" in p for p in password_violations("Aa1" + "x" * 130, "user"))


def test_each_character_class_is_required() -> None:
    assert password_violations("alllowercase1", "u") == ["Нужна хотя бы одна прописная буква"]
    assert password_violations("ALLUPPERCASE1", "u") == ["Нужна хотя бы одна строчная буква"]
    assert password_violations("NoDigitsHereAtAll", "u") == ["Нужна хотя бы одна цифра"]


def test_password_equal_to_username() -> None:
    assert password_violations("SameName12345", "SameName12345") == [
        "Пароль не должен совпадать с именем пользователя"
    ]


def test_cyrillic_letters_count_as_letters() -> None:
    assert password_violations("ПарольПароль1я", "u") == []


def test_all_violations_are_listed_together() -> None:
    with pytest.raises(AppError) as exc_info:
        ensure_password_policy("parol", "user")
    error = exc_info.value
    assert error.status_code == 422
    assert error.code == "PASSWORD_POLICY_VIOLATION"
    assert error.details is not None
    assert len(error.details["violations"]) == 3  # длина, прописная буква, цифра
