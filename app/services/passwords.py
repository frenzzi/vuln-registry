"""Парольная политика (BR-1)."""

from app.core.exceptions import AppError

MIN_LENGTH = 10
MAX_LENGTH = 128


def password_violations(password: str, username: str) -> list[str]:
    """Возвращает список невыполненных условий политики; пустой список — пароль подходит."""
    problems: list[str] = []
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        problems.append(f"Длина пароля должна быть от {MIN_LENGTH} до {MAX_LENGTH} символов")
    if not any(ch.islower() for ch in password):
        problems.append("Нужна хотя бы одна строчная буква")
    if not any(ch.isupper() for ch in password):
        problems.append("Нужна хотя бы одна прописная буква")
    if not any(ch.isdigit() for ch in password):
        problems.append("Нужна хотя бы одна цифра")
    if password == username:
        problems.append("Пароль не должен совпадать с именем пользователя")
    return problems


def ensure_password_policy(password: str, username: str) -> None:
    problems = password_violations(password, username)
    if problems:
        raise AppError(
            422,
            "PASSWORD_POLICY_VIOLATION",
            "Пароль не соответствует парольной политике",
            {"violations": problems},
        )
