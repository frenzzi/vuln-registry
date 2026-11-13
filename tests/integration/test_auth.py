import base64
import json

import jwt
from httpx import AsyncClient

from tests.conftest import PASSWORDS, Accounts
from tests.helpers import API

NEW_USER = {
    "username": "newuser",
    "email": "newuser@example.com",
    "full_name": "Новый Пользователь",
    "password": "Str0ngPass2026",
}


async def login(client: AsyncClient, username: str, password: str):
    return await client.post(f"{API}/auth/login", data={"username": username, "password": password})


async def test_register_success(anon: AsyncClient) -> None:
    response = await anon.post(f"{API}/auth/register", json=NEW_USER)
    assert response.status_code == 201
    body = response.json()
    assert response.headers["Location"] == f"{API}/users/{body['id']}"
    assert body["role"] == "owner"
    assert body["username"] == "newuser"
    assert body["is_active"] is True
    assert "password" not in body
    assert "hashed_password" not in body
    assert body["created_at"].endswith("Z")


async def test_register_cannot_choose_role(anon: AsyncClient) -> None:
    response = await anon.post(f"{API}/auth/register", json={**NEW_USER, "role": "admin"})
    assert response.status_code == 201
    assert response.json()["role"] == "owner"


async def test_register_duplicate_username_and_email(anon: AsyncClient) -> None:
    assert (await anon.post(f"{API}/auth/register", json=NEW_USER)).status_code == 201

    same_username = {**NEW_USER, "email": "other@example.com"}
    response = await anon.post(f"{API}/auth/register", json=same_username)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "USER_USERNAME_TAKEN"

    same_email = {**NEW_USER, "username": "otheruser", "email": "NewUser@Example.com"}
    response = await anon.post(f"{API}/auth/register", json=same_email)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "USER_EMAIL_TAKEN"


async def test_register_weak_password_lists_violations(anon: AsyncClient) -> None:
    response = await anon.post(f"{API}/auth/register", json={**NEW_USER, "password": "parol"})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "PASSWORD_POLICY_VIOLATION"
    assert len(error["details"]["violations"]) == 3

    same = await anon.post(
        f"{API}/auth/register",
        json={**NEW_USER, "username": "SamePass12345", "password": "SamePass12345"},
    )
    assert same.status_code == 422
    assert "совпадать" in same.json()["error"]["details"]["violations"][0]

    long_password = await anon.post(
        f"{API}/auth/register", json={**NEW_USER, "password": "Aa1" + "x" * 200}
    )
    assert long_password.status_code == 422


async def test_register_validation_errors_do_not_echo_input(anon: AsyncClient) -> None:
    response = await anon.post(
        f"{API}/auth/register", json={**NEW_USER, "email": "not-an-email", "username": "a"}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    fields = {e["field"] for e in body["error"]["details"]["errors"]}
    assert {"email", "username"} <= fields
    assert "Str0ngPass2026" not in response.text


async def test_login_success_returns_hs256_token(anon: AsyncClient, accounts: Accounts) -> None:
    response = await login(anon, "analyst", PASSWORDS["analyst"])
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 3600
    header = jwt.get_unverified_header(body["access_token"])
    assert header["alg"] == "HS256"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["role"] == "analyst"
    assert claims["sub"] == str(accounts.ids["analyst"])
    assert claims["exp"] - claims["iat"] == 3600


async def test_login_failures_are_indistinguishable(anon: AsyncClient, accounts: Accounts) -> None:
    wrong_password = await login(anon, "analyst", "Wrong-Password-1")
    unknown_user = await login(anon, "nosuchuser", "Wrong-Password-1")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()
    assert wrong_password.json()["error"]["code"] == "AUTH_INVALID_CREDENTIALS"


async def test_blocked_user_cannot_login_and_token_stops_working(
    anon: AsyncClient, admin: AsyncClient, owner2: AsyncClient, accounts: Accounts
) -> None:
    assert (await owner2.get(f"{API}/auth/me")).status_code == 200

    blocked = await admin.patch(f"{API}/users/{accounts.ids['owner2']}", json={"is_active": False})
    assert blocked.status_code == 200

    response = await owner2.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_TOKEN"

    response = await login(anon, "owner2", PASSWORDS["owner2"])
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTH_USER_INACTIVE"

    # Неверный пароль у заблокированного ничем не отличается от обычного отказа
    response = await login(anon, "owner2", "Wrong-Password-1")
    assert response.status_code == 401


async def test_me_requires_a_valid_token(
    anon: AsyncClient, make_client, accounts: Accounts
) -> None:
    response = await anon.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_TOKEN"
    assert response.headers["www-authenticate"] == "Bearer"

    token = accounts.tokens["admin"]
    async with make_client(token[:-3] + "abc") as client:
        assert (await client.get(f"{API}/auth/me")).status_code == 401

    def b64(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    none_token = (
        f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': '1', 'exp': 9999999999, 'iat': 1})}."
    )
    async with make_client(none_token) as client:
        assert (await client.get(f"{API}/auth/me")).status_code == 401

    async with make_client(token) as client:
        response = await client.get(f"{API}/auth/me")
        assert response.status_code == 200
        assert response.json()["username"] == "admin"


async def test_change_password_flow(
    anon: AsyncClient, owner1: AsyncClient, accounts: Accounts
) -> None:
    wrong = await owner1.post(
        f"{API}/auth/change-password",
        json={"current_password": "Wrong-Password-1", "new_password": "Brand-New-Pass-77"},
    )
    assert wrong.status_code == 400
    assert wrong.json()["error"]["code"] == "AUTH_WRONG_CURRENT_PASSWORD"
    assert (await login(anon, "owner1", PASSWORDS["owner1"])).status_code == 200

    weak = await owner1.post(
        f"{API}/auth/change-password",
        json={"current_password": PASSWORDS["owner1"], "new_password": "weak"},
    )
    assert weak.status_code == 422

    changed = await owner1.post(
        f"{API}/auth/change-password",
        json={"current_password": PASSWORDS["owner1"], "new_password": "Brand-New-Pass-77"},
    )
    assert changed.status_code == 200

    assert (await login(anon, "owner1", PASSWORDS["owner1"])).status_code == 401
    assert (await login(anon, "owner1", "Brand-New-Pass-77")).status_code == 200


async def test_login_form_is_required(anon: AsyncClient) -> None:
    response = await anon.post(f"{API}/auth/login", json={"username": "a", "password": "b"})
    assert response.status_code == 422
