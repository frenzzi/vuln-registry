import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings

logger = logging.getLogger("app")


class AppError(Exception):
    """Доменное исключение: превращается в ответ единого формата."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


def error_body(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


_HTTP_CODES = {
    400: "BAD_REQUEST",
    401: "AUTH_INVALID_TOKEN",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    422: "VALIDATION_ERROR",
}

_HTTP_MESSAGES = {
    401: "Требуется аутентификация",
    403: "Недостаточно прав",
    404: "Ресурс не найден",
    405: "Метод не поддерживается",
}


async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(exc.code, exc.message, exc.details),
        headers=exc.headers,
    )


async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Входное значение (input) в ответ не попадает: там могут оказаться пароли.
    errors = [
        {
            "field": ".".join(str(part) for part in err["loc"][1:]) or str(err["loc"][0]),
            "message": err["msg"],
            "type": err["type"],
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content=error_body(
            "VALIDATION_ERROR", "Ошибка валидации входных данных", {"errors": errors}
        ),
    )


async def _http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = _HTTP_CODES.get(exc.status_code, f"HTTP_{exc.status_code}")
    message = _HTTP_MESSAGES.get(exc.status_code, "Ошибка запроса")
    headers = dict(exc.headers) if exc.headers else None
    return JSONResponse(
        status_code=exc.status_code, content=error_body(code, message), headers=headers
    )


async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Необработанная ошибка: %s %s", request.method, request.url.path)
    details = {"exception": type(exc).__name__} if get_settings().debug else None
    return JSONResponse(
        status_code=500,
        content=error_body("INTERNAL_ERROR", "Внутренняя ошибка сервера", details),
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, _unhandled_handler)


def not_found(code: str, message: str) -> AppError:
    return AppError(404, code, message)


def conflict(code: str, message: str, details: dict[str, Any] | None = None) -> AppError:
    return AppError(409, code, message, details)


def forbidden_role() -> AppError:
    return AppError(403, "AUTHZ_ROLE_FORBIDDEN", "Недостаточно прав для этой операции")
