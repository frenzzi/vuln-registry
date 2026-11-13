import logging

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import API_PREFIX, get_settings
from app.core.exceptions import register_exception_handlers

DESCRIPTION = """
REST API для учёта информационных активов организации, ведения каталога уязвимостей
и контроля устранения уязвимостей, обнаруженных на конкретных активах.

Для работы в Swagger UI нажмите **Authorize** и введите логин и пароль.
"""


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO)

    app = FastAPI(
        title="Vulnerability Registry",
        description=DESCRIPTION,
        version="1.0.0",
    )
    register_exception_handlers(app)
    app.include_router(api_router, prefix=API_PREFIX)

    @app.get("/health", tags=["service"], summary="Проверка работоспособности")
    def health() -> dict[str, str]:
        """Возвращает `{"status": "ok"}`. Версий библиотек и путей не раскрывает."""
        return {"status": "ok"}

    return app


app = create_app()
