"""Выгрузка схемы OpenAPI без запуска сервера: python scripts/export_openapi.py [путь]

По умолчанию пишет security/dast/openapi.json (вход для OWASP ZAP и Schemathesis).
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Для выгрузки схемы ключ подписи не используется, но настройки требуют его наличия.
os.environ.setdefault("APP_SECRET_KEY", "openapi-export-only-key-" + "0" * 16)


def main() -> None:
    from app.main import app

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "security" / "dast" / "openapi.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Схема записана: {target}")


if __name__ == "__main__":
    main()
