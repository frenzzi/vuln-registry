from fastapi import APIRouter

# Роутеры подключаются явными импортами: динамический обход пакета ломается после обфускации.
from app.api.v1.endpoints import (
    analytics,
    asset_groups,
    assets,
    auth,
    findings,
    users,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(users.router, prefix="/users")
api_router.include_router(asset_groups.router, prefix="/asset-groups")
api_router.include_router(assets.router, prefix="/assets")
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities")
api_router.include_router(vulnerabilities.cvss_router, prefix="/cvss")
api_router.include_router(findings.router, prefix="/findings")
api_router.include_router(analytics.router, prefix="/analytics")
