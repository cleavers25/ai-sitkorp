from fastapi import APIRouter

from app.api.v1 import (
    actions, ai, assessments, assets, audit_logs, auth, backups, credentials, dashboard, health, integrations, memories, notifications, schedules, users,
)

api_router = APIRouter(prefix="/api/v1")
for module in (health, auth, users, credentials, assets, assessments, actions, backups, schedules, memories, notifications, integrations, ai, audit_logs, dashboard):
    api_router.include_router(module.router)
