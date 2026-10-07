from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from app.api.deps import DB

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def liveness():
    return {"status": "ok"}


@router.get("/ready")
def readiness(db: DB):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable")
    return {"status": "ok", "database": "ok"}
