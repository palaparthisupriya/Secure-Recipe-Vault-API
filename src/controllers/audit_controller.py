from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from src.database.session import get_db
from src.middleware.rbac import require_admin
from src.middleware.auth import AuthenticatedUser
from src.services.audit_service import audit_service


router = APIRouter(tags=["Audit Logs"])


def serialize_audit_log(entry):
    return {
        "id": str(entry.id),
        "event_type": entry.event_type,
        "username": entry.username,
        "ip_address": entry.ip_address,
        "details": entry.details,
        "created_at": entry.created_at.isoformat() if entry.created_at else None
    }


@router.get("/api/audit-logs", status_code=status.HTTP_200_OK)
@router.get("/api/audit/logs", status_code=status.HTTP_200_OK)
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_admin: AuthenticatedUser = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Returns security events audit trail.
    STRICTLY restricted to the 'admin' role. Rejects non-admin users with 403 Forbidden.
    """
    logs = audit_service.get_all_logs(db=db, limit=limit, offset=offset)
    return [serialize_audit_log(item) for item in logs]
