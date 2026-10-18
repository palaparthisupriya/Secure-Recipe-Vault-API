from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from src.models.audit_log import AuditLog


class AuditService:
    @staticmethod
    def record_event(
        db: Session,
        event_type: str,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[str] = None
    ) -> AuditLog:
        """Creates and commits a new security audit log entry."""
        log_entry = AuditLog(
            event_type=event_type,
            username=username,
            ip_address=ip_address,
            details=details,
            created_at=datetime.now(timezone.utc)
        )
        db.add(log_entry)
        try:
            db.commit()
            db.refresh(log_entry)
        except Exception:
            db.rollback()
            raise
        return log_entry

    @staticmethod
    def get_all_logs(db: Session, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        """Retrieves system security audit events ordered by creation timestamp descending."""
        return (
            db.query(AuditLog)
            .order_by(AuditLog.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )


audit_service = AuditService()
