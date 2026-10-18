import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from src.database.session import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(50), index=True, nullable=False)
    username = Column(String(100), index=True, nullable=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<AuditLog(id='{self.id}', event_type='{self.event_type}', username='{self.username}')>"
