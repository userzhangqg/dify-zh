import enum
from datetime import datetime

from sqlalchemy import Column, String, Text, Boolean, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .engine import db
from .types import StringUUID


class AuditActionType(enum.StrEnum):
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_CHANGE = "permission_change"
    DATA_EXPORT = "data_export"
    SYSTEM_MANAGEMENT = "system_management"


class AuditLogCategory(enum.StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_OPERATION = "data_operation"
    SYSTEM_OPERATION = "system_operation"


class AuditLog(db.Model):  # type: ignore[name-defined]
    __tablename__ = "audit_logs"
    __table_args__ = (
        db.PrimaryKeyConstraint("id", name="audit_log_pkey"),
        db.Index("audit_log_account_id_idx", "account_id"),
        db.Index("audit_log_action_type_idx", "action_type"),
        db.Index("audit_log_category_idx", "category"),
    )

    id: Mapped[str] = mapped_column(StringUUID, server_default=db.text("uuid_generate_v4()"))
    account_id = db.Column(UUID, nullable=True)
    account_email = db.Column(String(255), nullable=True)
    timestamp = db.Column(DateTime, nullable=False, server_default=func.current_timestamp())
    action_type = db.Column(String(32), nullable=False)
    action_details = db.Column(Text, nullable=True)
    success = db.Column(Boolean, nullable=False)
    source_ip = db.Column(String(45), nullable=True)
    device_info = db.Column(Text, nullable=True)
    category = db.Column(String(32), nullable=False)

    @classmethod
    def create_log(
        cls,
        account_id: str,
        account_email: str,
        action_type: AuditActionType,
        action_details: str,
        success: bool,
        source_ip: str,
        device_info: str = None,
        category: AuditLogCategory = None,
    ) -> "AuditLog":
        if category is None:
            category = cls._infer_category(action_type)

        return cls(
            account_id=account_id,
            account_email=account_email,
            action_type=action_type.value,
            action_details=action_details,
            success=success,
            source_ip=source_ip,
            device_info=device_info,
            category=category.value,
        )

    @classmethod
    def _infer_category(cls, action_type: AuditActionType) -> AuditLogCategory:
        if action_type in {AuditActionType.LOGIN, AuditActionType.LOGOUT, AuditActionType.LOGIN_FAILED}:
            return AuditLogCategory.AUTHENTICATION
        elif action_type in {AuditActionType.UNAUTHORIZED_ACCESS, AuditActionType.PERMISSION_CHANGE}:
            return AuditLogCategory.AUTHORIZATION
        elif action_type == AuditActionType.DATA_EXPORT:
            return AuditLogCategory.DATA_OPERATION
        else:
            return AuditLogCategory.SYSTEM_OPERATION

    def to_dict(self) -> dict:
        return {
            'id': str(self.id),
            'account_id': str(self.account_id) if self.account_id else None,
            'account_email': self.account_email,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'action_type': self.action_type,
            'action_details': self.action_details,
            'success': self.success,
            'source_ip': self.source_ip,
            'device_info': self.device_info,
            'category': self.category
        }
