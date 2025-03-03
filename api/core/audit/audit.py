from functools import wraps
from flask import request, has_request_context
from datetime import datetime
from models.audit_log import AuditLog, AuditActionType, AuditLogCategory
from extensions.ext_database import db
import click


def audit_log(action_type: AuditActionType, action_details: str, catch_exceptions: list[Exception] = []):
    """Decorator to log user actions to the audit log."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            need_audit = True
            if catch_exceptions:
                need_audit = False
            # Execute the function and record success/failure
            try:
                result = func(*args, **kwargs)
                success = True
            except Exception as e:
                success = False
                # If the exception is not in the list, do not log it
                if catch_exceptions and any(isinstance(e, exc_type) for exc_type in catch_exceptions):
                    need_audit = True
                raise e
            finally:
                if need_audit:
                    source_ip = ''
                    device_info = ''
                    user_id = None
                    user_email = ''
                    if has_request_context():
                        source_ip = request.remote_addr
                        device_info = request.headers.get('User-Agent', 'Unknown')

                    # Get user info 
                    from flask import g
                    from extensions.ext_login import load_user_from_request
                    try:
                        if hasattr(g, "current_account"):
                            current_account = g.current_account
                            user_id = getattr(current_account, 'id', None)
                            user_email = getattr(current_account, 'email', None)
                        else:
                            logged_user = load_user_from_request("")
                            user_id = getattr(logged_user, 'id', None)
                            user_email = getattr(logged_user, 'email', None)
                    except:
                        user_email = getattr(g, 'current_user_email', '')

                    # Create audit log entry
                    log = AuditLog.create_log(
                        account_id=user_id,
                        account_email=user_email,
                        action_type=action_type,
                        action_details=action_details,
                        success=success,
                        source_ip=source_ip,
                        device_info=device_info,
                        category=None
                    )
                    db.session.add(log)
                    db.session.commit()
            return result
        return wrapper
    return decorator
