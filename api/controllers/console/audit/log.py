from flask import request
from flask_login import current_user
from flask_restful import Resource
from werkzeug.exceptions import Forbidden
from controllers.console.wraps import account_initialization_required, setup_required
from libs.login import login_required
from controllers.console import api
from models.audit_log import AuditLog


class AuditLogListApi(Resource):
    @setup_required
    @login_required
    @account_initialization_required
    def get(self):
        """查询审计日志"""
        if not current_user.is_auditor:
            raise Forbidden()

        action_type = request.args.get('action_type')
        action_details = request.args.get('action_details')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 20))
        
        query = AuditLog.query
        if action_type:
            query = query.filter(AuditLog.action_type == action_type)
        if action_details:
            query = query.filter(AuditLog.action_details.ilike(f'%{action_details}%'))
            
        if start_time:
            query = query.filter(AuditLog.timestamp >= start_time)
        if end_time:
            query = query.filter(AuditLog.timestamp <= end_time)
            
        pagination = query.paginate(page=page, per_page=page_size)
        
        return {
            'data': [log.to_dict() for log in pagination.items],
            'total': pagination.total,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'pages': pagination.pages
        }

api.add_resource(AuditLogListApi, "/audit-logs")
