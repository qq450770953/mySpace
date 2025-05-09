from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import AuditLog, User
from app.extensions import db
from datetime import datetime

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('/audit/logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """获取审计日志列表"""
    try:
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # 检查用户权限
        current_user = User.query.get(current_user_id)
        if not current_user or not current_user.has_permission('view_audit_logs'):
            return jsonify({'error': '权限不足'}), 403
        
        # 获取审计日志
        logs = AuditLog.query.order_by(AuditLog.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'total': logs.total,
            'pages': logs.pages,
            'current_page': logs.page
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@audit_bp.route('/audit/logs/<int:log_id>', methods=['GET'])
@jwt_required()
def get_audit_log(log_id):
    """获取单个审计日志详情"""
    try:
        current_user_id = get_jwt_identity()
        
        # 检查用户权限
        current_user = User.query.get(current_user_id)
        if not current_user or not current_user.has_permission('view_audit_logs'):
            return jsonify({'error': '权限不足'}), 403
        
        # 获取审计日志
        log = AuditLog.query.get_or_404(log_id)
        return jsonify(log.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@audit_bp.route('/audit/logs/search', methods=['GET'])
@jwt_required()
def search_audit_logs():
    """搜索审计日志"""
    try:
        current_user_id = get_jwt_identity()
        
        # 检查用户权限
        current_user = User.query.get(current_user_id)
        if not current_user or not current_user.has_permission('view_audit_logs'):
            return jsonify({'error': '权限不足'}), 403
        
        # 获取搜索参数
        user_id = request.args.get('user_id', type=int)
        action = request.args.get('action')
        resource_type = request.args.get('resource_type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # 构建查询
        query = AuditLog.query
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        if action:
            query = query.filter_by(action=action)
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        if start_date:
            query = query.filter(AuditLog.created_at >= datetime.fromisoformat(start_date))
        if end_date:
            query = query.filter(AuditLog.created_at <= datetime.fromisoformat(end_date))
        
        # 执行查询
        logs = query.order_by(AuditLog.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'total': logs.total,
            'pages': logs.pages,
            'current_page': logs.page
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500 