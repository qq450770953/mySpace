from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import SystemLog, SystemSetting, User
from app.extensions import db
from datetime import datetime
import logging

bp = Blueprint('system', __name__)

@bp.route('/logs', methods=['GET'])
@jwt_required()
def get_system_logs():
    """Get system logs"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'logs': [log.to_dict() for log in logs.items],
        'total': logs.total,
        'pages': logs.pages,
        'current_page': logs.page
    })

@bp.route('/settings', methods=['GET'])
@jwt_required()
def get_system_settings():
    """Get system settings"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    settings = SystemSetting.query.all()
    return jsonify({'settings': [setting.to_dict() for setting in settings]})

@bp.route('/settings/<key>', methods=['PUT'])
@jwt_required()
def update_system_setting(key):
    """Update a system setting"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    setting = SystemSetting.query.filter_by(key=key).first()
    if not setting:
        return jsonify({'error': 'Setting not found'}), 404
        
    data = request.get_json()
    if 'value' not in data:
        return jsonify({'error': 'Value is required'}), 400
        
    setting.value = data['value']
    setting.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify(setting.to_dict())

@bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }) 