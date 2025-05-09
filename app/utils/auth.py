from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            if not current_user:
                return jsonify({'message': '用户不存在'}), 401
            return f(current_user, *args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"Token验证失败: {str(e)}")
            return jsonify({'message': '无效的token'}), 401
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_admin:
                return jsonify({'message': '需要管理员权限'}), 403
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"管理员权限验证失败: {str(e)}")
            return jsonify({'message': '无效的token'}), 401
    return decorated

def permission_required(permission):
    """权限验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.has_permission(permission):
                current_app.logger.warning(f"User {current_user_id} attempted to access {permission} without permission")
                return jsonify({
                    'error': 'Insufficient permissions',
                    'error_code': 'INSUFFICIENT_PERMISSIONS'
                }), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_2fa():
    """二次验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.two_factor_enabled:
                current_app.logger.warning(f"User {current_user_id} attempted sensitive operation without 2FA")
                return jsonify({
                    'error': 'Two-factor authentication required',
                    'error_code': '2FA_REQUIRED'
                }), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required():
    """管理员权限验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.is_admin:
                current_app.logger.warning(f"User {current_user_id} attempted admin operation without permission")
                return jsonify({
                    'error': 'Admin privileges required',
                    'error_code': 'ADMIN_REQUIRED'
                }), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator 