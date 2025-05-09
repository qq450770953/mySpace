from flask import current_app, request, render_template, jsonify, redirect, url_for
from flask_jwt_extended import JWTManager, decode_token, verify_jwt_in_request
from app.models.auth import User, TokenBlacklist
from datetime import datetime, timedelta
from flask_jwt_extended.exceptions import NoAuthorizationError
import logging
from functools import wraps
from flask_wtf.csrf import generate_csrf

logger = logging.getLogger(__name__)

def log_jwt_error(func):
    """装饰器：记录 JWT 错误"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"JWT Error in {func.__name__}: {str(e)}")
            raise
    return wrapper

def setup_jwt_callbacks(jwt: JWTManager):
    """Setup JWT callbacks and error handlers"""
    
    # 移除不兼容的 csrf_check_loader
    # 新版本的Flask-JWT-Extended默认不强制CSRF保护
    # 而是在需要的路由上使用 jwt_required(csrf=True)
    
    @jwt.user_lookup_loader
    @log_jwt_error
    def user_lookup_callback(jwt_header, jwt_data):
        """根据JWT身份查找用户"""
        try:
            identity = jwt_data.get('sub')
            if not identity:
                logger.error("No identity found in token")
                return None
            
            logger.info(f"Looking up user with identity: {identity}")
            user = User.query.get(identity)
            
            if not user:
                logger.error(f"User not found with identity: {identity}")
                return None
            
            if not user.is_active:
                logger.error(f"User {user.username} is inactive")
                return None
            
            logger.info(f"User found: {user.username}")
            logger.info(f"User roles: {[role.name for role in user.roles]}")
            logger.info(f"User permissions: {[perm.name for role in user.roles for perm in role.permissions]}")
            
            return user
            
        except Exception as e:
            logger.error(f"Error in user lookup: {str(e)}")
            return None
    
    @jwt.token_in_blocklist_loader
    @log_jwt_error
    def check_if_token_in_blocklist(jwt_header, jwt_data):
        """检查令牌是否在黑名单中"""
        try:
            jti = jwt_data.get('jti')
            if not jti:
                logger.error("No JTI found in JWT data")
                return False
            
            logger.info(f"Checking if token {jti} is in blocklist")
            
            # 检查令牌是否过期
            exp = jwt_data.get('exp')
            if exp and datetime.fromtimestamp(exp, tz=current_app.config['TIMEZONE']) < datetime.now(current_app.config['TIMEZONE']):
                logger.warning(f"Token {jti} has expired")
                return True
            
            is_blocklisted = TokenBlacklist.is_blacklisted(jti)
            if is_blocklisted:
                logger.error(f"Token {jti} is blocklisted")
            else:
                logger.info(f"Token {jti} is valid")
            
            return is_blocklisted
            
        except Exception as e:
            logger.error(f"Error checking token blocklist: {str(e)}")
            return False
    
    @jwt.additional_claims_loader
    @log_jwt_error
    def add_additional_claims(identity):
        """添加额外的声明"""
        try:
            logger.info(f"Adding additional claims for user {identity}")
            user = User.query.get(identity)
            
            if not user:
                logger.error(f"User not found for identity: {identity}")
                return {}
            
            if not user.is_active:
                logger.warning(f"User {identity} is not active")
                return {}
            
            roles = [role.name for role in user.roles]
            permissions = [perm.name for role in user.roles for perm in role.permissions]
            
            claims = {
                'aud': current_app.config.get('JWT_AUDIENCE', 'task_management_system'),
                'user_claims': {
                    'username': user.username,
                    'roles': roles,
                    'permissions': permissions,
                    'is_active': user.is_active
                }
            }
            
            logger.info(f"Added claims for user {identity}: {claims}")
            return claims
            
        except Exception as e:
            logger.error(f"Error adding additional claims: {str(e)}")
            return {}
    
    @jwt.token_verification_loader
    @log_jwt_error
    def verify_token(jwt_header, jwt_data):
        """验证令牌"""
        try:
            logger.info("Verifying token")
            logger.info(f"JWT Header: {jwt_header}")
            logger.info(f"JWT Data: {jwt_data}")
            
            # 验证令牌类型
            if jwt_header.get('typ') != 'JWT':
                logger.error("Invalid token type")
                return False
            
            # 验证算法
            if jwt_header.get('alg') != current_app.config.get('JWT_ALGORITHM', 'HS256'):
                logger.error("Invalid algorithm")
                return False
            
            # 验证受众
            aud = jwt_data.get('aud')
            expected_aud = current_app.config.get('JWT_AUDIENCE', 'task_management_system')
            if aud != expected_aud:
                logger.error(f"Invalid audience: expected {expected_aud}, got {aud}")
                return False
            
            # 验证过期时间
            exp = jwt_data.get('exp')
            if exp and datetime.fromtimestamp(exp, tz=current_app.config['TIMEZONE']) < datetime.now(current_app.config['TIMEZONE']):
                logger.error("Token has expired")
                return False
            
            # 验证发行时间，添加更大的时间容差
            iat = jwt_data.get('iat')
            if iat:
                current_time = datetime.now(current_app.config['TIMEZONE'])
                token_time = datetime.fromtimestamp(iat, tz=current_app.config['TIMEZONE'])
                time_diff = (token_time - current_time).total_seconds()
                # 允许最多24小时的时间差
                if time_diff > 86400:
                    logger.error(f"Token issued too far in the future: {time_diff} seconds")
                    return False
                logger.info(f"Token time difference: {time_diff} seconds")
            
            # 验证用户声明
            user_claims = jwt_data.get('user_claims')
            if not user_claims:
                logger.error("Missing user claims in token")
                return False
            
            # 验证用户声明中的角色和权限
            if 'roles' not in user_claims or 'permissions' not in user_claims:
                logger.error("Missing roles or permissions in user claims")
                return False
            
            logger.info("Token verification successful")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying token: {str(e)}")
            return False
    
    @jwt.unauthorized_loader
    @log_jwt_error
    def missing_token_callback(error):
        """处理缺失令牌"""
        logger.error(f"Missing token: {str(error)}")
        if request.path.startswith('/api/'):
            response = {
                'error': 'Missing authorization token',
                'message': '请先登录',
                'status_code': 401
            }
            logger.info(f"Returning API response for missing token: {response}")
            return jsonify(response), 401
        
        logger.info("Redirecting to login page")
        return redirect(url_for('auth.login'))
    
    @jwt.invalid_token_loader
    @log_jwt_error
    def invalid_token_callback(error):
        """处理无效令牌"""
        logger.error(f"Invalid token: {str(error)}")
        if request.path.startswith('/api/'):
            response = {
                'error': 'Invalid token',
                'message': '无效的令牌',
                'status_code': 401,
                'details': str(error)
            }
            logger.info(f"Returning API response for invalid token: {response}")
            return jsonify(response), 401
        
        logger.info("Redirecting to login page")
        return redirect(url_for('auth.login'))
    
    @jwt.expired_token_loader
    @log_jwt_error
    def expired_token_callback(jwt_header, jwt_payload):
        """处理过期令牌"""
        logger.error("Token expired")
        if request.path.startswith('/api/'):
            response = {
                'error': 'Token expired',
                'message': '令牌已过期',
                'status_code': 401,
                'exp': jwt_payload.get('exp')
            }
            logger.info(f"Returning API response for expired token: {response}")
            return jsonify(response), 401
        
        logger.info("Redirecting to login page")
        return redirect(url_for('auth.login'))
    
    @jwt.needs_fresh_token_loader
    @log_jwt_error
    def token_not_fresh_callback(jwt_header, jwt_payload):
        """处理非新鲜令牌"""
        logger.error("Token not fresh")
        if request.path.startswith('/api/'):
            response = {
                'error': 'Token not fresh',
                'message': '需要刷新令牌',
                'status_code': 401
            }
            logger.info(f"Returning API response for non-fresh token: {response}")
            return jsonify(response), 401
        
        logger.info("Redirecting to login page")
        return redirect(url_for('auth.login'))
    
    @jwt.revoked_token_loader
    @log_jwt_error
    def revoked_token_callback(jwt_header, jwt_payload):
        """处理撤销令牌"""
        logger.error("Token has been revoked")
        if request.path.startswith('/api/'):
            response = {
                'error': 'Token revoked',
                'message': '令牌已被撤销',
                'status_code': 401
            }
            logger.info(f"Returning API response for revoked token: {response}")
            return jsonify(response), 401
        
        logger.info("Redirecting to login page")
        return redirect(url_for('auth.login'))
    
    # 删除不兼容的 csrf_error_loader 装饰器
    # 在新版本 Flask-JWT-Extended 中处理 CSRF 错误的函数
    def handle_csrf_error(error=None):
        """处理CSRF错误的函数"""
        logger.error(f"CSRF error: {str(error)}")
        
        # 检查是否有bypass_jwt参数
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
            
        if bypass_jwt:
            # 在bypass_jwt模式下，对所有请求自动绕过CSRF检查
            # 这是一个开发/测试特性，生产环境应该移除
            logger.info(f"绕过CSRF检查 (bypass_jwt参数): {request.path}")
            
            # 直接返回None，表示没有错误，让请求继续处理
            return None
            
        # 对于API路径，返回JSON错误响应
        if request.path.startswith('/api/'):
            response = {
                'error': 'CSRF token validation failed',
                'message': 'CSRF令牌验证失败，请确保令牌有效或刷新页面重试',
                'status_code': 401,
                'details': str(error) if error else 'Unknown CSRF error'
            }
            logger.info(f"Returning API response for CSRF error: {response}")
            return jsonify(response), 401
        
        # 对于普通页面请求，重定向到登录页面
        logger.info("Redirecting to login page due to CSRF error")
        return redirect(url_for('auth.login')) 