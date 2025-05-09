from flask import Blueprint, request, jsonify, current_app, render_template, url_for, redirect
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.auth import User, Role, Permission
from app import db
from app.utils.permissions import role_required, permission_required, ROLE_ADMIN, ROLE_PROJECT_MANAGER, ROLE_USER
from app.utils.permissions import PERMISSION_MANAGE_USERS, PERMISSION_MANAGE_ROLES
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
import pytz

users_bp = Blueprint('users', __name__)
logger = logging.getLogger(__name__)

@users_bp.route('/api/users/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    token = generate_token(user)
    return jsonify({
        'token': token,
        'user': user.to_dict()
    })

@users_bp.route('/api/auth/users', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_USERS)
def get_users():
    """获取所有用户列表"""
    try:
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '')
        
        # 构建查询
        query = User.query
        
        # 搜索过滤
        if search:
            query = query.filter(
                (User.username.ilike(f'%{search}%')) | 
                (User.email.ilike(f'%{search}%')) | 
                (User.name.ilike(f'%{search}%'))
            )
        
        # 分页
        pagination = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page)
        
        # 准备响应数据
        users = [user.to_dict() for user in pagination.items]
        
        return jsonify({
            'users': users,
            'total': pagination.total,
            'pages': pagination.pages,
            'page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        current_app.logger.error(f"获取用户列表出错: {str(e)}")
        return jsonify({'error': '获取用户列表失败'}), 500

@users_bp.route('/api/auth/users', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_USERS)
def create_user():
    """创建新用户（仅管理员）"""
    try:
        data = request.get_json()
        
        # 验证必要字段
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'缺少必要字段: {field}'}), 400
        
        # 检查用户名和邮箱是否已存在
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': '用户名已存在'}), 400
            
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': '邮箱已被使用'}), 400
        
        # 创建新用户
        user = User(
            username=data['username'],
            email=data['email'],
            name=data.get('name', data['username']),
            is_active=data.get('is_active', True),
            created_at=datetime.now(pytz.utc)
        )
        user.set_password(data['password'])
        
        # 分配角色
        role_name = data.get('role', ROLE_USER)  # 默认为普通用户
        role = Role.query.filter_by(name=role_name).first()
        
        # 如果指定角色不存在，使用普通用户角色
        if not role:
            role = Role.query.filter_by(name=ROLE_USER).first()
            if not role:
                return jsonify({'error': '无法分配角色，角色不存在'}), 500
        
        user.roles.append(role)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': '用户创建成功',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"创建用户出错: {str(e)}")
        return jsonify({'error': '创建用户失败'}), 500

@users_bp.route('/api/auth/users/<int:user_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_USERS)
def get_user(user_id):
    """获取单个用户信息"""
    try:
        user = User.query.get_or_404(user_id)
        return jsonify(user.to_dict())
        
    except Exception as e:
        current_app.logger.error(f"获取用户信息出错: {str(e)}")
        return jsonify({'error': '获取用户信息失败'}), 500

@users_bp.route('/api/auth/users/<int:user_id>', methods=['PUT'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_USERS)
def update_user(user_id):
    """更新用户信息"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        # 更新基本信息
        if 'name' in data:
            user.name = data['name']
        if 'email' in data and data['email'] != user.email:
            # 检查邮箱是否已被使用
            if User.query.filter(User.email == data['email'], User.id != user_id).first():
                return jsonify({'error': '邮箱已被使用'}), 400
            user.email = data['email']
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        # 如果提供了新密码，更新密码
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        
        # 如果提供了角色，更新角色（仅限管理员）
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if 'role' in data and current_user.has_role(ROLE_ADMIN):
            # 清除现有角色
            user.roles = []
            
            # 添加新角色
            role = Role.query.filter_by(name=data['role']).first()
            if role:
                user.roles.append(role)
            else:
                return jsonify({'error': f'角色不存在: {data["role"]}'}), 400
        
        user.updated_at = datetime.now(pytz.utc)
        db.session.commit()
        
        return jsonify({
            'message': '用户信息更新成功',
            'user': user.to_dict()
        })
        
    except Exception as e:
        current_app.logger.error(f"更新用户信息出错: {str(e)}")
        return jsonify({'error': '更新用户信息失败'}), 500

@users_bp.route('/api/auth/users/<int:user_id>', methods=['DELETE'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_USERS)
def delete_user(user_id):
    """删除用户"""
    try:
        # 不允许自删除
        current_user_id = get_jwt_identity()
        if user_id == current_user_id:
            return jsonify({'error': '不能删除当前登录的用户账号'}), 400
        
        user = User.query.get_or_404(user_id)
        
        # 删除用户
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': f'用户 {user.username} 已成功删除'})
        
    except Exception as e:
        current_app.logger.error(f"删除用户出错: {str(e)}")
        return jsonify({'error': '删除用户失败'}), 500

@users_bp.route('/api/auth/users/<int:user_id>/role', methods=['PUT'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_USERS)
def update_user_role(user_id):
    """更新用户角色"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if not data or 'role' not in data:
            return jsonify({'error': '缺少角色信息'}), 400
        
        role_name = data['role']
        role = Role.query.filter_by(name=role_name).first()
        
        if not role:
            return jsonify({'error': f'角色不存在: {role_name}'}), 400
        
        # 清除现有角色并设置新角色
        user.roles = [role]
        db.session.commit()
        
        return jsonify({
            'message': f'用户角色已更新为 {role_name}',
            'user': user.to_dict()
        })
        
    except Exception as e:
        current_app.logger.error(f"更新用户角色出错: {str(e)}")
        return jsonify({'error': '更新用户角色失败'}), 500

@users_bp.route('/api/auth/roles', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_ROLES)
def get_roles():
    """获取所有角色列表"""
    try:
        roles = Role.query.all()
        roles_data = [role.to_dict() for role in roles]
        
        return jsonify({'roles': roles_data})
        
    except Exception as e:
        current_app.logger.error(f"获取角色列表出错: {str(e)}")
        return jsonify({'error': '获取角色列表失败'}), 500

@users_bp.route('/api/auth/permissions', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_MANAGE_ROLES)
def get_permissions():
    """获取所有权限列表"""
    try:
        permissions = Permission.query.all()
        permissions_data = [perm.to_dict() for perm in permissions]
        
        return jsonify({'permissions': permissions_data})
        
    except Exception as e:
        current_app.logger.error(f"获取权限列表出错: {str(e)}")
        return jsonify({'error': '获取权限列表失败'}), 500

@users_bp.route('/api/users/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        current_user = get_jwt_identity()
        user = User.query.get_or_404(current_user)
        return jsonify(user.to_dict())
    except Exception as e:
        logger.error(f"Error getting profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@users_bp.route('/api/users/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        current_user = get_jwt_identity()
        user = User.query.get_or_404(current_user)
        data = request.get_json()
        
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        if 'password' in data:
            user.set_password(data['password'])
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify(user.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({'error': str(e)}), 500 