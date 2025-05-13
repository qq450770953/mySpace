from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import User
from app.extensions import csrf, db

global_users_bp = Blueprint('global_users', __name__)

@global_users_bp.route('/api/global/users', methods=['GET'])
@csrf.exempt
def get_global_users():
    """获取所有用户的简化列表，用于下拉菜单选择"""
    try:
        # 检查是否有bypass_jwt参数，用于开发测试
        bypass_auth = request.args.get('bypass_jwt', 'false').lower() == 'true'
        
        # 如果不是bypass模式，尝试获取当前用户身份
        user_id = None
        if not bypass_auth:
            try:
                # 尝试从JWT获取用户身份
                user_id = get_jwt_identity()
            except:
                # 如果JWT验证失败，检查是否有cookie中的用户ID
                user_id = request.cookies.get('user_id')
        
        # 查询所有活跃用户
        users = User.query.filter(
            User.is_active == True
        ).order_by(User.name).all()
        
        # 构建简化的用户数据，返回必要字段
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'name': user.name or user.username,
                'username': user.username,
                'email': user.email,
                'role': getattr(user, 'role', None),
                'department': getattr(user, 'department', None),
                # 添加前端所需的状态字段
                'is_active': user.is_active,
                'status': '活跃' if user.is_active else '禁用',
                'status_color': 'success' if user.is_active else 'danger'
            })
        
        return jsonify(users_data)
        
    except Exception as e:
        current_app.logger.error(f"获取用户列表失败: {str(e)}")
        return jsonify({'error': '获取用户列表失败'}), 500 