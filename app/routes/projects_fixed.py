# -*- coding: utf-8 -*-

from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response
from flask import current_app
import pytz
from app import csrf  # 导入CSRFProtect实例
from app.models import Project, User, Task, TeamMember
from app.models.auth import User
from app import db
from datetime import datetime
import logging
from sqlalchemy import or_
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
import json

# 导入权限相关的工具
from app.utils.permissions import (
    permission_required, 
    can_manage_project, 
    PERMISSION_MANAGE_ALL_PROJECTS,
    PERMISSION_MANAGE_PROJECT,
    PERMISSION_VIEW_PROJECT,
    PERMISSION_CREATE_PROJECT,
    ROLE_ADMIN,
    ROLE_PROJECT_MANAGER
)

project_bp = Blueprint('projects', __name__)
logger = logging.getLogger(__name__)

# 定义一个新的蓝图专门用于调试API
debug_bp = Blueprint('debug', __name__)

# CSRF错误处理函数，使用蓝图的错误处理器
@project_bp.errorhandler(400)
def handle_csrf_error(e):
    # 检查是否是CSRF错误
    if 'CSRF' in str(e):
        logger.error(f"CSRF验证失败: {str(e)}")
        
        # 记录请求信息，帮助调试
        headers_info = {key: value for key, value in request.headers.items() 
                      if key.lower() not in ['cookie', 'authorization']}  # 排除敏感信息
        
        logger.warning(f"CSRF错误请求信息: 路径={request.path}, 方法={request.method}, 头部={headers_info}")
        
        # 返回JSON错误响应
        return jsonify({
            'error': 'CSRF验证失败',
            'detail': str(e),
            'message': '可能缺少必要的CSRF令牌，请刷新页面后重试'
        }), 400
    
    # 如果不是CSRF错误，则传递给下一个错误处理器
    return e

@project_bp.route('/<int:project_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_PROJECT)
def update_project(project_id):
    """更新项目信息"""
    
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"更新项目 {project_id} - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 确保用户有权限更新此项目
        user = User.query.get(current_user_id)
        if not (user.has_permission(PERMISSION_MANAGE_ALL_PROJECTS) or 
                project.owner_id == current_user_id or 
                project.manager_id == current_user_id):
            logger.warning(f"用户 {current_user_id} 无权更新项目 {project_id}")
            return jsonify({'error': '您没有权限更新此项目'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': '缺少更新数据'}), 400
        
        # 记录变更
        changes = []
        
        # 更新基本信息
        if 'name' in data and data['name'] != project.name:
            # 检查新名称是否已存在
            existing_project = Project.query.filter_by(name=data['name']).first()
            if existing_project and existing_project.id != project_id:
                return jsonify({'error': '项目名称已存在'}), 400
            changes.append(f'名称从 "{project.name}" 改为 "{data["name"]}"')
            project.name = data['name']
        
        if 'description' in data and data['description'] != project.description:
            changes.append('更新了描述')
            project.description = data['description']
        
        # 更新状态
        if 'status' in data and data['status'] != project.status:
            valid_statuses = ['active', 'completed', 'cancelled', 'on_hold']
            if data['status'] not in valid_statuses:
                return jsonify({'error': '无效的状态值'}), 400
            changes.append(f'状态从 "{project.status}" 改为 "{data["status"]}"')
            project.status = data['status']
            
        # 保存更改
        db.session.commit()
        
        # 记录变更日志
        if changes:
            logger.info(f"Project {project.id} updated by user {current_user_id}: {'; '.join(changes)}")
        
        return jsonify({
            'message': '项目更新成功',
            'project': project.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating project: {str(e)}")
        return jsonify({'error': f'更新项目失败: {str(e)}'}), 500
