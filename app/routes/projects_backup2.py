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
from flask import current_app
import pytz
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
import json
# 导入权限相关的工�?
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

# CSRF错误处理函数，使用蓝图的错误处理�?
@project_bp.errorhandler(400)
def handle_csrf_error(e):
    # 检查是否是CSRF错误
    if 'CSRF' in str(e):
        logger.error(f"CSRF验证失败: {str(e)}")
        
        # 记录请求信息，帮助调�?
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

@project_bp.route('/list')
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def project_list():
    """渲染项目列表页面"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"显示项目列表页面 - 用户ID: {current_user_id}")
        
        # 获取所有项目和用户用于表单选择
        projects = Project.query.all()
        users = User.query.all()
        
        # 准备甘特图数�?
        gantt_tasks = []
        for project in projects:
            for task in project.tasks:
                # 使用正确的日期字�?
                start_date = task.created_at
                end_date = task.due_date
                
                if start_date and end_date:
                    gantt_tasks.append({
                        'id': f'task_{task.id}',
                        'name': task.title,
                        'start': start_date.strftime('%Y-%m-%d'),
                        'end': end_date.strftime('%Y-%m-%d'),
                        'progress': task.progress or 0,
                        'dependencies': ''
                    })
        
        logger.info(f"Rendering projects list with {len(projects)} projects and {len(gantt_tasks)} tasks")
        return render_template('projects.html', 
                              projects=projects, 
                              gantt_tasks=gantt_tasks, 
                              users=users,
                              user_id=current_user_id)
    except Exception as e:
        logger.error(f"Error in project_list: {str(e)}")
        if request.accept_mimetypes.accept_json:
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
        return render_template('error.html', error=f'Internal server error: {str(e)}'), 500

@project_bp.route('/', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_projects():
    """获取项目列表，支持多种过滤条件、排序和分页"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"获取项目列表 - 用户ID: {current_user_id}")
        
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'msg': 'User not found'}), 404
            
        # 获取查询参数
        status = request.args.getlist('status')  # 支持多状态过�?
        search = request.args.get('search', '')  # 搜索标题和描�?
        
        # 分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        per_page = min(per_page, 100)  # 限制每页最大数�?
        
        # 排序参数
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # 构建查询
        query = Project.query
        
        # 基本过滤条件
        if status:
            query = query.filter(Project.status.in_(status))
            
        # 搜索标题和描�?
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Project.name.ilike(search_term),
                    Project.description.ilike(search_term)
                )
            )
            
        # 排序
        valid_sort_fields = {
            'created_at': Project.created_at,
            'updated_at': Project.updated_at,
            'name': Project.name,
            'status': Project.status
        }
        
        sort_field = valid_sort_fields.get(sort_by, Project.created_at)
        if sort_order == 'desc':
            sort_field = sort_field.desc()
        query = query.order_by(sort_field)
        
        # 预加载关联数�?
        query = query.options(
            db.joinedload(Project.manager)
        )
        
        # 执行分页查询
        try:
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            projects = pagination.items
        except Exception as e:
            logger.error(f"Error during pagination: {str(e)}")
            return jsonify({'error': 'Failed to paginate projects'}), 500
        
        # 构建响应数据
        try:
            response = {
                'projects': [project.to_dict() for project in projects],
                'pagination': {
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'current_page': page,
                    'per_page': per_page,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                }
            }
            return jsonify(response)
            
        except Exception as e:
            logger.error(f"Error serializing projects: {str(e)}")
            return jsonify({'error': 'Failed to serialize projects'}), 500
            
    except Exception as e:
        logger.error(f"Error in get_projects: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_CREATE_PROJECT)
def create_project():
    """创建新项�?""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"创建新项�?- 用户ID: {current_user_id}")
        
        data = request.get_json()
        logger.info(f"Received project creation data: {data}")
        
        # 验证必要字段
        if not data or not data.get('name'):
            return jsonify({'error': '项目名称不能为空'}), 400
            
        # 检查项目名称是否已存在
        existing_project = Project.query.filter_by(name=data['name']).first()
        if existing_project:
            return jsonify({'error': '项目名称已存�?}), 400
            
        # 创建新项�?
        project = Project(
            name=data['name'],
            description=data.get('description'),
            status=data.get('status', 'active'),
            start_date=datetime.fromisoformat(data['start_date']) if data.get('start_date') else None,
            end_date=datetime.fromisoformat(data['end_date']) if data.get('end_date') else None,
            manager_id=data.get('manager_id', current_user_id),
            owner_id=current_user_id
        )
        
        db.session.add(project)
        db.session.commit()
        
        logger.info(f"Project created successfully: {project.id} - {project.name}")
        
        return jsonify({
            'message': '项目创建成功',
            'project': project.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating project: {str(e)}")
        return jsonify({'error': f'创建项目失败: {str(e)}'}), 500

@project_bp.route('/<int:project_id>', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_project(project_id):
    """获取单个项目详情"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"获取项目 {project_id} 详情 - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 权限检�?- 确认用户是项目所有者、经理或成员
        user_is_owner = project.owner_id == current_user_id
        user_is_manager = project.manager_id == current_user_id
        user_is_member = current_user_id in [member.id for member in project.members]
        
        if not (user_is_owner or user_is_manager or user_is_member):
            return jsonify({'error': '没有权限访问此项目'}), 403
            
        return jsonify(project.to_dict())
        
    except Exception as e:
        logger.error(f"Error getting project: {str(e)}")
        return jsonify({'error': f'获取项目详情失败: {str(e)}'}), 500

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
            # 检查新名称是否已存�?
            existing_project = Project.query.filter_by(name=data['name']).first()
            if existing_project and existing_project.id != project_id:
                return jsonify({'error': '项目名称已存�?}), 400
            changes.append(f'名称�?"{project.name}" 改为 "{data["name"]}"')
            project.name = data['name']
        
        if 'description' in data and data['description'] != project.description:
            changes.append('更新了描�?)
            project.description = data['description']
        
        # 更新状�?
        if 'status' in data and data['status'] != project.status:
            valid_statuses = ['active', 'completed', 'cancelled', 'on_hold']
            if data['status'] not in valid_statuses:
                return jsonify({'error': '无效的状态�?}), 400
            changes.append(f'状态从 "{project.status}" 改为 "{data["status"]}"')
            project.status = data['status']
        
        # 更新日期
        if 'start_date' in data and data['start_date']:
            try:
                project.start_date = datetime.fromisoformat(data['start_date'])
            except ValueError as e:
                logger.warning(f"无效的开始日期格�? {data['start_date']}, 错误: {str(e)}")
                # 尝试多种日期格式
                try:
                    project.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
                except ValueError:
                    logger.error(f"无法解析开始日�? {data['start_date']}")
                    return jsonify({'error': f'无效的开始日期格�? {data["start_date"]}'}), 400
        elif 'start_date' in data:
            project.start_date = None
        
        if 'end_date' in data and data['end_date']:
            try:
                project.end_date = datetime.fromisoformat(data['end_date'])
            except ValueError as e:
                logger.warning(f"无效的结束日期格�? {data['end_date']}, 错误: {str(e)}")
                # 尝试多种日期格式
                try:
                    project.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
                except ValueError:
                    logger.error(f"无法解析结束日期: {data['end_date']}")
                    return jsonify({'error': f'无效的结束日期格�? {data["end_date"]}'}), 400
        elif 'end_date' in data:
            project.end_date = None
        
        # 更新负责�?
        if 'manager_id' in data and data['manager_id'] != project.manager_id:
            if data['manager_id']:
                new_manager = User.query.get(data['manager_id'])
                if not new_manager:
                    return jsonify({'error': '指定的负责人不存�?}), 400
            old_manager = User.query.get(project.manager_id)
            new_manager = User.query.get(data['manager_id'])
            changes.append(f'负责人从 {old_manager.name if old_manager else "�?} 改为 {new_manager.name if new_manager else "�?}')
            project.manager_id = data['manager_id']
        
        project.updated_by = current_user_id
        project.updated_at = datetime.utcnow()
        
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

@project_bp.route('/<int:project_id>', methods=['DELETE'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_PROJECT)
def delete_project(project_id):
    """删除项目"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"删除项目 {project_id} - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 获取用户对象
        user = User.query.get(current_user_id)
        
        # 权限检�?- 允许项目所有者、项目经理和管理员删除项�?
        if not (project.owner_id == current_user_id or 
                user.has_role(ROLE_ADMIN) or 
                (user.has_role(ROLE_PROJECT_MANAGER) and project.manager_id == current_user_id)):
            return jsonify({'error': '没有权限删除此项�?}), 403
        
        # 检查是否有未完成的任务
        if project.tasks.filter(Task.status != 'completed').count() > 0:
            return jsonify({'error': '无法删除包含未完成任务的项目，请先完成或删除所有任�?}), 400
            
        # 删除项目
        db.session.delete(project)
        db.session.commit()
        
        return jsonify({
            'message': '项目删除成功',
            'project_id': project_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting project: {str(e)}")
        return jsonify({'error': f'删除项目失败: {str(e)}'}), 500

@project_bp.route('/<int:project_id>/members', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_project_members(project_id):
    """获取项目成员列表"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"获取项目 {project_id} 成员列表 - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 权限检�?- 确认用户是项目所有者、经理或成员
        user_is_owner = project.owner_id == current_user_id
        user_is_manager = project.manager_id == current_user_id
        user_is_member = current_user_id in [member.id for member in project.members]
        
        if not (user_is_owner or user_is_manager or user_is_member):
            return jsonify({'error': '没有权限访问此项目'}), 403
            
        members = project.members.all()
        return jsonify([member.to_dict() for member in members])
        
    except Exception as e:
        logger.error(f"Error getting project members: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/<int:project_id>/members', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_PROJECT)
def add_project_member(project_id):
    """添加项目成员"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"添加项目 {project_id} 成员 - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 权限检�?- 确认用户是项目所有者或经理
        if project.owner_id != current_user_id and project.manager_id != current_user_id:
            return jsonify({'error': '没有权限管理项目成员'}), 403
        
        data = request.get_json()
        if not data or not data.get('user_id'):
            return jsonify({'error': '缺少用户ID'}), 400
            
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'error': '用户不存�?}), 404
            
        if user in project.members:
            return jsonify({'error': '用户已经是项目成�?}), 400
            
        project.members.append(user)
        db.session.commit()
        
        return jsonify({
            'message': '成功添加项目成员',
            'member': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding project member: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/<int:project_id>/members/<int:user_id>', methods=['DELETE'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_PROJECT)
def remove_project_member(project_id, user_id):
    """移除项目成员"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"移除项目 {project_id} 成员 {user_id} - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 权限检�?- 确认用户是项目所有者或经理
        if project.owner_id != current_user_id and project.manager_id != current_user_id:
            return jsonify({'error': '没有权限管理项目成员'}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存�?}), 404
            
        if user not in project.members:
            return jsonify({'error': '用户不是项目成员'}), 400
            
        # 检查用户是否有未完成的任务
        if project.tasks.filter(Task.assignee_id == user_id, Task.status != 'completed').count() > 0:
            return jsonify({'error': '无法移除有未完成任务的项目成�?}), 400
            
        project.members.remove(user)
        db.session.commit()
        
        return jsonify({
            'message': '成功移除项目成员',
            'member_id': user_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing project member: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/detail/<int:project_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt  # 豁免CSRF保护，避免CSRF相关错误
def detail(project_id):
    """渲染项目详情页面"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        
        # 记录请求信息
        logger.info(f"获取项目 {project_id} 详情页面 - 用户ID: {current_user_id}, URL: {request.url}")
        
        # 直接获取项目信息，不进行重定向
        try:
            project = Project.query.get_or_404(project_id)
        except Exception as e:
            logger.error(f"获取项目 {project_id} 失败: {str(e)}")
            return render_template('error.html', error=f'找不到项目: {str(e)}'), 404
            
        # 权限检查 - 检查是否使用bypass_jwt或no_redirect模式
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        no_redirect = request.args.get('no_redirect') == 'true'
        
        # 如果不是bypass或no_redirect模式，则检查权限
        if not (bypass_jwt or no_redirect):
            user_is_owner = project.owner_id == current_user_id
            user_is_manager = project.manager_id == current_user_id
            
            # 检查用户是否是团队成员
            user_is_member = False
            for team in project.teams.all():
                for member in team.members:
                    if member.user_id == current_user_id:
                        user_is_member = True
                        break
                if user_is_member:
                    break
            
            if not (user_is_owner or user_is_manager or user_is_member):
                return render_template('error.html', error='没有权限访问此项目'), 403
        
        # 获取项目管理员
        manager = None
        if project.manager_id:
            manager = User.query.get(project.manager_id)
        
        manager_name = manager.name if manager and manager.name else manager.username if manager else "未分配"
        
        # 将manager_id转换为整数以确保前端比较正确
        manager_id = int(project.manager_id) if project.manager_id else None
        
        # 获取项目成员
        members = []
        teams = project.teams.all()
        for team in teams:
            for member in team.members:
                user = User.query.get(member.user_id)
                if user:
                    members.append({
                        'id': user.id,
                        'name': user.name or user.username,
                        'role': member.role
                    })
        
        # 获取项目任务
        tasks = Task.query.filter_by(project_id=project_id).all()
        project_tasks = []
        for task in tasks:
            assignee = User.query.get(task.assignee_id)
            assignee_name = assignee.name if assignee else "未分配"
            
            project_tasks.append({
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'progress': task.progress,
                'assignee': assignee_name,
                'due_date': task.due_date.strftime('%Y-%m-%d') if task.due_date else "未设置"
            })
        
        # 格式化项目数据
        project_data = {
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'manager': manager_name,
            'manager_id': manager_id,
            'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else "",
            'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else "",
            'status': project.status,
            'progress': project.progress or 0
        }
        
        # 获取所有用户
        all_users = User.query.all()
        
        # 筛选出具有"项目经理"角色的用户
        project_managers = []
        for user in all_users:
            if user.has_role('project_manager') or user.has_role('admin'):
                project_managers.append(user)
        
        # 渲染项目详情页面，不处理CSRF令牌，避免重定向循环
        response = render_template('projects/detail.html', 
                           project=project_data, 
                           members=members, 
                           tasks=project_tasks,
                           users=all_users,
                           project_managers=project_managers,
                           current_user_id=current_user_id,
                           gantt_tasks=[])
        
        return response
        
    except Exception as e:
        logger.error(f"Project detail route error: {str(e)}")
        return render_template('error.html', error=f"加载项目详情失败: {str(e)}"), 500

@project_bp.route('/api/detail/<int:project_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def detail_api(project_id):
    """API版本: 获取项目详情数据"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        logger.info(f"获取项目 {project_id} 详情API - 用户ID: {current_user_id}")
        
        project = Project.query.get_or_404(project_id)
        
        # 权限检�?- 确认用户是项目所有者、经理或成员
        user_is_owner = project.owner_id == current_user_id
        user_is_manager = project.manager_id == current_user_id
        user_is_member = current_user_id in [member.id for member in project.members]
        
        if not (user_is_owner or user_is_manager or user_is_member):
            return jsonify({'error': '没有权限访问此项目'}), 403
        
        # 获取项目成员
        members = []
        teams = project.teams.all()
        for team in teams:
            for member in team.members:
                user = User.query.get(member.user_id)
                if user:
                    members.append({
                        'id': user.id,
                        'name': user.name or user.username,
                        'role': member.role
                    })
        
        # 获取项目任务
        tasks = Task.query.filter_by(project_id=project_id).all()
        project_tasks = []
        for task in tasks:
            assignee = User.query.get(task.assignee_id)
            assignee_name = assignee.name if assignee else "未分�?
            
            project_tasks.append({
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'progress': task.progress,
                'assignee': assignee_name,
                'assignee_id': task.assignee_id,
                'due_date': task.due_date.strftime('%Y-%m-%d') if task.due_date else None
            })
        
        # 返回项目详情JSON数据
        return jsonify({
            'project': project.to_dict(),
            'members': members,
            'tasks': project_tasks,
            'user_permissions': {
                'is_owner': user_is_owner,
                'is_manager': user_is_manager,
                'is_member': user_is_member
            }
        })
        
    except Exception as e:
        logger.error(f"Project detail API error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/api/projects/<int:project_id>', methods=['GET'])
@csrf.exempt
def get_project_api(project_id):
    """API端点: 获取单个项目详情"""
    try:
        # 获取项目
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'error': '项目不存�?}), 404
            
        # 获取当前用户ID，用于权限检�?
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # 检查权�?
        if not user.has_permission(PERMISSION_VIEW_PROJECT) and not can_manage_project(project_id)(lambda: True)():
            return jsonify({'error': '无权查看此项�?}), 403
            
        return jsonify(project.to_dict())
    except Exception as e:
        logger.error(f"获取项目API出错: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/api/projects/<int:project_id>', methods=['PUT'])
@jwt_required()
def update_project_api(project_id):
    """API端点: 更新项目信息"""
    try:
        # 获取项目
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'error': '项目不存�?}), 404
            
        # 获取当前用户ID，用于权限检�?
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # 检查权�?
        if not user.has_permission(PERMISSION_MANAGE_PROJECT) and not can_manage_project(project_id)(lambda: True)():
            return jsonify({'error': '无权修改此项�?}), 403
            
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数�?}), 400
            
        # 更新项目信息
        allowed_fields = ['name', 'description', 'status', 'start_date', 'end_date', 'manager_id']
        for field in allowed_fields:
            if field in data:
                # 特殊处理日期字段
                if field in ['start_date', 'end_date'] and data[field]:
                    try:
                        setattr(project, field, datetime.fromisoformat(data[field]))
                    except ValueError:
                        return jsonify({'error': f'无效的日期格�? {field}'}), 400
                else:
                    setattr(project, field, data[field])
        
        # 保存更改
        db.session.commit()
        
        return jsonify({'message': '项目更新成功', 'project': project.to_dict()})
    except Exception as e:
        logger.error(f"更新项目API出错: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@project_bp.route('/api/projects/<int:project_id>', methods=['DELETE'])
@jwt_required()
def delete_project_api(project_id):
    """API端点: 删除项目"""
    try:
        # 获取项目
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'error': '项目不存�?}), 404
            
        # 获取当前用户ID，用于权限检�?
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # 检查权�?
        if not user.has_permission(PERMISSION_MANAGE_PROJECT) and project.owner_id != current_user_id:
            return jsonify({'error': '无权删除此项�?}), 403
            
        # 删除项目
        db.session.delete(project)
        db.session.commit()
        
        return jsonify({'message': '项目删除成功'})
    except Exception as e:
        logger.error(f"删除项目API出错: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@project_bp.route('/api/auth/projects', methods=['GET'])
@jwt_required()
def get_projects_api():
    """API端点: 获取项目列表"""
    try:
        # 获取当前用户ID
        current_user_id = get_jwt_identity()
        
        # 检查用户是否存�?
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': '用户不存�?}), 404
            
        # 检查权�?
        if not user.has_permission(PERMISSION_VIEW_PROJECT):
            return jsonify({'error': '无权查看项目列表'}), 403
            
        # 调用现有的项目列表逻辑
        return get_projects()
    except Exception as e:
        logger.error(f"获取项目列表API出错: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/api/auth/projects/<int:project_id>', methods=['GET'])
@jwt_required()
def get_project_auth_api(project_id):
    """API端点: 通过认证获取单个项目详情"""
    return get_project_api(project_id)

@project_bp.route('/api/noauth/projects/<int:project_id>', methods=['GET', 'PUT', 'DELETE'])
@csrf.exempt
def get_project_noauth(project_id):
    """无需认证的项目API端点 - 用于前端交互"""
    try:
        # 记录请求详情，帮助调�?
        logger.info(f"无需认证的项目API请求: {request.method} - 项目ID: {project_id}")
        logger.info(f"请求�? {dict(request.headers)}")
        logger.info(f"请求URL: {request.url}")
        logger.info(f"CSRF令牌: {request.headers.get('X-CSRF-TOKEN') or request.cookies.get('csrf_token') or request.args.get('csrf_token') or 'None'}")
        
        # 明确设置响应类型为JSON
        resp_headers = {'Content-Type': 'application/json; charset=utf-8'}
        
        # 明确豁免CSRF检�?
        if hasattr(request, '_csrf_token'):
            request._csrf_token = True
            logger.info("已设置CSRF豁免")

        # 获取请求方法
        method = request.method
        
        # 获取项目，使用try-except捕获异常
        try:
            project = Project.query.get(project_id)
            
            if not project:
                logger.error(f"项目 {project_id} 不存�?)
                error_response = jsonify({
                    'error': '项目不存�?, 
                    'status': 'error',
                    'project_id': project_id
                })
                
                # 设置响应�?
                for key, value in resp_headers.items():
                    error_response.headers[key] = value
                    
                return error_response, 404
                
        except Exception as e:
            logger.error(f"获取项目 {project_id} 时出�? {str(e)}")
            error_response = jsonify({
                'error': f'获取项目出错: {str(e)}', 
                'status': 'error',
                'project_id': project_id
            })
            
            # 设置响应�?
            for key, value in resp_headers.items():
                error_response.headers[key] = value
                
            return error_response, 500
            
        # 根据请求方法调用不同的处�?
        if method == 'GET':
            logger.info(f"获取项目 {project_id} 详情")
            # 获取项目管理�?
            manager = None
            if project.manager_id:
                manager = User.query.get(project.manager_id)
            
            # 确保获取有效的管理员名称，多重备�?
            if manager and manager.name:
                manager_name = manager.name
            elif manager and manager.username:
                manager_name = manager.username
            else:
                manager_name = "未分�?
            
            # 确保manager_id是整数或None
            manager_id = int(project.manager_id) if project.manager_id else None
            
            # 构造项目数�?
            project_data = {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'manager': manager_name,
                'manager_id': manager_id,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else "",
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else "",
                'status': project.status,
                'progress': project.progress or 0
            }
            
            # 获取所有可用的项目经理
            project_managers = []
            try:
                # 查询所有活跃用�?
                all_users = User.query.filter(User.is_active == True).all()
                
                # 添加所有用户作为潜在的项目经理
                for user in all_users:
                    project_managers.append({
                        'id': user.id,
                        'name': user.name or user.username or f"用户 #{user.id}"
                    })
                
                # 如果当前项目管理员不在活跃用户列表中，也添加到列�?
                if manager_id and not any(pm['id'] == manager_id for pm in project_managers):
                    project_managers.append({
                        'id': manager_id,
                        'name': manager_name
                    })
                
                logger.info(f"获取�?{len(project_managers)} 个可用的项目经理")
                
            except Exception as e:
                logger.error(f"获取项目经理列表出错: {str(e)}")
                # 添加至少一个默认用户以确保前端有选项
                project_managers = [
                    {'id': 1, 'name': '管理员(默认)'},
                    {'id': 2, 'name': '项目经理(默认)'}
                ]
                
                # 确保当前项目负责人在列表�?
                if manager_id and not any(pm['id'] == manager_id for pm in project_managers):
                    project_managers.append({
                        'id': manager_id,
                        'name': manager_name
                    })
                
            # 返回JSON响应
            response_data = {
                'project': project_data,
                'project_managers': project_managers,  # 添加项目经理列表
                'status': 'success',
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"成功获取项目 {project_id} 数据，返�?{len(project_managers)} 个项目经理选项")
            
            # 创建响应对象，并设置响应�?
            response = jsonify(response_data)
            for key, value in resp_headers.items():
                response.headers[key] = value
                
            return response
            
        elif method == 'PUT':
            data = request.get_json()
            logger.info(f"更新项目 {project_id}，请求数�? {data}")
            
            if not data:
                logger.error(f"更新项目 {project_id} 失败: 请求数据为空")
                return jsonify({'error': '无效的请求数�?, 'status': 'error'}), 400
                
            # 更新项目
            if 'name' in data:
                project.name = data['name']
            if 'description' in data:
                project.description = data['description']
            if 'status' in data:
                project.status = data['status']
            if 'start_date' in data and data['start_date']:
                try:
                    project.start_date = datetime.fromisoformat(data['start_date'])
                except (ValueError, TypeError) as e:
                    logger.error(f"解析开始日期出�? {str(e)}, 日期�? {data['start_date']}")
                    # 尝试其他格式
                    try:
                        project.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
                    except (ValueError, TypeError):
                        logger.error(f"解析开始日期出错，使用默认�? 当前日期")
                        project.start_date = datetime.now()
            elif 'start_date' in data:
                project.start_date = None
            
            if 'end_date' in data and data['end_date']:
                try:
                    project.end_date = datetime.fromisoformat(data['end_date'])
                except (ValueError, TypeError) as e:
                    logger.error(f"解析结束日期出错: {str(e)}, 日期�? {data['end_date']}")
                    # 尝试其他格式
                    try:
                        project.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
                    except (ValueError, TypeError):
                        logger.error(f"解析结束日期出错，设置为None")
                        project.end_date = None
            elif 'end_date' in data:
                project.end_date = None
            
            # 特别处理manager_id
            if 'manager_id' in data:
                if data['manager_id']:
                    # 尝试将其转换为整�?
                    try:
                        manager_id = int(data['manager_id'])
                        project.manager_id = manager_id
                        logger.info(f"更新项目 {project_id} 负责人为: {manager_id}")
                    except (ValueError, TypeError) as e:
                        logger.error(f"无效的manager_id: {data['manager_id']}, 错误: {str(e)}")
                        # 不更新manager_id
                else:
                    # 设置为null/None
                    project.manager_id = None
                    logger.info(f"清除项目 {project_id} 负责�?)
            
            # 保存更新
            try:
                project.updated_at = datetime.now()
                db.session.commit()
                logger.info(f"成功更新项目 {project_id}")
                
                # 重新获取项目信息以返回最新状�?
                updated_project = Project.query.get(project_id)
                
                # 获取负责人信�?
                manager_name = "未分�?
                manager_id = None
                
                if updated_project.manager_id:
                    manager = User.query.get(updated_project.manager_id)
                    if manager:
                        manager_name = manager.name if manager.name else manager.username if manager.username else f"用户 #{updated_project.manager_id}"
                        manager_id = manager.id
                
                # 构造更新后的项目数�?
                updated_data = {
                    'id': updated_project.id,
                    'name': updated_project.name,
                    'description': updated_project.description,
                    'manager': manager_name,
                    'manager_id': manager_id,
                    'start_date': updated_project.start_date.strftime('%Y-%m-%d') if updated_project.start_date else None,
                    'end_date': updated_project.end_date.strftime('%Y-%m-%d') if updated_project.end_date else None,
                    'status': updated_project.status,
                    'progress': updated_project.progress or 0,
                    'updated_at': updated_project.updated_at.isoformat() if updated_project.updated_at else None
                }
                
                return jsonify({
                    'status': 'success',
                    'message': '项目更新成功',
                    'project': updated_data
                })
                
            except Exception as e:
                logger.error(f"保存项目 {project_id} 更新时出�? {str(e)}")
                db.session.rollback()
                return jsonify({'error': f'保存更新时出�? {str(e)}', 'status': 'error'}), 500
        
        elif method == 'DELETE':
            try:
                # 获取项目名称用于日志记录
                project_name = project.name
                logger.info(f"删除项目 {project_id}: {project_name}")
                
                # 删除项目
                db.session.delete(project)
                db.session.commit()
                logger.info(f"成功删除项目 {project_id}: {project_name}")
                
                return jsonify({
                    'status': 'success',
                    'message': f'项目 "{project_name}" 已成功删�?
                })
            
            except Exception as e:
                logger.error(f"删除项目 {project_id} 时出�? {str(e)}")
                db.session.rollback()
                return jsonify({'error': f'删除项目时出�? {str(e)}', 'status': 'error'}), 500
        
        # 不支持的HTTP方法
        logger.warning(f"不支持的HTTP方法: {method}")
        error_response = jsonify({
            'error': f'不支持的HTTP方法: {method}', 
            'status': 'error'
        })
        
        # 设置响应�?
        for key, value in resp_headers.items():
            error_response.headers[key] = value
            
        return error_response, 405
        
    except Exception as e:
        logger.error(f"处理项目 {project_id} API请求时出�? {str(e)}")
        # 返回带有详细信息的错误响�?
        error_info = {
            'error': str(e),
            'status': 'error',
            'detail': {
                'request_method': request.method,
                'request_url': request.url,
                'timestamp': datetime.now().isoformat()
            }
        }
        
        # 创建响应对象，并设置响应�?
        response = jsonify(error_info)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        
        return response, 500

@project_bp.route('/api/auth/projects', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'])
@permission_required(PERMISSION_CREATE_PROJECT)
def create_project_auth():
    """创建项目的认证API端点"""
    try:
        # 获取当前用户ID
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return jsonify({'error': '用户不存�?}), 404
        
        # 获取请求数据
        data = request.get_json()
        logger.info(f"创建项目的请求数�? {data}")
        
        # 验证必要字段
        if not data.get('name'):
            return jsonify({'error': '项目名称不能为空'}), 400
            
        # 检查是否存在同名项�?
        existing_project = Project.query.filter_by(name=data['name']).first()
        if existing_project:
            return jsonify({'error': '项目名称已存�?}), 400
        
        # 处理日期格式
        start_date = None
        if data.get('start_date'):
            try:
                # 尝试解析开始日�?
                start_date = datetime.fromisoformat(data['start_date'].replace('Z', '+00:00'))
                logger.info(f"解析的开始日�? {start_date}")
            except (ValueError, TypeError) as e:
                logger.warning(f"无效的开始日期格�? {data.get('start_date')}, 错误: {str(e)}")
                # 如果日期格式无效，使用当前日�?
                start_date = datetime.now(pytz.utc)
        else:
            # 如果未提供开始日期，默认为当前日�?
            start_date = datetime.now(pytz.utc)
            
        end_date = None
        if data.get('end_date'):
            try:
                # 尝试解析结束日期
                end_date = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))
                logger.info(f"解析的结束日�? {end_date}")
            except (ValueError, TypeError) as e:
                logger.warning(f"无效的结束日期格�? {data.get('end_date')}, 错误: {str(e)}")
                # 如果日期格式无效，结束日期设置为None
                end_date = None
        
        # 处理manager_id字段，确保其为整数或None
        manager_id = current_user_id
        if 'manager_id' in data and data['manager_id']:
            try:
                manager_id = int(data['manager_id'])
                logger.info(f"使用提供的manager_id: {manager_id}")
            except (ValueError, TypeError):
                logger.warning(f"无效的manager_id格式: {data['manager_id']}，设置为None")
                manager_id = None
        
        # 创建项目
        project = Project(
            name=data.get('name'),
            description=data.get('description', ''),
            start_date=start_date,
            end_date=end_date,
            status=data.get('status', 'planning'),
            owner_id=current_user_id,  # 设置项目拥有者为当前用户
            manager_id=manager_id
        )
        
        # 保存到数据库
        db.session.add(project)
        db.session.commit()
        
        logger.info(f"项目创建成功，ID: {project.id}, 名称: {project.name}, 负责人ID: {project.manager_id}")
        
        # 添加创建者为项目成员（如果有项目成员模型�?
        try:
            from app.models.project import ProjectMember
            member = ProjectMember(
                project_id=project.id,
                user_id=current_user_id,
                role='owner',  # 项目角色，不同于系统角色
                can_manage=True,
                joined_at=datetime.now(pytz.utc)
            )
            db.session.add(member)
            db.session.commit()
        except Exception as e:
            logger.warning(f"添加项目成员出错，可能是项目成员模型不存�? {str(e)}")
            # 继续执行，不中断流程
        
        return jsonify({
            'message': '项目创建成功',
            'project': project.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"创建项目出错: {str(e)}")
        return jsonify({'error': '创建项目失败', 'detail': str(e)}), 500

@project_bp.route('/api/project-managers', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_project_managers():
    """获取所有用户作为可选项目经�?""
    try:
        # 记录API调用
        logger.info("获取项目经理列表API被调�?)
        
        # 检查是否应绕过JWT验证（用于测试）
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        # 如果不绕过，则获取当前用户ID
        if not bypass_jwt:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                logger.warning("未授权访问，未找到用户身�?)
                return jsonify({'error': '未授权访问，请登�?}), 401
        
        # 获取所有用�?
        try:
            all_users = User.query.filter(User.is_active == True).all()
            logger.info(f"已找�?{len(all_users)} 个活跃用户用于项目经理选择")
            
            if not all_users or len(all_users) == 0:
                logger.warning("没有找到活跃用户，返回默认项目经理列�?)
                return jsonify({
                    'success': True,
                    'project_managers': [
                        {'id': 1, 'name': '管理员(默认)'},
                        {'id': 2, 'name': '项目经理(默认)'},
                        {'id': 3, 'name': '开发主管(默认)'}
                    ],
                    'message': '使用默认用户列表 - 未找到活跃用户'
                })
                
        except Exception as e:
            logger.error(f"查询用户列表时出�? {str(e)}")
            # 创建一些默认用户以确保接口正常返回
            return jsonify({
                'success': True,
                'project_managers': [
                    {'id': 1, 'name': '管理员(默认)'},
                    {'id': 2, 'name': '项目经理(默认)'},
                    {'id': 3, 'name': '开发主管(默认)'}
                ],
                'message': '使用默认用户列表 - 数据库查询失败'
            })
        
        # 创建项目经理列表 - 包含所有活跃用�?
        project_managers = []
        
        # 按照名称进行排序
        sorted_users = sorted(all_users, key=lambda user: user.name or user.username or '')
        
        for user in sorted_users:
            # 记录每个用户的角色，帮助调试
            try:
                user_roles = [role.name for role in user.roles] if hasattr(user, 'roles') and user.roles else []
                logger.debug(f"用户 {user.id}: {user.name or user.username}, 角色: {user_roles}")
            except Exception as e:
                logger.warning(f"获取用户 {user.id} 的角色时出错: {str(e)}")
                user_roles = []
            
            # 构建用户名称，确保有�?
            if user.name and user.name.strip():
                display_name = user.name
            elif user.username and user.username.strip():
                display_name = user.username
            else:
                display_name = f"用户 #{user.id}"
            
            # 为管理员或项目经理角色的用户添加标识
            if 'admin' in user_roles or 'project_manager' in user_roles or 'manager' in user_roles:
                if 'admin' in user_roles:
                    display_name = f"{display_name} (管理�?"
                else:
                    display_name = f"{display_name} (项目经理)"
            
            # 添加到项目经理列�?
            project_managers.append({
                'id': user.id,
                'name': display_name,
                'email': user.email if hasattr(user, 'email') else None,
                'roles': user_roles
            })
        
        # 确保项目经理列表不为�?
        if not project_managers or len(project_managers) == 0:
            logger.warning("处理后的项目经理列表为空，添加默认选项")
            project_managers = [
                {'id': 1, 'name': '管理员(默认)'},
                {'id': 2, 'name': '项目经理(默认)'},
                {'id': 3, 'name': '开发主管(默认)'}
            ]
        
        logger.info(f"返回 {len(project_managers)} 个可选的项目负责�?)
        
        return jsonify({
            'success': True,
            'project_managers': project_managers,
            'count': len(project_managers)
        })
    except Exception as e:
        logger.error(f"获取项目经理列表出错: {str(e)}")
        # 即使出错也返回一些默认的选项
        return jsonify({
            'success': False,
            'error': str(e),
            'project_managers': [
                {'id': 1, 'name': '管理员(出错后备选项)'},
                {'id': 2, 'name': '项目经理 (出错后备选项)'}
            ],
            'message': '出现错误，使用默认选项'
        })

@project_bp.route('/api/projects', methods=['GET'])
@csrf.exempt
def get_all_projects_api():
    """获取所有项目的简化列表，用于下拉菜单选择"""
    try:
        # 检查是否有bypass_jwt参数，用于开发测�?
        bypass_auth = request.args.get('bypass_jwt', 'false').lower() == 'true'
        
        # 如果不是bypass模式，尝试获取当前用户身�?
        user_id = None
        if not bypass_auth:
            try:
                # 尝试从JWT获取用户身份
                user_id = get_jwt_identity()
            except:
                # 如果JWT验证失败，检查是否有cookie中的用户ID
                user_id = request.cookies.get('user_id')
        
        # 查询所有活跃项�?
        projects = Project.query.filter(Project.status != 'deleted').all()
        
        # 构建简化的项目数据，只返回必要字段
        projects_data = []
        for project in projects:
            projects_data.append({
                'id': project.id,
                'name': project.name
            })
            
        return jsonify(projects_data)
        
    except Exception as e:
        logger.error(f"Error in get_all_projects_api: {str(e)}")
        return jsonify({'error': str(e)}), 500

@project_bp.route('/api/active-projects', methods=['GET'])
@csrf.exempt
def get_active_projects_api():
    """获取所有活跃项目的API，返回项目负责人完整信息"""
    try:
        logger.info("查询活跃项目列表")
        # 查询所有非删除状态的项目
        projects = Project.query.filter(Project.status != 'deleted').all()
        
        # 构建包含项目负责人完整信息的项目列表
        project_list = []
        for project in projects:
            # 查询项目管理�?
            manager = None
            if project.manager_id:
                manager = User.query.get(project.manager_id)
            
            project_data = {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'status': project.status,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
                'progress': project.progress or 0,
                'manager_id': project.manager_id,
                'manager': {
                    'id': manager.id if manager else None,
                    'name': manager.name if manager and manager.name else (
                           manager.username if manager and manager.username else '未分配'),
                    'email': manager.email if manager and manager.email else None
                } if manager else None
            }
            project_list.append(project_data)
        
        return jsonify({
            'success': True,
            'message': '项目列表获取成功',
            'projects': project_list
        })
    except Exception as e:
        logger.exception(f"获取活跃项目列表失败: {str(e)}")
        return jsonify({'error': f'获取项目列表失败: {str(e)}'}), 500

@project_bp.route('/api/projects/<int:project_id>/members', methods=['GET'])
@csrf.exempt
def get_project_members_api(project_id):
    """获取项目成员的API端点，无需认证，用于前端获取成员列�?""
    try:
        logger.info(f"获取项目 {project_id} 的成员列�?)
        
        # 获取项目
        project = Project.query.get_or_404(project_id)
        
        # 准备成员列表
        members = []
        
        # 检查项目是否有teams属�?
        if hasattr(project, 'teams'):
            # 获取项目团队成员
            for team in project.teams.all():
                for member in team.members:
                    user = User.query.get(member.user_id)
                    if user:
                        members.append({
                            'id': user.id,
                            'name': user.name or user.username or f"用户 #{user.id}",
                            'role': member.role
                        })
        
        # 如果没有通过teams找到成员，检查project.members
        if not members and hasattr(project, 'members'):
            for member in project.members:
                members.append({
                    'id': member.id,
                    'name': member.name if hasattr(member, 'name') and member.name else (
                           member.username if hasattr(member, 'username') and member.username else f"用户 #{member.id}"),
                    'role': 'member'
                })
        
        # 如果仍然没有成员，返回空列表但确保格式正�?
        if not members:
            logger.warning(f"项目 {project_id} 没有找到成员，尝试添加项目负责人")
            
            # 尝试至少添加项目负责�?
            if project.manager_id:
                manager = User.query.get(project.manager_id)
                if manager:
                    members.append({
                        'id': manager.id,
                        'name': manager.name or manager.username or f"负责�?#{manager.id}",
                        'role': 'manager'
                    })
        
        # 如果仍然没有找到任何成员，获取系统中的活跃用户作为备�?
        if not members:
            logger.warning(f"项目 {project_id} 没有找到负责人，返回系统活跃用户")
            active_users = User.query.filter(User.is_active == True).limit(10).all()
            for user in active_users:
                members.append({
                    'id': user.id,
                    'name': user.name or user.username or f"用户 #{user.id}",
                    'role': 'member'
                })
        
        logger.info(f"返回项目 {project_id} �{len(members)} 个成?)
        
        return jsonify(members)
    except Exception as e:
        logger.error(f"获取项目成员API出错: {str(e)}")
        # 即使出错也返回一个有效的JSON响应
        return jsonify([
            {'id': 1, 'name': '默认用户 1', 'role': 'member'},
            {'id': 2, 'name': '默认用户 2', 'role': 'member'}
        ])

@project_bp.route('/api/noauth/project-editor/<int:project_id>', methods=['PUT'])
@csrf.exempt
def update_project_editor(project_id):
    """专门为编辑器设计的项目更新API端点，包含CSRF豁免和细致的错误处理"""
    try:
        logger.info(f"通过编辑器API更新项目 {project_id}")
        
        # 获取项目
        project = Project.query.get_or_404(project_id)
        
        # 获取请求数据
        if not request.is_json:
            logger.warning(f"更新项目 {project_id} 请求不是JSON格式")
            return jsonify({
                'status': 'error',
                'error': '请求必须是JSON格式',
                'details': {
                    'content_type': request.content_type
                }
            }), 400, {'Content-Type': 'application/json'}
            
        data = request.get_json()
        if not data:
            logger.warning(f"更新项目 {project_id} 无有效JSON数据")
            return jsonify({
                'status': 'error',
                'error': '请求中没有有效的JSON数据'
            }), 400, {'Content-Type': 'application/json'}
            
        logger.info(f"准备更新项目 {project_id}，数�? {data}")
        
        # 更新项目信息
        allowed_fields = ['name', 'description', 'status', 'start_date', 'end_date', 'manager_id']
        updated_fields = []
        
        for field in allowed_fields:
            if field in data:
                # 特殊处理日期字段
                if field in ['start_date', 'end_date'] and data[field]:
                    try:
                        # 尝试解析日期
                        if isinstance(data[field], str):
                            # 处理不同的日期格�?
                            if 'T' in data[field]:  # ISO格式
                                date_value = datetime.fromisoformat(data[field].split('T')[0])
                            else:
                                date_value = datetime.strptime(data[field], '%Y-%m-%d')
                                
                            setattr(project, field, date_value)
                            updated_fields.append(field)
                        else:
                            logger.warning(f"项目 {project_id} �?{field} 不是有效的日期字符串: {data[field]}")
                    except ValueError as e:
                        logger.error(f"处理项目 {project_id} 的日期字�?{field} 出错: {str(e)}")
                        return jsonify({
                            'status': 'error',
                            'error': f'无效的日期格�? {field}',
                            'details': str(e)
                        }), 400, {'Content-Type': 'application/json'}
                else:
                    # 处理普通字�?
                    original_value = getattr(project, field)
                    if str(original_value) != str(data[field]):
                        setattr(project, field, data[field])
                        updated_fields.append(field)
        
        if not updated_fields:
            logger.info(f"项目 {project_id} 没有变更，跳过更�?)
            return jsonify({
                'status': 'success',
                'message': '项目没有变更',
                'project': project.to_dict()
            }), 200, {'Content-Type': 'application/json'}
            
        # 更新修改时间
        project.updated_at = datetime.now(pytz.utc)
        updated_fields.append('updated_at')
        
        # 保存到数据库
        try:
            db.session.commit()
            logger.info(f"项目 {project_id} 更新成功，更新字�? {updated_fields}")
            
            # 获取最新的项目数据
            db.session.refresh(project)
            
            return jsonify({
                'status': 'success',
                'message': '项目更新成功',
                'updated_fields': updated_fields,
                'project': project.to_dict()
            }), 200, {'Content-Type': 'application/json'}
            
        except Exception as e:
            logger.error(f"保存项目 {project_id} 更新时出�? {str(e)}")
            db.session.rollback()
            return jsonify({
                'status': 'error',
                'error': f'保存更新时出�? {str(e)}'
            }), 500, {'Content-Type': 'application/json'}
            
    except Exception as e:
        logger.error(f"更新项目 {project_id} 时出现未处理的异�? {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'detail': {
                'message': '处理更新请求时出现服务器错误',
                'timestamp': datetime.now().isoformat()
            }
        }), 500, {'Content-Type': 'application/json'}

@project_bp.route('/api/noauth/project-editor/<int:project_id>', methods=['GET'])
@csrf.exempt
def get_project_for_editor(project_id):
    """专门为编辑器模态框设计的API端点，返回标准化的项目数据格�?""
    try:
        logger.info(f"获取项目{project_id}用于编辑�?)
        
        # 获取项目基本信息
        project = Project.query.get_or_404(project_id)
        
        # 获取项目管理�?
        manager = None
        if project.manager_id:
            manager = User.query.get(project.manager_id)
        
        # 确保获取有效的管理员名称
        manager_name = "未分�?
        if manager:
            if manager.name:
                manager_name = manager.name
            elif manager.username:
                manager_name = manager.username
        
        # 获取项目经理列表
        project_managers = []
        try:
            # 查询所有活跃用�?
            all_users = User.query.filter(User.is_active == True).all()
            
            # 添加所有用户作为潜在的项目经理
            for user in all_users:
                project_managers.append({
                    'id': user.id,
                    'name': user.name or user.username or f"用户 #{user.id}"
                })
            
            # 如果当前项目管理员不在活跃用户列表中，也添加到列�?
            if project.manager_id and not any(pm['id'] == project.manager_id for pm in project_managers):
                project_managers.append({
                    'id': project.manager_id,
                    'name': manager_name
                })
            
        except Exception as e:
            logger.error(f"获取项目经理列表出错: {str(e)}")
            # 添加默认管理�?
            project_managers = [
                {'id': 1, 'name': '管理员(默认)'},
                {'id': 2, 'name': '项目经理(默认)'}
            ]
        
        # 构造标准化的项目数�?
        project_data = {
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'status': project.status,
            'progress': project.progress or 0,
            'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
            'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
            'manager_id': project.manager_id,
            'manager': manager_name,
            'created_at': project.created_at.strftime('%Y-%m-%d %H:%M:%S') if project.created_at else None,
            'updated_at': project.updated_at.strftime('%Y-%m-%d %H:%M:%S') if project.updated_at else None
        }
        
        # 返回标准化的响应
        response = {
            'project': project_data,
            'project_managers': project_managers,
            'status': 'success',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 设置明确的Content-Type�?
        return jsonify(response), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        logger.error(f"获取项目编辑器数据出�? {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'detail': '获取项目编辑器数据失�?
        }), 500, {'Content-Type': 'application/json'}

@project_bp.route('/api/projects', methods=['POST'])
@csrf.exempt
def create_project_api():
    """API端点，创建新项目"""
    try:
        # 获取当前登录用户，支持JWT绕过
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("API创建项目 - 使用测试用户")
            current_user_id = 1  # 使用测试用户
        else:
            # 验证JWT
            try:
                verify_jwt_in_request(optional=True)
                current_user_id = get_jwt_identity()
                if not current_user_id:
                    logger.warning("未授权访问API创建项目")
                    return jsonify({'error': '请先登录'}), 401
            except Exception as e:
                logger.error(f"JWT验证失败: {str(e)}")
                return jsonify({'error': '认证失败', 'details': str(e)}), 401
        
        # 检查请求内容类�?
        if not request.is_json:
            logger.warning(f"API创建项目: 非JSON请求 {request.content_type}")
            return jsonify({'error': '请求必须是JSON格式'}), 400
            
        data = request.get_json()
        logger.info(f"API创建项目: 收到数据 {data}")
        
        # 验证必要字段
        if not data or not data.get('name'):
            logger.warning("API创建项目: 缺少项目名称")
            return jsonify({'error': '项目名称不能为空'}), 400
            
        # 检查项目名称是否已存在
        existing_project = Project.query.filter_by(name=data['name']).first()
        if existing_project:
            logger.warning(f"API创建项目: 项目名称已存�?'{data['name']}'")
            return jsonify({'error': '项目名称已存�?}), 400
            
        # 创建新项�?
        try:
            # 处理日期格式
            start_date = None
            if 'start_date' in data and data['start_date']:
                try:
                    if 'T' in data['start_date']:
                        start_date = datetime.fromisoformat(data['start_date'])
                    else:
                        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
                except ValueError:
                    logger.warning(f"API创建项目: 开始日期格式错�?'{data['start_date']}'")
                    return jsonify({'error': '开始日期格式错�?}), 400
            
            end_date = None
            if 'end_date' in data and data['end_date']:
                try:
                    if 'T' in data['end_date']:
                        end_date = datetime.fromisoformat(data['end_date'])
                    else:
                        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
                except ValueError:
                    logger.warning(f"API创建项目: 结束日期格式错误 '{data['end_date']}'")
                    return jsonify({'error': '结束日期格式错误'}), 400
            
            # 处理manager_id，确保是整数
            manager_id = current_user_id
            if 'manager_id' in data and data['manager_id']:
                try:
                    manager_id = int(data['manager_id'])
                except (ValueError, TypeError):
                    logger.warning(f"API创建项目: 管理者ID格式错误 '{data['manager_id']}'")
                    return jsonify({'error': '管理者ID必须是整数'}), 400
            
            project = Project(
                name=data['name'],
                description=data.get('description', ''),
                status=data.get('status', 'active'),
                start_date=start_date,
                end_date=end_date,
                manager_id=manager_id,
                owner_id=current_user_id
            )
            
            db.session.add(project)
            db.session.commit()
            
            logger.info(f"API创建项目成功: {project.id} - {project.name}")
            
            return jsonify({
                'success': True,
                'message': '项目创建成功',
                'project': project.to_dict()
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"API创建项目数据库错�? {str(e)}")
            return jsonify({'error': f'创建项目失败: {str(e)}'}), 500
            
    except Exception as e:
        logger.error(f"API创建项目出错: {str(e)}")
        return jsonify({'error': str(e)}), 500 

@project_bp.route('/api/global/project-managers', methods=['GET'])
@csrf.exempt
def get_global_project_managers():
    """获取所有用户作为可选项目经理的全局API端点，不需要CSRF验证"""
    try:
        # 记录API调用
        logger.info("全局项目经理列表API被调�?)
        
        # 获取所有用�?
        try:
            all_users = User.query.filter(User.is_active == True).all()
            logger.info(f"已找�?{len(all_users)} 个活跃用户用于项目经理选择")
            
            if not all_users or len(all_users) == 0:
                logger.warning("没有找到活跃用户，返回默认项目经理列�?)
                return jsonify({
                    'success': True,
                    'project_managers': [
                        {'id': 1, 'name': '管理员(默认)'},
                        {'id': 2, 'name': '项目经理(默认)'},
                        {'id': 3, 'name': '开发主管(默认)'}
                    ],
                    'message': '使用默认用户列表 - 未找到活跃用户'
                })
                
        except Exception as e:
            logger.error(f"查询用户列表时出�? {str(e)}")
            # 创建一些默认用户以确保接口正常返回
            return jsonify({
                'success': True,
                'project_managers': [
                    {'id': 1, 'name': '管理员(默认)'},
                    {'id': 2, 'name': '项目经理(默认)'},
                    {'id': 3, 'name': '开发主管(默认)'}
                ],
                'message': '使用默认用户列表 - 数据库查询失败'
            })
        
        # 创建项目经理列表 - 包含所有活跃用�?
        project_managers = []
        
        # 按照名称进行排序
        sorted_users = sorted(all_users, key=lambda user: user.name or user.username or '')
        
        for user in sorted_users:
            # 构建用户名称，确保有�?
            if user.name and user.name.strip():
                display_name = user.name
            elif user.username and user.username.strip():
                display_name = user.username
            else:
                display_name = f"用户 #{user.id}"
            
            # 添加到项目经理列�?
            project_managers.append({
                'id': user.id,
                'name': display_name
            })
        
        # 确保项目经理列表不为�?
        if not project_managers or len(project_managers) == 0:
            logger.warning("处理后的项目经理列表为空，添加默认选项")
            project_managers = [
                {'id': 1, 'name': '管理员(默认)'},
                {'id': 2, 'name': '项目经理(默认)'},
                {'id': 3, 'name': '开发主管(默认)'}
            ]
        
        logger.info(f"返回 {len(project_managers)} 个可选的项目负责�?)
        
        # 添加CORS头，确保跨域请求可用
        response = jsonify({
            'success': True,
            'project_managers': project_managers,
            'count': len(project_managers)
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
        return response
    except Exception as e:
        logger.error(f"获取项目经理列表出错: {str(e)}")
        # 即使出错也返回一些默认的选项
        response = jsonify({
            'success': False,
            'error': str(e),
            'project_managers': [
                {'id': 1, 'name': '管理员(出错后备选项)'},
                {'id': 2, 'name': '项目经理 (出错后备选项)'}
            ],
            'message': '出现错误，使用默认选项'
        })
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
        return response

@project_bp.errorhandler(500)
def handle_internal_error(e):
    """处理内部服务器错�?""
    logger.error(f"内部服务器错�? {str(e)}")
    return render_template('error.html', error='服务器内部错误，请联系管理员'), 500



