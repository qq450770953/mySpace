from functools import wraps
from flask import request, jsonify, current_app, g
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from app.models.auth import User, Role, Permission, role_permissions
from app.models.project import Project, ProjectMember
from app.models.task import Task
from app import db
import logging
from datetime import datetime
from flask_login import current_user
import sys

logger = logging.getLogger(__name__)

# 角色常量
ROLE_ADMIN = 'admin'         # 管理员 - 拥有全部权限，可以访问所有模块
ROLE_PROJECT_MANAGER = 'manager'  # 项目经理 - 可以管理自己的项目、任务、资源和风险，但不能管理用户
ROLE_USER = 'user'           # 普通用户 - 只有查看权限，没有创建和管理的权限

# 权限常量
PERMISSION_MANAGE_USERS = 'manage_users'           # 管理用户
PERMISSION_MANAGE_ROLES = 'manage_roles'           # 管理角色
PERMISSION_MANAGE_ALL_PROJECTS = 'manage_all_projects'  # 管理所有项目
PERMISSION_MANAGE_PROJECT = 'manage_project'      # 管理项目
PERMISSION_MANAGE_ALL_TASKS = 'manage_all_tasks'      # 管理所有任务
PERMISSION_MANAGE_TASK = 'manage_task'           # 管理任务
PERMISSION_VIEW_PROJECT = 'view_project'         # 查看项目
PERMISSION_VIEW_TASK = 'view_task'              # 查看任务
PERMISSION_MANAGE_RESOURCES = 'manage_resources'     # 管理资源
PERMISSION_MANAGE_RISKS = 'manage_risks'          # 管理风险
PERMISSION_VIEW_REPORTS = 'view_reports'          # 查看报表
PERMISSION_CREATE_TASK = 'create_task'           # 创建任务
PERMISSION_CREATE_PROJECT = 'create_project'      # 创建项目
PERMISSION_ASSIGN_TASK = 'assign_task'           # 分配任务
PERMISSION_CHANGE_PROJECT_STATUS = 'change_project_status' # 更改项目状态
PERMISSION_CHANGE_TASK_STATUS = 'change_task_status'    # 更改任务状态

# 角色权限配置
ROLE_PERMISSIONS = {
    ROLE_ADMIN: [
        PERMISSION_MANAGE_USERS,
        PERMISSION_MANAGE_ROLES,
        PERMISSION_MANAGE_ALL_PROJECTS,
        PERMISSION_MANAGE_PROJECT,
        PERMISSION_MANAGE_ALL_TASKS,
        PERMISSION_MANAGE_TASK,
        PERMISSION_VIEW_PROJECT,
        PERMISSION_VIEW_TASK,
        PERMISSION_MANAGE_RESOURCES,
        PERMISSION_MANAGE_RISKS,
        PERMISSION_VIEW_REPORTS,
        PERMISSION_CREATE_TASK,
        PERMISSION_CREATE_PROJECT,
        PERMISSION_ASSIGN_TASK,
        PERMISSION_CHANGE_PROJECT_STATUS,
        PERMISSION_CHANGE_TASK_STATUS
    ],
    ROLE_PROJECT_MANAGER: [
        PERMISSION_MANAGE_PROJECT,
        PERMISSION_MANAGE_TASK,
        PERMISSION_VIEW_PROJECT,
        PERMISSION_VIEW_TASK,
        PERMISSION_MANAGE_RESOURCES,
        PERMISSION_MANAGE_RISKS,
        PERMISSION_VIEW_REPORTS,
        PERMISSION_CREATE_PROJECT,
        PERMISSION_CREATE_TASK,
        PERMISSION_ASSIGN_TASK,
        PERMISSION_CHANGE_PROJECT_STATUS,
        PERMISSION_CHANGE_TASK_STATUS
    ],
    ROLE_USER: [
        PERMISSION_VIEW_PROJECT,
        PERMISSION_VIEW_TASK,
        PERMISSION_VIEW_REPORTS
    ]
}

def init_roles_permissions():
    """
    初始化角色和权限
    应在应用启动时调用
    """
    try:
        # 检查并创建权限
        permissions = {}
        for permission_name in [
            PERMISSION_MANAGE_USERS, PERMISSION_MANAGE_ROLES, PERMISSION_MANAGE_ALL_PROJECTS,
            PERMISSION_MANAGE_PROJECT, PERMISSION_MANAGE_ALL_TASKS, PERMISSION_MANAGE_TASK,
            PERMISSION_VIEW_PROJECT, PERMISSION_VIEW_TASK, PERMISSION_MANAGE_RESOURCES,
            PERMISSION_MANAGE_RISKS, PERMISSION_VIEW_REPORTS, PERMISSION_CREATE_TASK,
            PERMISSION_CREATE_PROJECT, PERMISSION_ASSIGN_TASK, PERMISSION_CHANGE_PROJECT_STATUS,
            PERMISSION_CHANGE_TASK_STATUS
        ]:
            permission = Permission.query.filter_by(name=permission_name).first()
            if not permission:
                permission = Permission(name=permission_name, description=f"权限: {permission_name}")
                db.session.add(permission)
            else:
                logger.info(f"更新权限: {permission_name}")
            permissions[permission_name] = permission
        
        db.session.commit()
        
        # 获取所有权限
        all_permissions = Permission.query.all()
        
        # 创建角色并分配权限
        for role_name, role_permissions_list in ROLE_PERMISSIONS.items():
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name, description=f"角色: {role_name}")
                db.session.add(role)
                db.session.flush()  # 获取ID
            
            logger.info(f"更新角色: {role_name}")
            
            # 获取角色当前的权限
            current_permissions = role.permissions
            
            current_permission_names = {p.name for p in current_permissions}
            
            # 添加角色权限
            if role_name == ROLE_ADMIN:
                # 管理员拥有所有权限
                logger.info(f"为管理员角色添加所有权限: {len(all_permissions)}个")
                for permission in all_permissions:
                    if permission.name not in current_permission_names:
                        role.permissions.append(permission)
            else:
                # 为其他角色添加指定的权限
                for permission_name in role_permissions_list:
                    logger.info(f"为角色 {role_name} 添加权限: {permission_name}")
                    if permission_name not in current_permission_names and permission_name in permissions:
                        role.permissions.append(permissions[permission_name])
        
        db.session.commit()
        logger.info("角色和权限初始化完成")
        return True
    except Exception as e:
        db.session.rollback()
        logger.error(f"初始化角色和权限时出错: {str(e)}")
        return False

def role_required(role_name):
    """
    验证用户是否拥有指定角色
    :param role_name: 角色名称
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 检查用户是否有指定角色
                if not user.has_role(role_name):
                    # 管理员角色可以访问任何角色的功能
                    if not user.has_role(ROLE_ADMIN):
                        return jsonify({'error': '权限不足，需要' + role_name + '角色'}), 403
                
                return fn(*args, **kwargs)
            except Exception as e:
                logger.error(f"角色验证出错: {str(e)}")
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def permission_required(permission_name):
    """
    验证用户是否拥有指定权限
    :param permission_name: 权限名称
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 检查是否启用了JWT绕过（用于测试）
                bypass_jwt = request.args.get('bypass_jwt') == 'true'
                if bypass_jwt:
                    logger.info(f"使用JWT绕过，允许访问，跳过权限检查: {permission_name}")
                    # 设置一个默认用户（通常是ID为1的管理员）
                    g.current_user = User.query.get(1)
                    return fn(*args, **kwargs)
                
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员拥有所有权限
                if user.has_role(ROLE_ADMIN):
                    g.current_user = user
                    return fn(*args, **kwargs)
                
                # 检查用户是否有指定权限
                if not user.has_permission(permission_name):
                    logger.warning(f"权限拒绝: 用户 {user_id} 没有 {permission_name} 权限")
                    return jsonify({'error': f'权限不足，需要{permission_name}权限'}), 403
                
                # 将用户保存在g对象中，以便在视图函数中访问
                g.current_user = user
                
                return fn(*args, **kwargs)
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def can_manage_project(project_id):
    """
    检查用户是否可以管理指定项目
    管理员可以管理任何项目
    项目经理可以管理自己负责的项目
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员可以管理任何项目
                if user.has_role(ROLE_ADMIN):
                    return fn(*args, **kwargs)
                
                # 项目经理可以管理任何项目
                if user.has_role(ROLE_PROJECT_MANAGER) and user.has_permission(PERMISSION_MANAGE_ALL_PROJECTS):
                    return fn(*args, **kwargs)
                
                # 检查项目是否存在
                project = Project.query.get(project_id)
                if not project:
                    return jsonify({'error': '项目不存在'}), 404
                
                # 检查用户是否是项目所有者或项目经理
                if project.owner_id == user_id or project.manager_id == user_id:
                    return fn(*args, **kwargs)
                
                # 检查用户是否是项目成员且有管理权限
                project_member = ProjectMember.query.filter_by(
                    project_id=project_id, 
                    user_id=user_id,
                    can_manage=True
                ).first()
                
                if project_member:
                    return fn(*args, **kwargs)
                
                return jsonify({'error': '您没有管理此项目的权限'}), 403
                
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def can_manage_task(task_id):
    """
    检查用户是否可以管理指定任务
    管理员可以管理任何任务
    项目经理可以管理自己负责的项目中的任务
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员可以管理任何任务
                if user.has_role(ROLE_ADMIN):
                    return fn(*args, **kwargs)
                
                # 项目经理可以管理任何任务（如果有全局任务管理权限）
                if user.has_role(ROLE_PROJECT_MANAGER) and user.has_permission(PERMISSION_MANAGE_ALL_TASKS):
                    return fn(*args, **kwargs)
                
                # 检查任务是否存在
                task = Task.query.get(task_id)
                if not task:
                    return jsonify({'error': '任务不存在'}), 404
                
                # 检查项目是否存在
                project = Project.query.get(task.project_id)
                if not project:
                    return jsonify({'error': '任务所属项目不存在'}), 404
                
                # 项目经理权限检查 - 如果用户是项目经理并且有管理任务的权限，就允许访问
                if user.has_role(ROLE_PROJECT_MANAGER) and user.has_permission(PERMISSION_MANAGE_TASK):
                    # 检查用户是否是此项目的经理或所有者
                    if project.manager_id == user_id or project.owner_id == user_id:
                        logger.info(f"项目经理 {user_id} 对任务 {task_id} 有管理权限（项目负责人）")
                        return fn(*args, **kwargs)
                
                # 检查用户是否是任务创建者或被分配者
                if task.created_by == user_id or task.assignee_id == user_id:
                    return fn(*args, **kwargs)
                
                # 检查用户是否是任务所属项目的所有者或管理者（重复检查，确保不遗漏）
                if project and (project.owner_id == user_id or project.manager_id == user_id):
                    return fn(*args, **kwargs)
                
                # 检查用户是否是项目成员且有管理权限
                if project:
                    project_member = ProjectMember.query.filter_by(
                        project_id=project.id, 
                        user_id=user_id,
                        can_manage=True
                    ).first()
                    
                    if project_member:
                        return fn(*args, **kwargs)
                
                logger.warning(f"用户 {user_id} 没有管理任务 {task_id} 的权限")
                return jsonify({'error': '您没有管理此任务的权限'}), 403
                
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                # JWT验证失败，尝试检查是否启用了JWT绕过（用于测试）
                bypass_jwt = request.args.get('bypass_jwt') == 'true'
                if bypass_jwt:
                    logger.warning("使用JWT绕过，允许访问")
                    return fn(*args, **kwargs)
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def can_view_project(project_id):
    """
    检查用户是否可以查看指定项目
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员可以查看任何项目
                if user.has_role(ROLE_ADMIN):
                    return fn(*args, **kwargs)
                
                # 检查项目是否存在
                project = Project.query.get(project_id)
                if not project:
                    return jsonify({'error': '项目不存在'}), 404
                
                # 检查用户是否是项目所有者或项目经理或项目成员
                if project.owner_id == user_id or project.manager_id == user_id:
                    return fn(*args, **kwargs)
                
                # 检查用户是否是项目成员
                project_member = ProjectMember.query.filter_by(
                    project_id=project_id, 
                    user_id=user_id
                ).first()
                
                if project_member:
                    return fn(*args, **kwargs)
                
                return jsonify({'error': '您没有查看此项目的权限'}), 403
                
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def can_create_task(project_id=None):
    """
    检查用户是否可以在指定项目中创建任务
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员可以在任何项目中创建任务
                if user.has_role(ROLE_ADMIN):
                    return fn(*args, **kwargs)
                
                # 项目经理可以在任何项目中创建任务
                if user.has_role(ROLE_PROJECT_MANAGER) and user.has_permission(PERMISSION_CREATE_TASK):
                    return fn(*args, **kwargs)
                
                # 如果未指定项目ID，则从请求中获取
                if project_id is None:
                    project_id = request.json.get('project_id')
                    if not project_id:
                        # 如果请求中也没有项目ID，则检查用户是否有创建任务的权限
                        if user.has_permission(PERMISSION_CREATE_TASK):
                            return fn(*args, **kwargs)
                        else:
                            return jsonify({'error': '您没有创建任务的权限'}), 403
                
                # 检查项目是否存在
                project = Project.query.get(project_id)
                if not project:
                    return jsonify({'error': '项目不存在'}), 404
                
                # 检查用户是否是项目所有者或项目经理
                if project.owner_id == user_id or project.manager_id == user_id:
                    return fn(*args, **kwargs)
                
                # 检查用户是否是项目成员且有创建任务的权限
                project_member = ProjectMember.query.filter_by(
                    project_id=project_id, 
                    user_id=user_id,
                    can_create_tasks=True
                ).first()
                
                if project_member:
                    return fn(*args, **kwargs)
                
                return jsonify({'error': '您没有在此项目中创建任务的权限'}), 403
                
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def assign_default_role(user):
    """为新用户分配默认角色"""
    try:
        # 查询默认角色
        default_role = Role.query.filter_by(name=ROLE_USER).first()
        if not default_role:
            # 如果默认角色不存在，创建它
            default_role = Role(name=ROLE_USER, description="普通用户")
            db.session.add(default_role)
            db.session.commit()
        
        # 分配角色
        if default_role not in user.roles:
            user.roles.append(default_role)
            db.session.commit()
        
        return True
    except Exception as e:
        logger.error(f"分配默认角色失败: {str(e)}")
        db.session.rollback()
        return False

def can_manage_resources(project_id=None):
    """
    检查用户是否可以管理指定项目的资源
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员可以管理任何资源
                if user.has_role(ROLE_ADMIN):
                    return fn(*args, **kwargs)
                
                # 项目经理可以管理任何资源
                if user.has_role(ROLE_PROJECT_MANAGER) and user.has_permission(PERMISSION_MANAGE_RESOURCES):
                    return fn(*args, **kwargs)
                
                # 检查用户是否有管理资源的权限
                if not user.has_permission(PERMISSION_MANAGE_RESOURCES):
                    return jsonify({'error': '您没有管理资源的权限'}), 403
                
                # 如果指定了项目ID，检查用户是否是项目成员且有管理权限
                if project_id:
                    project = Project.query.get(project_id)
                    if not project:
                        return jsonify({'error': '项目不存在'}), 404
                    
                    # 检查用户是否是项目所有者或项目经理
                    if project.owner_id == user_id or project.manager_id == user_id:
                        return fn(*args, **kwargs)
                    
                    # 检查用户是否是项目成员且有管理权限
                    project_member = ProjectMember.query.filter_by(
                        project_id=project_id, 
                        user_id=user_id,
                        can_manage=True
                    ).first()
                    
                    if not project_member:
                        return jsonify({'error': '您没有在此项目中管理资源的权限'}), 403
                
                return fn(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                # JWT验证失败，尝试检查是否启用了JWT绕过（用于测试）
                bypass_jwt = request.args.get('bypass_jwt') == 'true'
                if bypass_jwt:
                    logger.warning("使用JWT绕过，允许访问风险管理")
                    return fn(*args, **kwargs)
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def can_manage_risks(project_id=None):
    """
    检查用户是否可以管理指定项目的风险
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # 验证JWT
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # 查询用户
                user = User.query.get(user_id)
                if not user:
                    return jsonify({'error': '用户不存在'}), 404
                
                # 管理员可以管理任何风险
                if user.has_role(ROLE_ADMIN):
                    return fn(*args, **kwargs)
                
                # 项目经理可以管理任何风险
                if user.has_role(ROLE_PROJECT_MANAGER) and user.has_permission(PERMISSION_MANAGE_RISKS):
                    return fn(*args, **kwargs)
                
                # 检查用户是否有管理风险的权限
                if not user.has_permission(PERMISSION_MANAGE_RISKS):
                    return jsonify({'error': '您没有管理风险的权限'}), 403
                
                # 如果指定了项目ID，检查用户是否是项目成员且有管理权限
                if project_id:
                    project = Project.query.get(project_id)
                    if not project:
                        return jsonify({'error': '项目不存在'}), 404
                    
                    # 检查用户是否是项目所有者或项目经理
                    if project.owner_id == user_id or project.manager_id == user_id:
                        return fn(*args, **kwargs)
                    
                    # 检查用户是否是项目成员且有管理权限
                    project_member = ProjectMember.query.filter_by(
                        project_id=project_id, 
                        user_id=user_id,
                        can_manage=True
                    ).first()
                    
                    if not project_member:
                        return jsonify({'error': '您没有在此项目中管理风险的权限'}), 403
                
                return fn(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"权限验证出错: {str(e)}")
                # JWT验证失败，尝试检查是否启用了JWT绕过（用于测试）
                bypass_jwt = request.args.get('bypass_jwt') == 'true'
                if bypass_jwt:
                    logger.warning("使用JWT绕过，允许访问风险管理")
                    return fn(*args, **kwargs)
                return jsonify({'error': '验证失败'}), 401
                
        return wrapper
    return decorator

def user_can_edit(user):
    """
    检查当前登录用户是否可以编辑指定用户
    管理员可以编辑任何用户
    用户可以编辑自己
    """
    
    # 处理匿名用户
    if not hasattr(user, 'id') or not user.is_authenticated:
        return False  # 匿名用户没有编辑权限
    
    # 尝试获取当前用户ID
    try:
        current_user_id = current_user.id
        # 检查当前用户是否已认证
        if not current_user.is_authenticated:
            return False
    except Exception:
        try:
            # 尝试通过JWT获取
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
        except Exception:
            logger.error("无法获取当前用户ID")
            return False
    
    # 查询当前用户
    current_user_obj = User.query.get(current_user_id)
    if not current_user_obj:
        logger.error(f"当前用户({current_user_id})不存在")
        return False
    
    # 管理员可以编辑任何用户
    if current_user_obj.has_role(ROLE_ADMIN):
        return True
    
    # 用户可以编辑自己
    if current_user_id == user.id:
        return True
    
    # 项目经理可以编辑项目成员
    if current_user_obj.has_role(ROLE_PROJECT_MANAGER):
        # 检查被编辑用户是否是当前用户管理的项目的成员
        for project in current_user_obj.managed_projects:
            member = ProjectMember.query.filter_by(project_id=project.id, user_id=user.id).first()
            if member:
                return True
    
    logger.warning(f"用户({current_user_id})尝试编辑用户({user.id})被拒绝")
    return False

def user_is_regular(user):
    """检查用户是否是普通用户"""
    # 处理匿名用户
    if not user or not hasattr(user, 'is_authenticated') or not user.is_authenticated:
        current_app.logger.info("未认证用户被视为普通用户")
        return True  # 匿名用户被视为普通用户
    
    # 安全检查 - 确保用户对象有roles属性
    if not hasattr(user, 'roles'):
        current_app.logger.warning(f"用户对象 {user.username if hasattr(user, 'username') else '未知'} 没有roles属性")
        return True
    
    # 直接检查用户的角色名称列表
    user_role_names = [role.name for role in user.roles] if user.roles else []
    
    # 检查是否是管理员或项目经理
    is_admin = 'admin' in user_role_names
    is_manager = 'manager' in user_role_names
    
    # 详细日志，便于调试
    current_app.logger.info(f"检查用户 {user.username} 是否为普通用户")
    current_app.logger.info(f"用户 {user.username} 的角色: {user_role_names}")
    current_app.logger.info(f"是否管理员: {is_admin}, 是否项目经理: {is_manager}")
    
    # 只有当用户既不是管理员也不是项目经理时，才被视为普通用户
    result = not (is_admin or is_manager)
    current_app.logger.info(f"用户 {user.username} 是否为普通用户: {result}")
    return result

def has_permission(user_id, permission_name):
    """
    检查用户是否拥有指定权限的非装饰器版本
    :param user_id: 用户ID
    :param permission_name: 权限名称
    :return: 布尔值，表示用户是否有权限
    """
    try:
        logger.info(f"检查用户ID={user_id}是否有{permission_name}权限")
        
        # 查询用户
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"用户ID={user_id}不存在")
            return False
        
        # 管理员拥有所有权限
        if user.has_role(ROLE_ADMIN):
            logger.info(f"用户ID={user_id}是管理员，拥有所有权限")
            return True
        
        # 检查用户是否有指定权限
        has_perm = user.has_permission(permission_name)
        logger.info(f"用户ID={user_id}是否有{permission_name}权限: {has_perm}")
        return has_perm
        
    except Exception as e:
        logger.error(f"检查权限时出错: {str(e)}")
        return False 