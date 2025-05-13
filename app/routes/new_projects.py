from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from app import csrf
from app.models import Project, User, Task, TeamMember
from app import db
from datetime import datetime
import logging
from flask_jwt_extended import jwt_required, get_jwt_identity

project_bp = Blueprint('projects', __name__)
logger = logging.getLogger(__name__)

@project_bp.route('/detail/<int:project_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
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