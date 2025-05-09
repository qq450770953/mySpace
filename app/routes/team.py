from flask import Blueprint, request, jsonify, render_template
from app.models.team import TeamMember, TeamMessage, ResourceAllocation, TeamNotification
from app.models.task import Project, Task
from app.models.auth import User
from app.extensions import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
import psutil
import json
import random
import logging

team_bp = Blueprint('team', __name__)
logger = logging.getLogger(__name__)

# 团队成员管理
@team_bp.route('/api/teams/<int:project_id>/members', methods=['GET'])
@jwt_required()
def get_team_members(current_user, project_id):
    """获取项目团队成员"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    members = TeamMember.query.filter_by(project_id=project_id).all()
    return jsonify([member.to_dict() for member in members])

@team_bp.route('/api/teams/<int:project_id>/members', methods=['POST'])
@jwt_required()
def add_team_member(current_user, project_id):
    """添加团队成员"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    data = request.get_json()
    if not data or not data.get('user_id') or not data.get('role'):
        return jsonify({'error': '缺少必要字段'}), 400
    
    # 检查用户是否存在
    user = User.query.get(data['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    # 检查是否已经是团队成员
    existing_member = TeamMember.query.filter_by(
        project_id=project_id,
        user_id=data['user_id']
    ).first()
    if existing_member:
        return jsonify({'error': '用户已经是团队成员'}), 400
    
    member = TeamMember(
        project_id=project_id,
        user_id=data['user_id'],
        role=data['role'],
        skills=data.get('skills', []),
        added_by=current_user,
        added_at=datetime.utcnow()
    )
    
    db.session.add(member)
    db.session.commit()
    
    return jsonify(member.to_dict()), 201

@team_bp.route('/api/teams/<int:project_id>/members/<int:member_id>', methods=['GET'])
@jwt_required()
def get_team_member(current_user, project_id, member_id):
    """获取团队成员详情"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    member = TeamMember.query.get_or_404(member_id)
    if member.project_id != project_id:
        return jsonify({'error': '成员不属于此项目'}), 400
    
    return jsonify(member.to_dict())

@team_bp.route('/api/teams/<int:project_id>/members/<int:member_id>', methods=['PUT'])
@jwt_required()
def update_team_member(current_user, project_id, member_id):
    """更新团队成员信息"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    member = TeamMember.query.get_or_404(member_id)
    if member.project_id != project_id:
        return jsonify({'error': '成员不属于此项目'}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({'error': '无效的请求数据'}), 400
    
    if 'role' in data:
        member.role = data['role']
    if 'skills' in data:
        member.skills = data['skills']
    if 'workload' in data:
        member.workload = float(data['workload'])
    
    db.session.commit()
    return jsonify(member.to_dict())

@team_bp.route('/api/teams/<int:project_id>/members/<int:member_id>', methods=['DELETE'])
@jwt_required()
def delete_team_member(current_user, project_id, member_id):
    """删除团队成员"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    member = TeamMember.query.get_or_404(member_id)
    if member.project_id != project_id:
        return jsonify({'error': '成员不属于此项目'}), 400
    
    db.session.delete(member)
    db.session.commit()
    return jsonify({'message': '成员已删除'})

# 团队消息
@team_bp.route('/api/teams/<int:project_id>/messages', methods=['GET'])
@jwt_required()
def get_team_messages(current_user, project_id):
    """获取团队消息"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    messages = TeamMessage.query.filter_by(project_id=project_id).order_by(
        TeamMessage.created_at.desc()
    ).all()
    return jsonify([message.to_dict() for message in messages])

@team_bp.route('/api/teams/<int:project_id>/messages', methods=['POST'])
@jwt_required()
def send_team_message(current_user, project_id):
    """发送团队消息"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    data = request.get_json()
    if not data or not data.get('content'):
        return jsonify({'error': '消息内容不能为空'}), 400
    
    message = TeamMessage(
        project_id=project_id,
        sender_id=current_user.id,
        content=data['content'],
        message_type=data.get('message_type', 'text'),
        file_path=data.get('file_path')
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify(message.to_dict()), 201

# 资源管理
@team_bp.route('/api/teams/<int:project_id>/resources', methods=['GET'])
@jwt_required()
def get_project_resources(current_user, project_id):
    """获取项目资源分配情况"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    resources = ResourceAllocation.query.filter_by(project_id=project_id).all()
    return jsonify([resource.to_dict() for resource in resources])

@team_bp.route('/api/teams/<int:project_id>/resources', methods=['POST'])
@jwt_required()
def allocate_resource(current_user, project_id):
    """分配项目资源"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    data = request.get_json()
    if not data or not data.get('resource_type') or not data.get('resource_name'):
        return jsonify({'error': '缺少必要字段'}), 400
    
    allocation = ResourceAllocation(
        project_id=project_id,
        resource_type=data['resource_type'],
        resource_name=data['resource_name'],
        allocation_percentage=float(data.get('allocation_percentage', 0)),
        start_date=datetime.fromisoformat(data['start_date']) if data.get('start_date') else None,
        end_date=datetime.fromisoformat(data['end_date']) if data.get('end_date') else None
    )
    
    db.session.add(allocation)
    db.session.commit()
    
    return jsonify(allocation.to_dict()), 201

@team_bp.route('/api/teams/<int:project_id>/resources/<int:resource_id>', methods=['PUT'])
@jwt_required()
def update_resource_allocation(current_user, project_id, resource_id):
    """更新资源分配"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    allocation = ResourceAllocation.query.get_or_404(resource_id)
    if allocation.project_id != project_id:
        return jsonify({'error': '资源不属于此项目'}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({'error': '无效的请求数据'}), 400
    
    if 'allocation_percentage' in data:
        allocation.allocation_percentage = float(data['allocation_percentage'])
    if 'status' in data:
        allocation.status = data['status']
    if 'start_date' in data:
        allocation.start_date = datetime.fromisoformat(data['start_date'])
    if 'end_date' in data:
        allocation.end_date = datetime.fromisoformat(data['end_date'])
    
    db.session.commit()
    return jsonify(allocation.to_dict())

# 系统资源监控
@team_bp.route('/api/system/resources', methods=['GET'])
@jwt_required()
def get_system_resources(current_user):
    """获取系统资源使用情况"""
    if not current_user.is_admin:
        return jsonify({'error': '需要管理员权限'}), 403
    
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return jsonify({
        'cpu': {
            'percent': cpu_percent,
            'cores': psutil.cpu_count()
        },
        'memory': {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent
        },
        'disk': {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        }
    })

# 通知管理
@team_bp.route('/api/notifications', methods=['GET'])
@jwt_required()
def get_notifications(current_user):
    """获取用户通知"""
    notifications = TeamNotification.query.filter_by(
        user_id=current_user.id
    ).order_by(TeamNotification.created_at.desc()).all()
    return jsonify([notification.to_dict() for notification in notifications])

@team_bp.route('/api/notifications/<int:notification_id>', methods=['PUT'])
@jwt_required()
def mark_notification_read(current_user, notification_id):
    """标记通知为已读"""
    notification = TeamNotification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        return jsonify({'error': '无权操作此通知'}), 403
    
    notification.is_read = True
    db.session.commit()
    return jsonify(notification.to_dict())

@team_bp.route('/api/notifications', methods=['POST'])
@jwt_required()
def create_notification(current_user):
    """创建通知"""
    data = request.get_json()
    if not data or not data.get('project_id') or not data.get('title') or not data.get('content'):
        return jsonify({'error': '缺少必要字段'}), 400
    
    project = Project.query.get_or_404(data['project_id'])
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    notification = TeamNotification(
        project_id=data['project_id'],
        user_id=data.get('user_id', current_user.id),
        title=data['title'],
        content=data['content'],
        notification_type=data.get('notification_type', 'info')
    )
    
    db.session.add(notification)
    db.session.commit()
    
    return jsonify(notification.to_dict()), 201

@team_bp.route('/team')
@jwt_required()
def team_page(current_user):
    """团队协作页面"""
    return render_template('team.html', project_id=request.args.get('project_id'))

@team_bp.route('/api/teams/<int:project_id>/workload-history', methods=['GET'])
@jwt_required()
def get_workload_history(current_user, project_id):
    """获取团队成员工作负载历史数据"""
    project = Project.query.get_or_404(project_id)
    if not project.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此项目'}), 403
    
    # 获取最近30天的数据
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    
    # 获取所有团队成员
    members = TeamMember.query.filter_by(project_id=project_id).all()
    
    # 获取每个成员的工作负载历史
    history = []
    for member in members:
        member_history = {
            'member_id': member.id,
            'name': member.user.name,
            'role': member.role,
            'data': []
        }
        
        # 模拟历史数据（实际项目中应该从数据库获取）
        current_date = start_date
        while current_date <= end_date:
            # 这里使用随机数据模拟，实际项目中应该使用真实数据
            workload = random.uniform(0, 100)
            member_history['data'].append({
                'date': current_date.strftime('%Y-%m-%d'),
                'workload': round(workload, 1)
            })
            current_date += timedelta(days=1)
        
        history.append(member_history)
    
    return jsonify(history) 