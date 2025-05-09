from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.task import Project, Task, TaskDependency, TaskProgressHistory, TaskProgressApproval
from app.models.auth import User
from app import db
from datetime import datetime, timedelta
import logging

gantt_bp = Blueprint('gantt', __name__)
logger = logging.getLogger(__name__)

@gantt_bp.route('/api/projects/<int:project_id>/tasks', methods=['GET'])
@jwt_required()
def get_project_tasks(project_id):
    """获取项目的所有任务"""
    project = Project.query.get_or_404(project_id)
    
    # 检查用户是否有权限访问项目
    if not project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权访问此项目'}), 403
    
    tasks = Task.query.filter_by(project_id=project_id).all()
    return jsonify([task.to_dict() for task in tasks])

@gantt_bp.route('/api/projects/<int:project_id>/dependencies', methods=['GET'])
@jwt_required()
def get_project_dependencies(project_id):
    """获取项目的任务依赖关系"""
    project = Project.query.get_or_404(project_id)
    
    # 检查用户是否有权限访问项目
    if not project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权访问此项目'}), 403
    
    dependencies = TaskDependency.query.join(
        Task, TaskDependency.task_id == Task.id
    ).filter(Task.project_id == project_id).all()
    
    return jsonify([{
        'id': dep.id,
        'task_id': dep.task_id,
        'dependent_id': dep.dependent_id,
        'dependency_type': dep.dependency_type,
        'dependent': dep.dependent.to_dict() if dep.dependent else None
    } for dep in dependencies])

@gantt_bp.route('/api/tasks/batch-update', methods=['PUT'])
@jwt_required()
def batch_update_tasks():
    """批量更新任务信息"""
    updates = request.get_json()
    if not isinstance(updates, list):
        return jsonify({'error': '无效的请求数据'}), 400
    
    try:
        current_user = get_jwt_identity()
        for update in updates:
            task = Task.query.get(update['id'])
            if not task:
                continue
                
            # 检查用户是否有权限修改任务
            if not task.project.is_accessible_by(current_user):
                continue
            
            # 更新任务信息
            task.start_date = datetime.fromisoformat(update['start_date'].replace('Z', '+00:00'))
            task.end_date = datetime.fromisoformat(update['end_date'].replace('Z', '+00:00'))
            task.progress = update['progress']
        
        db.session.commit()
        return jsonify({'message': '任务更新成功'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating tasks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks', methods=['POST'])
@jwt_required()
def create_task():
    """创建新任务"""
    data = request.get_json()
    if not data:
        return jsonify({'error': '无效的请求数据'}), 400
    
    try:
        current_user = get_jwt_identity()
        # 检查项目是否存在且用户有权限访问
        project = Project.query.get(data.get('project_id'))
        if not project or not project.is_accessible_by(current_user):
            return jsonify({'error': '无权在此项目中创建任务'}), 403
        
        # 创建新任务
        task = Task(
            title=data.get('title', '新任务'),
            description=data.get('description', ''),
            project_id=project.id,
            parent_id=data.get('parent_id'),
            assignee_id=data.get('assignee_id'),
            start_date=datetime.fromisoformat(data['start_date'].replace('Z', '+00:00')),
            end_date=datetime.fromisoformat(data['end_date'].replace('Z', '+00:00')),
            status=data.get('status', 'todo'),
            priority=data.get('priority', 'medium'),
            progress=data.get('progress', 0)
        )
        
        db.session.add(task)
        db.session.commit()
        
        return jsonify(task.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating task: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks/dependencies', methods=['POST'])
@jwt_required()
def create_dependency():
    """创建任务依赖关系"""
    data = request.get_json()
    if not data or not all(k in data for k in ['task_id', 'dependent_id', 'dependency_type']):
        return jsonify({'error': '缺少必要的参数'}), 400
    
    try:
        current_user = get_jwt_identity()
        # 检查任务是否存在且属于同一项目
        task = Task.query.get(data['task_id'])
        dependent = Task.query.get(data['dependent_id'])
        
        if not task or not dependent or task.project_id != dependent.project_id:
            return jsonify({'error': '无效的任务依赖关系'}), 400
        
        # 检查用户是否有权限修改项目
        if not task.project.is_accessible_by(current_user):
            return jsonify({'error': '无权修改此项目'}), 403
        
        # 创建依赖关系
        dependency = TaskDependency(
            task_id=task.id,
            dependent_id=dependent.id,
            dependency_type=data['dependency_type']
        )
        
        db.session.add(dependency)
        db.session.commit()
        
        return jsonify({
            'id': dependency.id,
            'task_id': dependency.task_id,
            'dependent_id': dependency.dependent_id,
            'dependency_type': dependency.dependency_type
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating dependency: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks/dependencies/<int:dependency_id>', methods=['DELETE'])
@jwt_required()
def delete_dependency(dependency_id):
    """删除任务依赖关系"""
    dependency = TaskDependency.query.get_or_404(dependency_id)
    
    # 检查用户是否有权限修改项目
    if not dependency.task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权修改此项目'}), 403
    
    try:
        db.session.delete(dependency)
        db.session.commit()
        return jsonify({'message': '依赖关系已删除'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting dependency: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks/<int:task_id>/progress-history', methods=['GET'])
@jwt_required()
def get_task_progress_history(task_id):
    """获取任务进度历史记录"""
    task = Task.query.get_or_404(task_id)
    
    # 检查用户是否有权限访问任务
    if not task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权访问此任务'}), 403
    
    # 获取历史记录
    history = task.progress_history.order_by(TaskProgressHistory.created_at.desc()).all()
    return jsonify([record.to_dict() for record in history])

@gantt_bp.route('/api/tasks/<int:task_id>/progress', methods=['PUT'])
@jwt_required()
def update_task_progress(task_id):
    """更新任务进度"""
    task = Task.query.get_or_404(task_id)
    
    # 检查用户是否有权限修改任务
    if not task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权修改此任务'}), 403
    
    data = request.get_json()
    if not data or 'progress' not in data:
        return jsonify({'error': '缺少进度参数'}), 400
    
    try:
        new_progress = int(data['progress'])
        if new_progress < 0 or new_progress > 100:
            return jsonify({'error': '进度必须在0-100之间'}), 400
        
        # 更新进度并记录历史
        change_reason = data.get('change_reason')
        task.update_progress(new_progress, get_jwt_identity(), change_reason)
        db.session.commit()
        
        return jsonify({
            'id': task.id,
            'progress': task.progress,
            'status': task.status
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating task progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/projects/<int:project_id>/recalculate-progress', methods=['POST'])
@jwt_required()
def recalculate_project_progress(project_id):
    """重新计算项目所有任务的进度"""
    project = Project.query.get_or_404(project_id)
    
    # 检查用户是否有权限访问项目
    if not project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权访问此项目'}), 403
    
    try:
        Task.recalculate_all_progress()
        db.session.commit()
        
        return jsonify({'message': '进度重新计算完成'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error recalculating project progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks/<int:task_id>/progress-approvals', methods=['GET'])
@jwt_required()
def get_task_progress_approvals(task_id):
    """获取任务的进度变更审批记录"""
    task = Task.query.get_or_404(task_id)
    
    # 检查用户是否有权限访问任务
    if not task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权访问此任务'}), 403
    
    approvals = task.progress_approvals.order_by(TaskProgressApproval.created_at.desc()).all()
    return jsonify([approval.to_dict() for approval in approvals])

@gantt_bp.route('/api/tasks/<int:task_id>/progress-approvals', methods=['POST'])
@jwt_required()
def request_progress_change(task_id):
    """申请进度变更"""
    task = Task.query.get_or_404(task_id)
    
    # 检查用户是否有权限修改任务
    if not task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权修改此任务'}), 403
    
    data = request.get_json()
    if not data or 'requested_progress' not in data:
        return jsonify({'error': '缺少必要的参数'}), 400
    
    try:
        requested_progress = int(data['requested_progress'])
        if requested_progress < 0 or requested_progress > 100:
            return jsonify({'error': '进度必须在0-100之间'}), 400
        
        # 创建进度变更申请
        approval = TaskProgressApproval(
            task_id=task_id,
            user_id=get_jwt_identity(),
            requested_progress=requested_progress,
            current_progress=task.progress,
            change_reason=data.get('change_reason')
        )
        
        db.session.add(approval)
        db.session.commit()
        
        return jsonify(approval.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error requesting progress change: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks/progress-approvals/<int:approval_id>', methods=['PUT'])
@jwt_required()
def process_progress_approval(approval_id):
    """处理进度变更申请"""
    approval = TaskProgressApproval.query.get_or_404(approval_id)
    
    # 检查用户是否有权限审批
    if not approval.task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权审批此申请'}), 403
    
    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({'error': '缺少必要的参数'}), 400
    
    try:
        status = data['status']
        if status not in ['approved', 'rejected']:
            return jsonify({'error': '无效的状态'}), 400
        
        approval.status = status
        approval.approver_id = get_jwt_identity()
        approval.approval_comment = data.get('approval_comment')
        
        # 如果审批通过，更新任务进度
        if status == 'approved':
            approval.task.update_progress(
                approval.requested_progress,
                get_jwt_identity(),
                f"通过审批: {approval.change_reason}"
            )
        
        db.session.commit()
        return jsonify(approval.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing progress approval: {str(e)}")
        return jsonify({'error': str(e)}), 500

@gantt_bp.route('/api/tasks/progress-approvals/pending', methods=['GET'])
@jwt_required()
def get_pending_approvals():
    """获取待处理的进度变更申请"""
    # 获取当前用户有权限审批的所有项目的待处理申请
    pending_approvals = TaskProgressApproval.query.join(
        Task, TaskProgressApproval.task_id == Task.id
    ).join(
        Project, Task.project_id == Project.id
    ).filter(
        TaskProgressApproval.status == 'pending',
        Project.members.any(id=get_jwt_identity())
    ).order_by(TaskProgressApproval.created_at.desc()).all()
    
    return jsonify([approval.to_dict() for approval in pending_approvals])

@gantt_bp.route('/api/tasks/<int:task_id>/progress-trend', methods=['GET'])
@jwt_required()
def get_task_progress_trend(task_id):
    """获取任务进度趋势数据"""
    task = Task.query.get_or_404(task_id)
    
    # 检查用户是否有权限访问任务
    if not task.project.is_accessible_by(get_jwt_identity()):
        return jsonify({'error': '无权访问此任务'}), 403
    
    # 获取时间周期参数
    period = request.args.get('period', 'week')
    
    # 计算时间范围
    end_date = datetime.utcnow()
    if period == 'week':
        start_date = end_date - timedelta(days=7)
        interval = 'day'
    elif period == 'month':
        start_date = end_date - timedelta(days=30)
        interval = 'day'
    else:  # year
        start_date = end_date - timedelta(days=365)
        interval = 'month'
    
    # 获取进度历史记录
    history = TaskProgressHistory.query.filter(
        TaskProgressHistory.task_id == task_id,
        TaskProgressHistory.created_at >= start_date,
        TaskProgressHistory.created_at <= end_date
    ).order_by(TaskProgressHistory.created_at).all()
    
    # 获取计划进度数据
    planned_progress = calculate_planned_progress(task, start_date, end_date, interval)
    
    # 处理进度历史数据
    progress_data = {}
    for record in history:
        date_key = record.created_at.strftime('%Y-%m-%d')
        if interval == 'month':
            date_key = record.created_at.strftime('%Y-%m')
        progress_data[date_key] = record.progress
    
    # 生成图表数据
    labels = []
    progress = []
    planned = []
    
    current_date = start_date
    while current_date <= end_date:
        date_key = current_date.strftime('%Y-%m-%d')
        if interval == 'month':
            date_key = current_date.strftime('%Y-%m')
        
        labels.append(date_key)
        progress.append(progress_data.get(date_key, progress[-1] if progress else 0))
        planned.append(planned_progress.get(date_key, 0))
        
        if interval == 'day':
            current_date += timedelta(days=1)
        else:
            current_date = (current_date.replace(day=1) + timedelta(days=32)).replace(day=1)
    
    return jsonify({
        'labels': labels,
        'progress': progress,
        'planned_progress': planned
    })

def calculate_planned_progress(task, start_date, end_date, interval):
    """计算计划进度"""
    planned_progress = {}
    
    if not task.start_date or not task.end_date:
        return planned_progress
    
    total_days = (task.end_date - task.start_date).days
    if total_days <= 0:
        return planned_progress
    
    current_date = max(start_date, task.start_date)
    while current_date <= min(end_date, task.end_date):
        date_key = current_date.strftime('%Y-%m-%d')
        if interval == 'month':
            date_key = current_date.strftime('%Y-%m')
        
        days_passed = (current_date - task.start_date).days
        progress = min(100, int((days_passed / total_days) * 100))
        planned_progress[date_key] = progress
        
        if interval == 'day':
            current_date += timedelta(days=1)
        else:
            current_date = (current_date.replace(day=1) + timedelta(days=32)).replace(day=1)
    
    return planned_progress 