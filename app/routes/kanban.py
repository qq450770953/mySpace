from flask import Blueprint, request, jsonify, render_template
from app.models.task import Project, Task
from app.models.auth import User
from app import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import logging

kanban_bp = Blueprint('kanban', __name__)
logger = logging.getLogger(__name__)

@kanban_bp.route('/kanban/boards', methods=['GET'])
@jwt_required()
def get_boards():
    try:
        current_user = get_jwt_identity()
        projects = Project.query.all()
        return jsonify([project.to_dict() for project in projects])
    except Exception as e:
        logger.error(f"Error getting kanban boards: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/boards/<int:project_id>/tasks', methods=['GET'])
@jwt_required()
def get_board_tasks(project_id):
    try:
        tasks = Task.query.filter_by(project_id=project_id).all()
        return jsonify([task.to_dict() for task in tasks])
    except Exception as e:
        logger.error(f"Error getting board tasks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/tasks/<int:task_id>/status', methods=['PUT'])
@jwt_required()
def update_task_status(task_id):
    try:
        current_user = get_jwt_identity()
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        if 'status' in data:
            task.status = data['status']
            task.updated_by = current_user
            task.updated_at = datetime.utcnow()
            
        db.session.commit()
        return jsonify(task.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating task status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/tasks/<int:task_id>/position', methods=['PUT'])
@jwt_required()
def update_task_position(task_id):
    try:
        current_user = get_jwt_identity()
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        if 'position' in data:
            task.position = data['position']
            task.updated_by = current_user
            task.updated_at = datetime.utcnow()
            
        db.session.commit()
        return jsonify(task.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating task position: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    """获取所有任务"""
    try:
        # 获取筛选参数
        project_id = request.args.get('project_id', type=int)
        status = request.args.get('status')
        priority = request.args.get('priority')
        assignee_id = request.args.get('assignee_id', type=int)
        search = request.args.get('search', '').strip()
        
        # 构建查询
        query = Task.query
        
        # 应用筛选条件
        if project_id:
            query = query.filter_by(project_id=project_id)
        if status:
            query = query.filter_by(status=status)
        if priority:
            query = query.filter_by(priority=priority)
        if assignee_id:
            query = query.filter_by(assignee_id=assignee_id)
        
        # 应用搜索条件
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                db.or_(
                    Task.title.ilike(search_pattern),
                    Task.description.ilike(search_pattern)
                )
            )
        
        # 只返回用户有权限访问的任务
        tasks = [task for task in query.all() if task.project.is_accessible_by(get_jwt_identity())]
        
        return jsonify([task.to_dict() for task in tasks])
    except Exception as e:
        logger.error(f"Error getting tasks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/projects', methods=['GET'])
@jwt_required()
def get_projects():
    """获取所有项目"""
    try:
        projects = Project.query.all()
        return jsonify([project.to_dict() for project in projects])
    except Exception as e:
        logger.error(f"Error getting projects: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/tasks', methods=['POST'])
@jwt_required()
def create_task():
    """创建新任务"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        # 检查项目是否存在
        project = Project.query.get(data.get('project_id'))
        if not project:
            return jsonify({'error': '项目不存在'}), 404
        
        # 检查用户是否有权限访问项目
        if not project.is_accessible_by(current_user):
            return jsonify({'error': '无权在此项目中创建任务'}), 403
        
        # 创建新任务
        task = Task(
            title=data.get('title'),
            description=data.get('description'),
            project_id=project.id,
            assignee_id=data.get('assignee_id'),
            priority=data.get('priority', 'medium'),
            start_date=datetime.fromisoformat(data['start_date']) if data.get('start_date') else None,
            end_date=datetime.fromisoformat(data['end_date']) if data.get('end_date') else None,
            status=data.get('status', 'todo'),
            progress=0
        )
        
        db.session.add(task)
        db.session.commit()
        
        return jsonify(task.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating task: {str(e)}")
        return jsonify({'error': str(e)}), 500

@kanban_bp.route('/kanban/users', methods=['GET'])
@jwt_required()
def get_users():
    """获取所有用户"""
    try:
        users = User.query.all()
        return jsonify([user.to_dict() for user in users])
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return jsonify({'error': str(e)}), 500 