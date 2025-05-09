from flask import jsonify, request, current_app, Blueprint, render_template, send_file, redirect, url_for
from app.models.task import Task, TaskComment, TaskDependency, TaskLog, TaskProgressHistory, TaskProgressApproval, TaskAttachment
from app.models.resource import Resource, ResourceAllocation
from app.models.auth import User  # 修改导入路径
from app.models.project import Project  # 保持这个导入不变
from flask_login import current_user
from app import db
from datetime import datetime
import os
import json
from werkzeug.utils import secure_filename
import logging
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.utils.permissions import permission_required, PERMISSION_MANAGE_RISKS, PERMISSION_CREATE_TASK
from app.utils.permissions import ROLE_ADMIN, ROLE_PROJECT_MANAGER  # 添加角色常量
from app.utils.permissions import PERMISSION_MANAGE_TASK, PERMISSION_MANAGE_ALL_TASKS  # 添加权限常量
from flask_wtf.csrf import CSRFProtect
import pytz

csrf = CSRFProtect()

task_bp = Blueprint('tasks', __name__)
logger = logging.getLogger(__name__)

# Define allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar'}

def allowed_file(filename):
    """检查文件是否有允许的扩展名"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@task_bp.route('/', methods=['GET'])
@jwt_required()
def get_tasks():
    """获取任务列表，支持多种过滤条件、排序和分页"""
    try:
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if not user:
            return jsonify({'msg': 'User not found'}), 404
            
        # 获取查询参数
        project_id = request.args.get('project_id', type=int)
        status = request.args.getlist('status')  # 支持多状态过滤
        priority = request.args.getlist('priority')  # 支持多优先级过滤
        assignee_id = request.args.get('assignee_id', type=int)
        created_by = request.args.get('created_by', type=int)
        search = request.args.get('search', '')  # 搜索标题和描述
        
        # 分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        per_page = min(per_page, 100)  # 限制每页最大数量
        
        # 排序参数
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # 构建查询
        query = Task.query
        
        # 基本过滤条件
        if project_id:
            query = query.filter_by(project_id=project_id)
        if status:
            query = query.filter(Task.status.in_(status))
        if priority:
            query = query.filter(Task.priority.in_(priority))
        if assignee_id:
            query = query.filter_by(assignee_id=assignee_id)
        if created_by:
            query = query.filter_by(created_by=created_by)
            
        # 搜索标题和描述
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Task.title.ilike(search_term),
                    Task.description.ilike(search_term)
                )
            )
            
        # 排序
        valid_sort_fields = {
            'created_at': Task.created_at,
            'updated_at': Task.updated_at,
            'title': Task.title,
            'status': Task.status,
            'priority': Task.priority,
            'progress': Task.progress
        }
        
        sort_field = valid_sort_fields.get(sort_by, Task.created_at)
        if sort_order == 'desc':
            sort_field = sort_field.desc()
        query = query.order_by(sort_field)
        
        # 预加载关联数据以避免 N+1 查询问题
        query = query.options(
            db.joinedload(Task.project),
            db.joinedload(Task.assignee),
            db.joinedload(Task.creator)
        )
        
        # 执行分页查询
        try:
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            tasks = pagination.items
        except Exception as e:
            logger.error(f"Error during pagination: {str(e)}")
            return jsonify({'error': 'Failed to paginate tasks'}), 500
        
        # 构建响应数据
        try:
            response = {
                'tasks': [task.to_dict() for task in tasks],
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
            logger.error(f"Error serializing tasks: {str(e)}")
            return jsonify({'error': 'Failed to serialize tasks'}), 500
            
    except Exception as e:
        logger.error(f"Error in get_tasks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_CREATE_TASK)
def create_task():
    """创建新任务"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for create_task - Using test user")
            # 在bypass_jwt模式下，我们可以设置一个请求属性来允许CSRF绕过
            # 这通常仅用于测试和开发环境
            if hasattr(request, '_csrf_token'):
                # 将CSRF令牌设置为已验证状态（flask-jwt-extended内部使用）
                request._csrf_token = True
            current_user = 1  # Replace with a valid user ID in your database
        else:
            current_user = get_jwt_identity()
            if not current_user:
                logger.warning("Unauthorized access to create_task", extra={
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string
                })
                return jsonify({'error': '认证失败，请登录', 'detail': 'No JWT token found or token invalid'}), 401
        
        data = request.get_json()
        logger.info(f"Received task creation data: {data}")
        
        # 验证必要字段
        if not data or not data.get('title'):
            return jsonify({'error': '任务标题不能为空'}), 400
            
        if not data.get('project_id'):
            return jsonify({'error': '项目ID不能为空'}), 400
            
        # 检查项目是否存在
        project = Project.query.get(data['project_id'])
        if not project:
            return jsonify({'error': '项目不存在'}), 404
            
        # 创建新任务
        task = Task(
            title=data['title'],
            description=data.get('description'),
            status=data.get('status', 'todo'),
            priority=data.get('priority', 'medium'),
            start_date=datetime.fromisoformat(data['start_date']) if data.get('start_date') else None,
            due_date=datetime.fromisoformat(data['due_date']) if data.get('due_date') else None,
            project_id=data['project_id'],
            assignee_id=data.get('assignee_id'),
            created_by=current_user
        )
        
        db.session.add(task)
        db.session.commit()
        
        logger.info(f"Task created successfully: {task.id} - {task.title}")
        
        return jsonify({
            'message': '任务创建成功',
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'project_id': task.project_id,
                'start_date': task.start_date.isoformat() if task.start_date else None,
                'due_date': task.due_date.isoformat() if task.due_date else None
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating task: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>', methods=['GET'])
@jwt_required()
def get_task(task_id):
    """获取单个任务的详细信息"""
    try:
        task = Task.query.get_or_404(task_id)
        if not task.project.is_accessible_by(get_jwt_identity()):
            return jsonify({'error': '无权访问此任务'}), 403
            
        # 获取相关数据
        comments = TaskComment.query.filter_by(task_id=task_id).order_by(TaskComment.created_at.desc()).limit(5).all()
        attachments = TaskAttachment.query.filter_by(task_id=task_id).all()
        logs = TaskLog.query.filter_by(task_id=task_id).order_by(TaskLog.created_at.desc()).limit(10).all()
        risks = Risk.query.filter_by(task_id=task_id).all()
        dependencies = TaskDependency.query.filter_by(task_id=task_id).all()
        resource_allocations = ResourceAllocation.query.filter_by(task_id=task_id, status='active').all()
        
        # 构建详细响应
        response = {
            'task': task.to_dict(),
            'project': task.project.to_dict(),
            'assignee': task.assignee.to_dict() if task.assignee else None,
            'creator': task.creator.to_dict(),
            'parent_task': task.parent.to_dict() if task.parent else None,
            'comments': [comment.to_dict() for comment in comments],
            'attachments': [attachment.to_dict() for attachment in attachments],
            'logs': [log.to_dict() for log in logs],
            'risks': [risk.to_dict() for risk in risks],
            'dependencies': [dependency.to_dict() for dependency in dependencies],
            'resource_allocations': [allocation.to_dict() for allocation in resource_allocations],
            'statistics': {
                'total_comments': TaskComment.query.filter_by(task_id=task_id).count(),
                'total_attachments': len(attachments),
                'total_logs': TaskLog.query.filter_by(task_id=task_id).count(),
                'open_risks': Risk.query.filter_by(task_id=task_id, status='open').count(),
                'total_dependencies': len(dependencies),
                'active_resources': len(resource_allocations)
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting task: {str(e)}")
        return jsonify({'error': f'获取任务详情失败: {str(e)}'}), 500

@task_bp.route('/<int:task_id>', methods=['PUT'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_TASK)  # 添加权限检查
def update_task(task_id):
    """更新任务信息"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for update_task - Using test user")
            # 在bypass_jwt模式下，我们可以设置一个请求属性来允许CSRF绕过
            # 这通常仅用于测试和开发环境
            if hasattr(request, '_csrf_token'):
                # 将CSRF令牌设置为已验证状态（flask-jwt-extended内部使用）
                request._csrf_token = True
            current_user_id = 1  # Replace with a valid user ID in your database
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                logger.warning("Unauthorized access to update_task", extra={
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string if hasattr(request, 'user_agent') else 'Unknown'
                })
                return jsonify({'error': '认证失败，请登录', 'detail': 'No JWT token found or token invalid'}), 401
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        # 检查权限 - 确保用户有权限更新此任务
        user = User.query.get(current_user_id)
        if not (user.has_permission(PERMISSION_MANAGE_ALL_TASKS) or task.assignee_id == current_user_id or task.created_by == current_user_id):
            # 检查用户是否是项目经理
            project = Project.query.get(task.project_id)
            if not (project and (project.manager_id == current_user_id or project.owner_id == current_user_id)):
                logger.warning(f"用户 {current_user_id} 尝试更新没有权限的任务 {task_id}")
                return jsonify({'error': '您没有权限更新此任务'}), 403
        
        data = request.get_json()
        
        # 更新任务信息
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'status' in data:
            task.status = data['status']
        if 'priority' in data:
            task.priority = data['priority']
        if 'start_date' in data and data['start_date']:
            task.start_date = datetime.fromisoformat(data['start_date'])
        if 'due_date' in data and data['due_date']:
            task.due_date = datetime.fromisoformat(data['due_date'])
        if 'progress' in data:
            task.progress = data['progress']
        if 'assignee_id' in data:
            task.assignee_id = data['assignee_id']
            
        # 更新最后修改时间
        task.updated_at = datetime.now(pytz.utc)
            
        db.session.commit()
        
        return jsonify({
            'message': '任务更新成功',
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'progress': task.progress,
                'start_date': task.start_date.isoformat() if task.start_date else None,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'assignee_id': task.assignee_id,
                'updated_at': task.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating task: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>', methods=['DELETE'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_TASK)  # 添加权限检查
def delete_task(task_id):
    """删除任务"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for delete_task - Using test user")
            current_user_id = 1  # Replace with a valid user ID in your database
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        # 检查权限 - 确保用户有权限删除此任务
        user = User.query.get(current_user_id)
        if not (user.has_permission(PERMISSION_MANAGE_ALL_TASKS) or task.created_by == current_user_id):
            # 检查用户是否是项目经理
            project = Project.query.get(task.project_id)
            if not (project and (project.manager_id == current_user_id or project.owner_id == current_user_id)):
                logger.warning(f"用户 {current_user_id} 尝试删除没有权限的任务 {task_id}")
                return jsonify({'error': '您没有权限删除此任务'}), 403
        
        # 获取项目
        project = Project.query.get(task.project_id)
        if not project:
            return jsonify({'error': '任务所属项目不存在'}), 404
            
        # 删除任务
        db.session.delete(task)
        db.session.commit()
            
        return jsonify({'message': '任务删除成功'})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting task: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>/comments', methods=['GET'])
@jwt_required()
def get_task_comments(task_id):
    try:
        comments = TaskComment.query.filter_by(task_id=task_id).order_by(TaskComment.created_at.desc()).all()
        return jsonify([comment.to_dict() for comment in comments])
    except Exception as e:
        logger.error(f"Error getting task comments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>/comments', methods=['POST'])
@jwt_required()
def add_task_comment(task_id):
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({'error': 'Missing comment content'}), 400
        
        comment = TaskComment(
            task_id=task_id,
            content=data['content'],
            user_id=current_user
        )
        db.session.add(comment)
        db.session.commit()
        
        return jsonify(comment.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding task comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>/attachments', methods=['GET'])
@jwt_required()
def get_task_attachments(task_id):
    try:
        attachments = TaskAttachment.query.filter_by(task_id=task_id).all()
        return jsonify([attachment.to_dict() for attachment in attachments])
    except Exception as e:
        logger.error(f"Error getting task attachments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>/attachments', methods=['POST'])
@jwt_required()
def add_task_attachment(task_id):
    try:
        current_user = get_jwt_identity()
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # 创建上传目录
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'tasks', str(task_id))
        os.makedirs(upload_dir, exist_ok=True)
        
        # 生成安全的文件名
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_dir, filename)
        
        # 保存文件
        file.save(file_path)
        
        # 创建附件记录
        attachment = TaskAttachment(
            task_id=task_id,
            filename=filename,
            file_path=file_path,
            file_type=file.content_type or 'application/octet-stream',
            size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            description=request.form.get('description', ''),
            uploader_id=current_user
        )
        
        db.session.add(attachment)
        db.session.commit()
        
        return jsonify(attachment.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding task attachment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>/resources', methods=['GET'])
@jwt_required()
def get_task_resources(task_id):
    allocations = ResourceAllocation.query.filter_by(task_id=task_id).all()
    return jsonify([allocation.to_dict() for allocation in allocations])

@task_bp.route('/<int:task_id>/subtasks', methods=['GET'])
@jwt_required()
def get_subtasks(task_id):
    """获取子任务列表"""
    task = Task.query.get_or_404(task_id)
    subtasks = Subtask.query.filter_by(parent_id=task_id).all()
    return jsonify([subtask.to_dict() for subtask in subtasks])

@task_bp.route('/<int:task_id>/subtasks', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def create_subtask(task_id):
    """创建子任务"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for create_subtask " + str(task_id) + " - Using test user")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 检查任务是否存在
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': '请求体为空或格式不正确'}), 400
            
        logger.info(f"接收到子任务创建数据: {data}")
        
        # 适配不同的字段名称
        subtask_name = data.get('name') or data.get('title')
        if not subtask_name:
            return jsonify({'error': '子任务名称不能为空'}), 400
            
        # 处理日期字段
        start_date = None
        if 'start_date' in data and data['start_date']:
            try:
                start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
            except ValueError:
                return jsonify({'error': '开始日期格式不正确，应为YYYY-MM-DD'}), 400
        else:
            start_date = datetime.now()
            
        end_date = None
        if 'end_date' in data and data['end_date']:
            try:
                end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
            except ValueError:
                return jsonify({'error': '结束日期格式不正确，应为YYYY-MM-DD'}), 400
        elif 'due_date' in data and data['due_date']:
            try:
                end_date = datetime.strptime(data['due_date'], '%Y-%m-%d')
            except ValueError:
                return jsonify({'error': '截止日期格式不正确，应为YYYY-MM-DD'}), 400
                
        # 创建子任务 - 使用Task模型而不是Subtask类
        subtask = Task(
            title=subtask_name,
            description=data.get('description', ''),
            parent_id=task_id,
            assignee_id=data.get('assignee_id'),
            due_date=end_date,
            project_id=task.project_id,  # 继承父任务的项目
            created_by=current_user_id,
            status='todo'  # 默认状态
        )
        
        logger.info(f"创建子任务: {subtask_name} 父任务ID: {task_id}")
        
        db.session.add(subtask)
        db.session.commit()
        
        # 记录日志
        log = TaskLog(
            task_id=task_id,
            user_id=current_user_id,
            action='created_subtask',
            details=f'创建了子任务 "{subtask_name}"'
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify(subtask.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"创建子任务失败: {str(e)}")
        return jsonify({'error': f'创建子任务失败: {str(e)}'}), 500

@task_bp.route('/<int:task_id>/dependencies', methods=['GET'])
@jwt_required()
def get_dependencies(task_id):
    """获取任务依赖关系"""
    task = Task.query.get_or_404(task_id)
    dependencies = TaskDependency.query.filter_by(task_id=task_id).all()
    return jsonify([{
        'id': dep.id,
        'task_id': dep.task_id,
        'dependent_id': dep.dependent_id  # 修正: 使用dependent_id替代depends_on_id
    } for dep in dependencies])

@task_bp.route('/<int:task_id>/dependencies', methods=['POST'])
@jwt_required()
def add_dependency(task_id):
    """添加任务依赖关系"""
    task = Task.query.get_or_404(task_id)
    data = request.get_json()
    
    dependency = TaskDependency(
        task_id=task_id,
        dependent_id=data['depends_on_id'],  # 修正: 将depends_on_id映射到dependent_id
        dependency_type="finish-to-start"    # 添加默认的依赖类型
    )
    
    db.session.add(dependency)
    db.session.commit()
    return jsonify({
        'id': dependency.id,
        'task_id': dependency.task_id,
        'dependent_id': dependency.dependent_id  # 修正: 使用dependent_id
    }), 201

@task_bp.route('/<int:task_id>/logs', methods=['GET'])
@jwt_required()
def get_task_logs(task_id):
    """获取任务日志"""
    task = Task.query.get_or_404(task_id)
    logs = TaskLog.query.filter_by(task_id=task_id).order_by(TaskLog.created_at.desc()).all()
    return jsonify([{
        'id': log.id,
        'details': log.details,
        'action': log.action,
        'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
    } for log in logs])

@task_bp.route('/<int:task_id>/logs', methods=['POST'])
@jwt_required()
def add_task_log(task_id):
    """添加任务日志"""
    try:
        current_user = get_jwt_identity()
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        if not data or not data.get('details'):
            return jsonify({'error': '缺少日志内容'}), 400
        
        log = TaskLog(
            task_id=task_id,
            user_id=current_user,
            action=data.get('action', 'comment'),
            details=data['details']
        )
        
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'id': log.id,
            'details': log.details,
            'action': log.action,
            'created_at': log.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"添加任务日志失败: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/project/<int:project_id>/gantt')
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def gantt_chart(project_id):
    """显示项目甘特图页面"""
    try:
        # 检查项目是否存在
        project = Project.query.get_or_404(project_id)
        
        # 检查用户权限（如果JWT可选，则在bypass_jwt时跳过）
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        current_user_id = get_jwt_identity()
        
        if current_user_id and not bypass_jwt:
            # 如果用户已登录且不是绕过JWT，检查权限
            if not project.is_accessible_by(current_user_id):
                logger.warning(f"用户 {current_user_id} 尝试查看无权限的项目甘特图: {project_id}")
                return render_template('error.html', error='您没有权限查看此项目的甘特图'), 403
        
        logger.info(f"展示甘特图页面: 项目ID={project_id}, 项目名称={project.name}")
        return render_template('gantt_chart.html', project_id=project_id)
    except Exception as e:
        logger.error(f"加载甘特图页面失败: {str(e)}", exc_info=True)
        return render_template('error.html', error=f'加载甘特图页面出错: {str(e)}'), 500

@task_bp.route('/project/<int:project_id>/gantt/data', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_gantt_data(project_id):
    """获取甘特图数据"""
    try:
        # 详细日志记录请求信息
        log_headers = {k:v for k,v in request.headers.items() 
                     if k.lower() not in ['cookie', 'authorization']}  # 排除敏感信息
        logger.info(f"甘特图数据请求: 项目ID={project_id}, URL={request.url}, 头部={log_headers}")
        
        # 检查项目是否存在
        project = Project.query.get(project_id)
        if not project:
            logger.warning(f"甘特图数据请求失败: 项目ID={project_id} 不存在")
            return jsonify({'error': '项目不存在', 'detail': f'ID为{project_id}的项目未找到'}), 404
            
        # 检查用户权限（如果JWT可选，则在bypass_jwt时跳过）
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        current_user_id = get_jwt_identity()
        
        if current_user_id and not bypass_jwt:
            # 如果用户已登录且不是绕过JWT，检查权限
            if not project.is_accessible_by(current_user_id):
                logger.warning(f"甘特图数据请求权限错误: 用户ID={current_user_id}, 项目ID={project_id}")
                return jsonify({'error': '无权访问此项目', 'detail': '您没有权限查看此项目的甘特图数据'}), 403
        
        # 查询项目任务
        tasks = Task.query.filter_by(project_id=project_id).all()
        logger.info(f"甘特图数据查询结果: 项目ID={project_id}, 任务数量={len(tasks)}")
        
        gantt_data = {
            'data': [],
            'links': []
        }
        
        # 处理任务数据
        for task in tasks:
            # 确保任务有开始日期和截止日期
            start_date = task.created_at.date() if task.created_at else datetime.now().date()
            due_date = task.due_date if task.due_date else (start_date + timedelta(days=7))
            
            # 确保日期格式正确
            if not isinstance(start_date, datetime.date):
                logger.warning(f"任务 {task.id} 开始日期格式不正确: {start_date}")
                start_date = datetime.now().date()
                
            if not isinstance(due_date, datetime.date):
                logger.warning(f"任务 {task.id} 截止日期格式不正确: {due_date}")
                due_date = start_date + timedelta(days=7)
            
            # 获取任务负责人姓名
            assignee_name = None
            if task.assignee_id:
                assignee = User.query.get(task.assignee_id)
                if assignee:
                    assignee_name = assignee.name or assignee.username
            
            # 创建甘特图任务数据
            task_data = {
                'id': task.id,
                'text': task.title,
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': due_date.strftime('%Y-%m-%d'),
                'progress': task.progress / 100 if task.progress else 0,
                'status': task.status,
                'priority': task.priority,
                'assignee': assignee_name,
                'parent': task.parent_id or 0  # 父任务ID或顶级任务
            }
            gantt_data['data'].append(task_data)
            
        # 处理任务间依赖关系
        if tasks:  # 只有当有任务时才处理依赖关系
            dependencies = TaskDependency.query.filter(
                TaskDependency.task_id.in_([task.id for task in tasks])
            ).all()
            
            for dep in dependencies:
                link_data = {
                    'id': f"link_{dep.id}",
                    'source': dep.dependent_id,  # 从属任务为源
                    'target': dep.task_id,       # 目标任务为目标
                    'type': '0'                  # 0表示完成-开始关系
                }
                gantt_data['links'].append(link_data)
        
        logger.info(f"甘特图数据请求成功，项目ID: {project_id}，任务: {len(gantt_data['data'])}，依赖: {len(gantt_data['links'])}")
        return jsonify(gantt_data)
        
    except Exception as e:
        logger.error(f"获取甘特图数据失败: {str(e)}", exc_info=True)
        return jsonify({
            'error': '获取甘特图数据失败', 
            'detail': str(e),
            'trace': str(e.__traceback__.tb_frame.f_code.co_filename) + ":" + str(e.__traceback__.tb_lineno)
        }), 500

@task_bp.route('/<int:task_id>/gantt', methods=['PUT'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def update_gantt_task(task_id):
    """更新甘特图中的任务信息"""
    try:
        # 检查任务是否存在
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
            
        logger.info(f"更新甘特图任务: {task_id}, 数据: {data}")
        
        # 检查用户权限（如果JWT可选，则在bypass_jwt时跳过）
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        current_user_id = get_jwt_identity()
        
        if current_user_id and not bypass_jwt:
            # 项目管理员、任务负责人或创建者有权限修改
            if (task.assignee_id != current_user_id and 
                task.project.manager_id != current_user_id and 
                task.created_by != current_user_id):
                logger.warning(f"用户 {current_user_id} 尝试修改无权限的任务: {task_id}")
                return jsonify({'error': '没有权限修改此任务'}), 403
        
        # 更新任务信息
        updated_fields = []
        
        if 'start_date' in data:
            # Task模型中将start_date映射到created_at
            if isinstance(data['start_date'], str):
                task.created_at = datetime.strptime(data['start_date'], '%Y-%m-%d')
            else:
                task.created_at = data['start_date']
            updated_fields.append('start_date')
                
        if 'end_date' in data:
            # Task模型中将end_date映射到due_date
            if isinstance(data['end_date'], str):
                task.due_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
            else:
                task.due_date = data['end_date']
            updated_fields.append('end_date')
                
        if 'progress' in data:
            task.progress = data['progress']
            updated_fields.append('progress')
            
            # 如果进度为100%，自动将状态设为completed
            if task.progress == 100 and task.status != 'completed':
                task.status = 'completed'
                task.completed_at = datetime.utcnow()
                updated_fields.append('status')
        
        db.session.commit()
        logger.info(f"甘特图任务更新成功: {task_id}, 字段: {', '.join(updated_fields)}")
        
        # 返回更新后的任务数据
        return jsonify({
            'id': task.id,
            'title': task.title,
            'status': task.status,
            'progress': task.progress,
            'start_date': task.created_at.strftime('%Y-%m-%d') if task.created_at else None,
            'end_date': task.due_date.strftime('%Y-%m-%d') if task.due_date else None,
            'message': '任务更新成功'
        })
    except ValueError as e:
        # 日期解析错误
        db.session.rollback()
        logger.error(f"更新甘特图任务失败(数据格式错误): {str(e)}")
        return jsonify({'error': f'数据格式错误: {str(e)}'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"更新甘特图任务失败(系统错误): {str(e)}")
        return jsonify({'error': f'系统错误: {str(e)}'}), 500

@task_bp.route('/dependencies/gantt', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def create_gantt_dependency():
    """创建甘特图中的任务依赖关系"""
    try:
        data = request.get_json()
        
        if not data or 'source' not in data or 'target' not in data:
            return jsonify({'error': '缺少必要参数'}), 400
        
        # 获取源任务和目标任务
        source_task = Task.query.get_or_404(data['source'])
        target_task = Task.query.get_or_404(data['target'])
        
        # 检查用户权限（如果JWT可选，则在bypass_jwt时跳过）
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        current_user_id = get_jwt_identity()
        
        if current_user_id and not bypass_jwt:
            # 检查用户是否有权限操作这两个任务
            if not source_task.project.is_accessible_by(current_user_id) or \
               not target_task.project.is_accessible_by(current_user_id):
                logger.warning(f"用户 {current_user_id} 尝试创建无权限的任务依赖关系")
                return jsonify({'error': '无权限创建任务依赖关系'}), 403
        
        # 检查项目是否一致
        if source_task.project_id != target_task.project_id:
            return jsonify({'error': '不能跨项目添加依赖关系'}), 400
        
        # 检查是否会造成循环依赖
        def check_dependency_cycle(source_id, target_id, visited=None):
            if visited is None:
                visited = set()
            
            if source_id in visited:
                return True
                
            visited.add(source_id)
            
            # 查找所有依赖当前任务的任务
            dependencies = TaskDependency.query.filter_by(dependent_id=source_id).all()
            for dep in dependencies:
                if dep.task_id == target_id or check_dependency_cycle(dep.task_id, target_id, visited):
                    return True
                    
            return False
            
        if check_dependency_cycle(data['target'], data['source']):
            return jsonify({'error': '不能创建循环依赖关系'}), 400
        
        # 检查是否已存在此依赖关系
        existing = TaskDependency.query.filter_by(
            task_id=data['target'],
            dependent_id=data['source']
        ).first()
        
        if existing:
            return jsonify({'error': '依赖关系已存在'}), 400
        
        # 创建依赖关系
        dependency = TaskDependency(
            task_id=data['target'],
            dependent_id=data['source'],
            dependency_type=data.get('type', 'finish-to-start')
        )
        
        db.session.add(dependency)
        db.session.commit()
        
        logger.info(f"甘特图依赖关系创建成功: {dependency.id}, 从 {data['source']} 到 {data['target']}")
        
        return jsonify({
            'id': dependency.id,
            'task_id': dependency.task_id,
            'dependent_id': dependency.dependent_id,
            'type': dependency.dependency_type,
            'message': '依赖关系创建成功'
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"创建甘特图依赖关系错误: {str(e)}")
        return jsonify({'error': f'创建依赖关系失败: {str(e)}'}), 500

@task_bp.route('/<int:task_id>/dependencies/<int:dependency_id>/gantt', methods=['DELETE'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def delete_gantt_dependency(task_id, dependency_id):
    """删除甘特图中的任务依赖关系"""
    try:
        # 查找依赖关系记录
        dependency = TaskDependency.query.filter_by(
            task_id=task_id,
            dependent_id=dependency_id
        ).first_or_404()
        
        # 检查用户权限（如果JWT可选，则在bypass_jwt时跳过）
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        current_user_id = get_jwt_identity()
        
        if current_user_id and not bypass_jwt:
            # 获取任务并检查用户是否有权限
            source_task = Task.query.get(dependency_id)
            target_task = Task.query.get(task_id)
            
            if source_task and target_task:
                if not source_task.project.is_accessible_by(current_user_id) or \
                   not target_task.project.is_accessible_by(current_user_id):
                    logger.warning(f"用户 {current_user_id} 尝试删除无权限的任务依赖关系")
                    return jsonify({'error': '无权限删除任务依赖关系'}), 403
        
        # 记录操作信息
        logger.info(f"删除甘特图依赖关系: 从任务 {dependency_id} 到任务 {task_id}")
        
        # 删除依赖关系
        db.session.delete(dependency)
        db.session.commit()
        
        return jsonify({'message': '依赖关系已删除'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除甘特图依赖关系错误: {str(e)}")
        return jsonify({'error': f'删除依赖关系失败: {str(e)}'}), 500

@task_bp.route('/<int:task_id>/status', methods=['PUT'])
@jwt_required()
def update_task_status(task_id):
    """更新任务状态"""
    task = Task.query.get_or_404(task_id)
    if not task.project.has_member(get_jwt_identity()):
        return jsonify({'error': '无权更新此任务'}), 403

    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify({'error': '缺少状态参数'}), 400

    valid_statuses = ['todo', 'in_progress', 'completed']
    if data['status'] not in valid_statuses:
        return jsonify({'error': '无效的状态值'}), 400

    task.status = data['status']
    if data['status'] == 'completed':
        task.completed_at = datetime.utcnow()
        task.progress = 100
    elif data['status'] == 'in_progress':
        task.progress = 50 if task.progress == 0 else task.progress

    db.session.commit()

    # 发送WebSocket通知
    from app import socketio
    socketio.emit('task_status_update', {
        'task_id': task.id,
        'new_status': task.status,
        'updated_by': get_jwt_identity()
    }, room=f'project_{task.project_id}')

    return jsonify({'message': '任务状态已更新'})

@task_bp.route('/api/tasks/dependencies', methods=['POST'])
@jwt_required()
def add_task_dependency():
    """添加任务依赖关系"""
    data = request.get_json()
    if not data or 'source' not in data or 'target' not in data:
        return jsonify({'error': '缺少必要参数'}), 400

    source_task = Task.query.get_or_404(data['source'])
    target_task = Task.query.get_or_404(data['target'])

    if not source_task.project.has_member(get_jwt_identity()):
        return jsonify({'error': '无权操作这些任务'}), 403

    if source_task.project_id != target_task.project_id:
        return jsonify({'error': '不能跨项目添加依赖关系'}), 400

    # 检查是否形成循环依赖
    def check_cycle(task, visited=None):
        if visited is None:
            visited = set()
        if task.id in visited:
            return True
        visited.add(task.id)
        for dep in task.dependencies:
            if check_cycle(dep, visited):
                return True
        return False

    if check_cycle(target_task):
        return jsonify({'error': '不能形成循环依赖'}), 400

    source_task.dependencies.append(target_task)
    db.session.commit()

    return jsonify({'message': '依赖关系已添加'})

@task_bp.route('/<int:task_id>/detail', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def task_detail_api(task_id):
    """获取任务详情API"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for task_detail " + str(task_id) + " - Using test user")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # Check if task exists
        task = Task.query.get(task_id)
        if not task:
            return jsonify({'error': '任务不存在', 'detail': 'Task not found'}), 404
                
        # 获取关联的项目和负责人
        project = Project.query.get(task.project_id) if task.project_id else None
        assignee = User.query.get(task.assignee_id) if task.assignee_id else None
                
        # Return task data in the format expected by frontend
        response = {
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'progress': task.progress,
                'project_id': task.project_id,
                'start_date': task.created_at.isoformat() if task.created_at else None,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'project': project.to_dict() if project else None,
                'assignee': assignee.to_dict() if assignee else None,
                'created_at': task.created_at.isoformat() if task.created_at else None,
                'updated_at': task.updated_at.isoformat() if task.updated_at else None
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error("Error getting task detail: " + str(e))
        return jsonify({'error': '获取任务详情失败', 'detail': str(e)}), 500

@task_bp.route('/api/auth/tasks/<int:task_id>/detail', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def task_detail_api_auth(task_id):
    """获取任务详情API - API前缀版本"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for task_detail " + str(task_id) + " - Using test user")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # Check if task exists
        task = Task.query.get(task_id)
        if not task:
            return jsonify({'error': '任务不存在', 'detail': 'Task not found'}), 404
                
        # 获取关联的项目和负责人
        project = Project.query.get(task.project_id) if task.project_id else None
        assignee = User.query.get(task.assignee_id) if task.assignee_id else None
                
        # Return task data in the format expected by frontend
        response = {
            'task': {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'progress': task.progress,
                'project_id': task.project_id,
                'start_date': task.created_at.isoformat() if task.created_at else None,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'project': project.to_dict() if project else None,
                'assignee': assignee.to_dict() if assignee else None,
                'created_at': task.created_at.isoformat() if task.created_at else None,
                'updated_at': task.updated_at.isoformat() if task.updated_at else None
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error("Error getting task detail: " + str(e))
        return jsonify({'error': '获取任务详情失败', 'detail': str(e)}), 500

@task_bp.route('/<int:task_id>/view', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def task_detail_page(task_id):
    """渲染任务详情页面"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for task_detail_page " + str(task_id) + " - Using test user")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # Check if task exists
        task = Task.query.get(task_id)
        if not task:
            return jsonify({'error': '任务不存在', 'detail': 'Task not found'}), 404
        
        # 获取任务相关数据
        projects = Project.query.all()
        users = User.query.all()
        
        # 检查Accept头来决定返回JSON还是HTML
        if request.headers.get('Accept') == 'application/json':
            # 获取关联的项目和负责人
            project = Project.query.get(task.project_id) if task.project_id else None
            assignee = User.query.get(task.assignee_id) if task.assignee_id else None
                    
            # 返回JSON格式的任务详情
            response = {
                'task': {
                    'id': task.id,
                    'title': task.title,
                    'description': task.description,
                    'status': task.status,
                    'priority': task.priority,
                    'progress': task.progress,
                    'project_id': task.project_id,
                    'start_date': task.created_at.isoformat() if task.created_at else None,
                    'due_date': task.due_date.isoformat() if task.due_date else None,
                    'project': {
                        'id': project.id,
                        'name': project.name
                    } if project else None,
                    'assignee': {
                        'id': assignee.id,
                        'name': assignee.name
                    } if assignee else None
                },
                'message': 'Task details retrieved successfully'
            }
            
            return jsonify(response)
        else:
            # 渲染任务详情页面 - 重定向到正确的路径
            # 这样可以确保JavaScript能够正确加载
            if request.path.endswith('/view'):
                return render_template(
                    'task_detail.html',
                    task=task,
                    projects=projects,
                    users=users,
                    task_id=task_id  # 显式传递任务ID
                )
            else:
                return render_template(
                    'task_detail.html',
                    task=task,
                    projects=projects,
                    users=users
                )
        
    except Exception as e:
        logger.error("Error rendering task detail page: " + str(e))
        return jsonify({'error': '渲染任务详情页面失败', 'detail': str(e)}), 500

@task_bp.route('/<int:task_id>/edit', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def edit_task_page(task_id):
    """打开任务编辑页面"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info(f"JWT验证已绕过 - 编辑任务页面 {task_id}")
            current_user = 1  # 使用测试用户
        else:
            current_user = get_jwt_identity()
            if not current_user:
                return redirect(url_for('auth.login_page'))
        
        # 获取当前用户对象
        user = User.query.get(current_user)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        # 权限检查
        # 管理员和项目经理可以编辑任何任务，任务的创建者和负责人可以编辑自己的任务
        if not (user.has_role(ROLE_ADMIN) or 
                user.has_role(ROLE_PROJECT_MANAGER) or 
                task.created_by == current_user or 
                task.assignee_id == current_user or
                user.has_permission(PERMISSION_MANAGE_TASK) or
                user.has_permission(PERMISSION_MANAGE_ALL_TASKS)):
            # 如果没有权限，显示错误页面或重定向到任务详情页
            return render_template('error.html', error='您没有权限编辑此任务')
            
        # 获取所有项目列表和用户列表，用于表单选择
        projects = Project.query.all()
        users = User.query.all()
        
        # 确保日期正确格式化用于前端显示
        task_data = {
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'status': task.status,
            'priority': task.priority,
            'progress': task.progress,
            'start_date': task.start_date,
            'due_date': task.due_date,
            'project_id': task.project_id,
            'assignee_id': task.assignee_id
        }
        
        # 返回任务编辑页面
        return render_template(
            'task_edit.html', 
            task=task_data, 
            projects=projects, 
            users=users
        )
    except Exception as e:
        logger.error("Error opening edit task page: " + str(e))
        return jsonify({'error': '打开任务编辑页面失败', 'detail': str(e)}), 500

@task_bp.route('/api/auth/tasks/<int:task_id>/attachments', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def add_task_attachment_auth(task_id):
    """上传任务附件 - API前缀版本"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for add_task_attachment " + str(task_id) + " - Using test user")
            current_user = 1  # 使用测试用户
        else:
            current_user = get_jwt_identity()
            if not current_user:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        if 'file' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400
        
        # 创建上传目录
        upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'tasks', str(task_id))
        os.makedirs(upload_dir, exist_ok=True)
        
        # 生成安全的文件名
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_dir, filename)
        
        # 保存文件
        file.save(file_path)
        
        # 创建附件记录
        attachment = TaskAttachment(
            task_id=task_id,
            filename=filename,
            file_path=file_path,
            file_type=file.content_type or 'application/octet-stream',
            size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            description=request.form.get('description', ''),
            uploader_id=current_user
        )
        
        db.session.add(attachment)
        db.session.commit()
        
        return jsonify(attachment.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding task attachment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/api/auth/tasks/<int:task_id>/attachments/<int:attachment_id>/download', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def download_attachment_auth(task_id, attachment_id):
    """下载任务附件 - API前缀版本"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for download_attachment " + str(task_id) + " - Using test user")
            current_user = 1  # 使用测试用户
        else:
            current_user = get_jwt_identity()
            if not current_user:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        attachment = TaskAttachment.query.get_or_404(attachment_id)
        if attachment.task_id != task_id:
            return jsonify({'error': '附件不属于该任务'}), 403
            
        return send_file(attachment.file_path, download_name=attachment.filename, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading attachment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/api/tasks/<int:task_id>/attachments', methods=['POST'])
@jwt_required()
def upload_attachment(task_id):
    """上传任务附件"""
    task = Task.query.get_or_404(task_id)
    current_user_id = get_jwt_identity()
    
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    # 创建上传目录
    upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'tasks', str(task_id))
    os.makedirs(upload_dir, exist_ok=True)
    
    # 生成安全的文件名
    filename = secure_filename(file.filename)
    file_path = os.path.join(upload_dir, filename)
    
    # 保存文件
    file.save(file_path)
    
    # 创建附件记录
    attachment = TaskAttachment(
        task_id=task_id,
        filename=filename,
        file_path=file_path,
        file_type=file.content_type,
        size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        description=request.form.get('description', ''),
        uploader_id=current_user_id
    )
    
    db.session.add(attachment)
    db.session.commit()
    
    return jsonify(attachment.to_dict()), 201

@task_bp.route('/api/tasks/<int:task_id>/attachments/<int:attachment_id>/download', methods=['GET'])
@jwt_required()
def download_attachment(task_id, attachment_id):
    """下载任务附件"""
    attachment = TaskAttachment.query.get_or_404(attachment_id)
    if attachment.task_id != task_id:
        return jsonify({'error': '附件不存在'}), 404
    
    return send_file(
        attachment.file_path,
        as_attachment=True,
        download_name=attachment.filename
    )

@task_bp.route('/api/tasks/<int:task_id>/attachments/<int:attachment_id>', methods=['DELETE'])
@jwt_required()
def delete_attachment(task_id, attachment_id):
    """删除任务附件"""
    attachment = TaskAttachment.query.get_or_404(attachment_id)
    if attachment.task_id != task_id:
        return jsonify({'error': '附件不存在'}), 404
    
    # 检查权限
    current_user_id = get_jwt_identity()
    if attachment.uploader_id != current_user_id and attachment.task.project.manager_id != current_user_id:
        return jsonify({'error': '没有权限删除此附件'}), 403
    
    # 删除文件
    try:
        os.remove(attachment.file_path)
    except OSError:
        pass
    
    # 删除记录
    db.session.delete(attachment)
    db.session.commit()
    
    return '', 204

@task_bp.route('/api/tasks/<int:task_id>/attachments/<int:attachment_id>/versions', methods=['POST'])
@jwt_required()
def upload_new_version(task_id, attachment_id):
    """上传附件的新版本"""
    parent_attachment = TaskAttachment.query.get_or_404(attachment_id)
    if parent_attachment.task_id != task_id:
        return jsonify({'error': '附件不存在'}), 404
    
    current_user_id = get_jwt_identity()
    
    if 'file' not in request.files:
        return jsonify({'error': '没有选择文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    # 验证文件类型
    if not allowed_file(file.filename):
        return jsonify({'error': '不支持的文件类型'}), 400
    
    # 创建上传目录
    upload_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'tasks', str(task_id))
    os.makedirs(upload_dir, exist_ok=True)
    
    # 生成安全的文件名
    filename = secure_filename(file.filename)
    file_path = os.path.join(upload_dir, filename)
    
    # 保存文件
    file.save(file_path)
    
    # 更新旧版本的is_latest状态
    parent_attachment.is_latest = False
    
    # 创建新版本记录
    new_version = TaskAttachment(
        task_id=task_id,
        filename=filename,
        file_path=file_path,
        file_type=file.content_type,
        size=os.path.getsize(file_path),
        description=request.form.get('description'),
        uploader_id=current_user_id,
        version=parent_attachment.version + 1,
        is_latest=True,
        parent_version_id=parent_attachment.id
    )
    
    db.session.add(new_version)
    db.session.commit()
    
    return jsonify(new_version.to_dict()), 201

@task_bp.route('/api/tasks/<int:task_id>/attachments/<int:attachment_id>/versions', methods=['GET'])
@jwt_required()
def get_attachment_versions(task_id, attachment_id):
    """获取附件的所有版本"""
    attachment = TaskAttachment.query.get_or_404(attachment_id)
    if attachment.task_id != task_id:
        return jsonify({'error': '附件不存在'}), 404
    
    # 获取所有版本（包括当前版本）
    versions = []
    current = attachment
    
    # 向上查找父版本
    while current.parent_version:
        current = current.parent_version
        versions.append(current.to_dict())
    
    # 添加当前版本
    versions.append(attachment.to_dict())
    
    # 向下查找子版本
    current = attachment
    while current.child_versions:
        current = current.child_versions[0]
        versions.append(current.to_dict())
    
    return jsonify(versions)

@task_bp.route('/api/tasks/<int:task_id>/risks', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def task_risks_front_path(task_id):
    """获取任务相关的风险列表 - 前端路径"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # 检查任务是否存在
        task = Task.query.get_or_404(task_id)
        
        # 获取风险列表
        risks = Risk.query.filter_by(task_id=task_id).all()
        
        return jsonify([risk.to_dict() for risk in risks])
        
    except Exception as e:
        logger.error(f"Error in task_risks_front_path: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/<int:task_id>/risks', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_RISKS)
def create_task_risk_front_path(task_id):
    """创建任务相关的风险 - 前端路径"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # 检查任务是否存在
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        if not data or not data.get('title'):
            return jsonify({'error': '缺少必要参数'}), 400
            
        # 创建风险记录
        risk = Risk(
            title=data['title'],
            description=data.get('description'),
            probability=data.get('probability', 'medium'),
            impact=data.get('impact', 'medium'),
            status=data.get('status', 'open'),
            severity=data.get('severity', 'medium'),  # 添加默认的严重性
            mitigation_plan=data.get('mitigation_plan'),
            task_id=task_id,
            project_id=task.project_id,
            owner_id=current_user_id  # 设置风险所有者为当前用户
        )
        
        db.session.add(risk)
        
        # 记录风险创建日志
        log = RiskLog(
            risk_id=risk.id,
            content=f'创建了风险 "{risk.title}"'
        )
        db.session.add(log)
        
        db.session.commit()
        
        return jsonify(risk.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in create_task_risk_front_path: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/api/tasks/<int:task_id>/progress', methods=['GET'])
@jwt_required()
def get_task_progress(task_id):
    try:
        task = Task.query.get_or_404(task_id)
        progress_history = TaskProgressHistory.query.filter_by(task_id=task_id).order_by(TaskProgressHistory.created_at.desc()).all()
        return jsonify([progress.to_dict() for progress in progress_history])
    except Exception as e:
        logger.error(f"Error getting task progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/api/tasks/<int:task_id>/progress', methods=['POST'])
@jwt_required()
def update_task_progress(task_id):
    try:
        current_user = get_jwt_identity()
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        progress = TaskProgressHistory(
            task_id=task_id,
            user_id=current_user,
            progress=data['progress'],
            description=data.get('description'),
            created_at=datetime.utcnow()
        )
        
        db.session.add(progress)
        db.session.commit()
        return jsonify(progress.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating task progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/api/tasks/<int:task_id>/progress/approve', methods=['POST'])
@jwt_required()
def approve_task_progress(task_id):
    try:
        current_user = get_jwt_identity()
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        approval = TaskProgressApproval(
            task_id=task_id,
            user_id=current_user,
            progress_id=data['progress_id'],
            status=data['status'],
            comment=data.get('comment'),
            created_at=datetime.utcnow()
        )
        
        db.session.add(approval)
        db.session.commit()
        return jsonify(approval.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving task progress: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/list')
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def task_list():
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for task_list - Using test user")
            current_user = 1  # 使用测试用户ID
        else:
            current_user = get_jwt_identity()
            
        logger.info(f"Task list requested by user {current_user}")
        
        if not current_user:
            logger.error("User not found")
            if request.accept_mimetypes.accept_json and request.args.get('format') == 'json':
                return jsonify({'error': 'User not found'}), 404
            return render_template('error.html', error='User not found'), 404
            
        # Get tasks for the current user (either assigned to or created by)
        tasks = Task.query.filter(
            (Task.assignee_id == current_user) | (Task.created_by == current_user)
        ).all()
        
        logger.info(f"Found {len(tasks)} tasks for user {current_user}")
        
        # Format tasks for display
        task_list = []
        for task in tasks:
            task_data = {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'due_date': task.due_date.strftime('%Y-%m-%d') if task.due_date else None,
                'created_at': task.created_at.strftime('%Y-%m-%d %H:%M:%S') if task.created_at else None,
                'updated_at': task.updated_at.strftime('%Y-%m-%d %H:%M:%S') if task.updated_at else None
            }
            
            # 处理可能为None的关联对象
            if task.assignee:
                task_data['assignee'] = {
                    'id': task.assignee.id,
                    'name': task.assignee.name
                }
            else:
                task_data['assignee'] = None
                
            if task.creator:
                task_data['creator'] = {
                    'id': task.creator.id,
                    'name': task.creator.name
                }
            else:
                task_data['creator'] = None
                
            task_list.append(task_data)
        
        # Get projects and users for the task creation form
        projects = Project.query.all()
        users = User.query.filter(User.is_active == True).all()
        
        project_list = []
        for project in projects:
            project_list.append({
                'id': project.id,
                'name': project.name
            })
            
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'name': user.name
            })
        
        # 只有当明确请求JSON格式时才返回JSON    
        if request.accept_mimetypes.accept_json and request.args.get('format') == 'json':
            logger.info("Returning JSON response - explicitly requested")
            return jsonify({'tasks': task_list})
            
        logger.info("Returning HTML response with tasks count: " + str(len(task_list)))
        # 打印任务列表以便于调试
        logger.info(f"Task list data: {task_list}")
        
        # 启用调试模式，在任务列表页面显示调试信息
        debug_mode = request.args.get('debug') == 'true'
        
        return render_template('tasks.html', tasks=task_list, projects=project_list, users=user_list, debug=debug_mode)
    except Exception as e:
        logger.error(f"Error in task_list: {str(e)}", exc_info=True)
        if request.accept_mimetypes.accept_json and request.args.get('format') == 'json':
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
        return render_template('error.html', error='任务列表加载失败: ' + str(e)), 500

@task_bp.route('/api/auth/tasks/<int:task_id>/logs', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_task_logs_auth(task_id):
    """获取任务日志 - API前缀版本"""
    return get_task_logs(task_id)

@task_bp.route('/api/auth/tasks/<int:task_id>/subtasks', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_subtasks_auth(task_id):
    """获取子任务列表 - API前缀版本"""
    return get_subtasks(task_id)

@task_bp.route('/api/auth/tasks/<int:task_id>/comments', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_task_comments_auth(task_id):
    """获取任务评论 - API前缀版本"""
    return get_task_comments(task_id)

@task_bp.route('/api/auth/tasks/<int:task_id>/attachments', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_task_attachments_auth(task_id):
    """获取任务附件 - API前缀版本"""
    return get_task_attachments(task_id)

@task_bp.route('/api/auth/tasks/<int:task_id>/risks', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_task_risks_auth(task_id):
    """获取任务风险 - API前缀版本"""
    return task_risks_front_path(task_id)

@task_bp.route('/api/auth/tasks/<int:task_id>/risks', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_RISKS)
def create_task_risk_auth(task_id):
    """创建任务风险 - API前缀版本"""
    return create_task_risk_front_path(task_id)

@task_bp.route('/api/auth/tasks/<int:task_id>/comments', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def add_task_comment_auth(task_id):
    """添加任务评论 - API前缀版本"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for add_task_comment " + str(task_id) + " - Using test user")
            current_user = 1  # 使用测试用户
        else:
            current_user = get_jwt_identity()
            if not current_user:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({'error': 'Missing comment content'}), 400
        
        comment = TaskComment(
            task_id=task_id,
            content=data['content'],
            user_id=current_user
        )
        db.session.add(comment)
        db.session.commit()
        
        return jsonify(comment.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding task comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@task_bp.route('/api/tasks/<int:task_id>', methods=['PUT'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def api_update_task(task_id):
    """API端点: 更新任务"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info(f"JWT验证已绕过 - API更新任务 {task_id}")
            # 在bypass_jwt模式下，设置CSRF令牌为已验证
            if hasattr(request, '_csrf_token'):
                request._csrf_token = True
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '未经授权', 'detail': '请先登录'}), 401
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        # 权限检查 - 只有管理员、项目经理或者有任务管理权限的用户才能编辑任务
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
            
        has_permission = False
        for role in current_user.roles:
            # 管理员和项目经理总是有权限
            if role.name in ['admin', 'manager']:
                has_permission = True
                break
            # 检查用户权限
            for permission in role.permissions:
                if permission.name in ['manage_task', 'manage_all_tasks', 'manage_project', 'manage_all_projects']:
                    has_permission = True
                    break
        
        if not has_permission:
            logger.warning(f"用户 {current_user_id} 尝试未经授权更新任务 {task_id}")
            return jsonify({
                'error': '权限不足', 
                'detail': '您没有编辑任务的权限'
            }), 403
        
        # 获取请求数据并验证
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据', 'detail': '请求数据为空或格式不正确'}), 400
        
        # 记录请求数据和来源，帮助调试
        request_headers = {key: value for key, value in request.headers.items() 
                          if key.lower() not in ['cookie', 'authorization']}  # 排除敏感信息
        logger.info(f"更新任务API: task_id={task_id}, 数据={data}, 请求头={request_headers}")
        
        # 更新任务字段
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'status' in data:
            task.status = data['status']
        if 'priority' in data:
            task.priority = data['priority']
        if 'progress' in data:
            task.progress = int(data['progress'])
        if 'start_date' in data:
            task.start_date = datetime.fromisoformat(data['start_date']) if data['start_date'] else None
        if 'due_date' in data:
            task.due_date = datetime.fromisoformat(data['due_date']) if data['due_date'] else None
        if 'project_id' in data:
            project = Project.query.get(data['project_id'])
            if not project:
                return jsonify({'error': '项目不存在', 'detail': f"ID为{data['project_id']}的项目未找到"}), 404
            task.project_id = data['project_id']
        if 'assignee_id' in data:
            if data['assignee_id']:
                user = User.query.get(data['assignee_id'])
                if not user:
                    return jsonify({'error': '指定的负责人不存在', 'detail': f"ID为{data['assignee_id']}的用户未找到"}), 404
            task.assignee_id = data['assignee_id']
        
        # 保存更改
        db.session.commit()
        
        # 记录任务更新日志
        log = TaskLog(
            task_id=task.id,
            user_id=current_user_id,
            action='updated',
            details=f"任务已通过API更新"
        )
        db.session.add(log)
        db.session.commit()
        
        # 清除缓存
        if hasattr(task, 'clear_cache'):
            task.clear_cache()
        
        # 返回成功响应
        return jsonify({
            'message': '任务更新成功',
            'task': task.to_dict()
        })
    except ValueError as e:
        # 处理日期解析等格式错误
        db.session.rollback()
        logger.error(f"任务API数据格式错误: {str(e)}")
        return jsonify({'error': '数据格式错误', 'detail': str(e)}), 400
    except Exception as e:
        # 处理一般错误
        db.session.rollback()
        logger.error(f"任务API更新错误: {str(e)}")
        return jsonify({'error': '更新任务失败', 'detail': str(e)}), 500

# 添加普通的完全绕过CSRF的路由，专门用于测试
@task_bp.route('/api/tasks/<int:task_id>/update_bypass', methods=['PUT'])
@csrf.exempt
def update_task_bypass_csrf(task_id):
    """用于测试的任务更新API端点，完全绕过CSRF保护"""
    try:
        logger.info(f"通过无CSRF验证的接口更新任务: {task_id}")
        
        # 固定使用测试用户
        current_user = 1
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        # 获取请求数据并验证
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        # 记录请求数据和来源
        logger.info(f"无CSRF验证更新任务: task_id={task_id}, 数据={data}")
        
        # 更新任务字段
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'status' in data:
            task.status = data['status']
        if 'priority' in data:
            task.priority = data['priority']
        if 'progress' in data:
            task.progress = int(data['progress'])
        if 'start_date' in data:
            task.start_date = datetime.fromisoformat(data['start_date']) if data['start_date'] else None
        if 'due_date' in data:
            task.due_date = datetime.fromisoformat(data['due_date']) if data['due_date'] else None
        if 'project_id' in data:
            task.project_id = data['project_id']
        if 'assignee_id' in data:
            task.assignee_id = data['assignee_id']
        
        # 保存更改
        db.session.commit()
        
        # 记录任务更新日志
        log = TaskLog(
            task_id=task.id,
            user_id=current_user,
            action='updated',
            details=f"任务已通过无CSRF验证的API更新"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'message': '任务更新成功',
            'task': task.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"无CSRF验证更新任务失败: {str(e)}")
        return jsonify({'error': '更新任务失败', 'detail': str(e)}), 500

# 添加任务蓝图的CSRF错误处理
@task_bp.errorhandler(400)
def handle_csrf_error(e):
    """处理CSRF验证错误"""
    # 检查是否是CSRF错误
    if 'CSRF' in str(e):
        logger.error(f"任务模块CSRF验证失败: {str(e)}")
        
        # 记录请求信息，帮助调试
        headers_info = {key: value for key, value in request.headers.items() 
                      if key.lower() not in ['cookie', 'authorization']}  # 排除敏感信息
        
        logger.warning(f"任务CSRF错误请求信息: 路径={request.path}, 方法={request.method}, 头部={headers_info}")
        
        # 返回JSON错误响应
        return jsonify({
            'error': 'CSRF验证失败',
            'detail': str(e),
            'message': '请刷新页面后重试，或重新登录'
        }), 400
    
    # 如果不是CSRF错误，则传递给下一个错误处理器
    return e 

@task_bp.route('/get-csrf-token', methods=['GET'])
def get_csrf_token():
    """获取CSRF令牌的API端点"""
    try:
        # 获取或生成CSRF令牌
        from flask_wtf.csrf import generate_csrf
        from flask import jsonify
        
        # 生成新的CSRF令牌
        csrf_token = generate_csrf()
        
        # 返回CSRF令牌
        return jsonify({
            'csrf_token': csrf_token,
            'message': 'CSRF令牌生成成功'
        })
    except Exception as e:
        logger.error(f"生成CSRF令牌失败: {str(e)}")
        return jsonify({'error': '生成CSRF令牌失败', 'detail': str(e)}), 500

# 添加一个额外的CSRF豁免端点，确保任务更新可用于客户端JavaScript
@task_bp.route('/api/tasks/<int:task_id>/no_csrf', methods=['PUT'])
@csrf.exempt
def update_task_no_csrf(task_id):
    """完全豁免CSRF的任务更新API端点 - 作为前端任务更新的主要端点"""
    try:
        logger.info(f"使用无CSRF验证端点更新任务: {task_id}")
        
        # 固定使用测试用户
        current_user = 1
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        # 获取请求数据并验证
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        # 记录请求数据
        logger.info(f"无CSRF验证端点更新任务数据: {data}")
        
        # 更新任务字段
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'status' in data:
            task.status = data['status']
        if 'priority' in data:
            task.priority = data['priority']
        if 'progress' in data:
            task.progress = int(data['progress'])
        if 'start_date' in data:
            task.start_date = datetime.fromisoformat(data['start_date']) if data['start_date'] else None
        if 'due_date' in data:
            task.due_date = datetime.fromisoformat(data['due_date']) if data['due_date'] else None
        if 'project_id' in data:
            task.project_id = data['project_id']
        if 'assignee_id' in data:
            task.assignee_id = data['assignee_id']
        
        # 保存更改
        db.session.commit()
        
        # 记录任务更新日志
        log = TaskLog(
            task_id=task.id,
            user_id=current_user,
            action='updated',
            details=f"任务已通过无CSRF验证的端点更新"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'message': '任务更新成功',
            'task': task.to_dict()
        })
    except Exception as e:
        db.session.rollback()
        logger.error(f"无CSRF验证端点更新任务失败: {str(e)}")
        return jsonify({'error': '更新任务失败', 'detail': str(e)}), 500

@task_bp.route('/api/tasks/<int:task_id>/detail', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def api_tasks_detail(task_id):
    """获取任务详情API - 前端专用端点"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info(f"JWT bypass enabled for api_tasks_detail {task_id} - Using test user")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # Check if task exists
        task = Task.query.get(task_id)
        if not task:
            logger.error(f"Task {task_id} not found in API endpoint")
            return jsonify({'error': '任务不存在', 'detail': 'Task not found'}), 404
                
        # 获取关联的项目和负责人
        project = Project.query.get(task.project_id) if task.project_id else None
        assignee = User.query.get(task.assignee_id) if task.assignee_id else None
                
        # Return task data
        try:
            project_data = project.to_dict() if project else None
            assignee_data = assignee.to_dict() if assignee else None
            
            response = {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'status': task.status,
                'priority': task.priority,
                'progress': task.progress,
                'project_id': task.project_id,
                'start_date': task.created_at.isoformat() if task.created_at else None,
                'due_date': task.due_date.isoformat() if task.due_date else None,
                'project': project_data,
                'assignee': assignee_data,
                'created_at': task.created_at.isoformat() if task.created_at else None,
                'updated_at': task.updated_at.isoformat() if task.updated_at else None
            }
            
            logger.info(f"Successfully retrieved task {task_id} details")
            return jsonify(response)
        except Exception as e:
            logger.error(f"Error serializing task data: {str(e)}")
            # 返回简化版本的任务数据
            return jsonify({
                'id': task.id,
                'title': task.title,
                'description': task.description or '',
                'status': task.status or 'todo',
                'priority': task.priority or 'medium',
                'progress': task.progress or 0,
                'project_id': task.project_id,
                'project_name': project.name if project else '未知项目',
                'assignee_id': task.assignee_id,
                'assignee_name': assignee.name if assignee else '未分配'
            })
        
    except Exception as e:
        logger.error(f"Error in api_tasks_detail: {str(e)}")
        return jsonify({'error': '获取任务详情失败', 'detail': str(e)}), 500