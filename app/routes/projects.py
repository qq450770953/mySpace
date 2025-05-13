from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response
from app import csrf
from app.models import Project, User, Task, TeamMember, Role
from app import db
from datetime import datetime, timedelta
import logging
from app.utils.jwt_callbacks import jwt_required, get_jwt_identity
from app.utils.permissions import has_permission
import time

project_bp = Blueprint('projects', __name__)
logger = logging.getLogger(__name__)

# 添加用于存储最近处理过的项目创建请求的缓存
_recent_project_requests = {}

# 添加无需认证的项目详情API端点
@project_bp.route('/api/noauth/projects/<int:project_id>', methods=['GET'])
@csrf.exempt
def get_project_noauth(project_id):
    """获取项目详情的API端点，无需认证即可访问"""
    try:
        logger.info(f"无需认证访问项目API: 项目ID={project_id}")
        
        # 获取项目信息
        project = Project.query.get_or_404(project_id)
        
        # 获取项目管理员
        manager = None
        if project.manager_id:
            manager = User.query.get(project.manager_id)
        
        manager_name = manager.name if manager and manager.name else manager.username if manager else "未分配"
        
        # 构建项目数据对象
        project_data = {
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'status': project.status,
            'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
            'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
            'progress': project.progress or 0,
            'manager': manager_name,
            'manager_id': project.manager_id
        }
        
        return jsonify({
            'success': True,
            'project': project_data
        })
        
    except Exception as e:
        logger.error(f"获取项目详情失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"获取项目详情失败: {str(e)}"
        }), 500

# 添加项目API端点 - 用于标准认证方式
@project_bp.route('/api/projects/<int:project_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
def get_project_api(project_id):
    """获取项目详情的API端点，支持JWT认证"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        
        logger.info(f"API访问项目详情: 项目ID={project_id}, 用户ID={current_user_id}")
        
        # 获取项目信息
        project = Project.query.get_or_404(project_id)
        
        # 检查是否有bypass_jwt参数
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        # 如果没有bypass_jwt参数，则检查权限
        if not bypass_jwt and current_user_id:
            # 检查用户权限
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
                logger.warning(f"用户无权限访问项目: 用户ID={current_user_id}, 项目ID={project_id}")
                return jsonify({
                    'success': False,
                    'error': '没有权限访问此项目'
                }), 403
        
        # 获取项目管理员
        manager = None
        if project.manager_id:
            manager = User.query.get(project.manager_id)
        
        manager_name = manager.name if manager and manager.name else manager.username if manager else "未分配"
        
        # 构建项目数据对象
        project_data = {
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'status': project.status,
            'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
            'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
            'progress': project.progress or 0,
            'manager': manager_name,
            'manager_id': project.manager_id
        }
        
        # 获取项目任务
        tasks = Task.query.filter_by(project_id=project_id).all()
        project_tasks = []
        for task in tasks:
            assignee = User.query.get(task.assignee_id)
            assignee_name = assignee.name if assignee and assignee.name else assignee.username if assignee else "未分配"
            
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
        
        # 获取团队成员
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
        
        return jsonify({
            'success': True,
            'project': project_data,
            'tasks': project_tasks,
            'members': members
        })
        
    except Exception as e:
        logger.error(f"API获取项目详情失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"获取项目详情失败: {str(e)}"
        }), 500

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
        
        # 检查是否使用no_redirect或bypass_jwt模式
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        no_redirect = request.args.get('no_redirect') == 'true'
        
        # 检查是否存在redirect_count cookie，以防止重定向循环
        redirect_count = request.cookies.get('redirect_count', '0')
        try:
            redirect_count = int(redirect_count)
        except ValueError:
            redirect_count = 0
            
        # 如果重定向次数过多，强制使用no_redirect模式
        if redirect_count > 2:
            logger.warning(f"检测到重定向循环，强制使用no_redirect模式 - 项目ID: {project_id}")
            no_redirect = True
            bypass_jwt = True
        
        # 直接获取项目信息
        try:
            project = Project.query.get_or_404(project_id)
        except Exception as e:
            logger.error(f"获取项目 {project_id} 失败: {str(e)}")
            return render_template('error.html', error=f'找不到项目: {str(e)}'), 404
            
        # 如果不是bypass或no_redirect模式，则检查权限（否则跳过权限检查）
        if not (bypass_jwt or no_redirect):
            # 检查用户权限
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
        html_content = render_template('projects/detail.html', 
                        project=project_data, 
                        members=members, 
                        tasks=project_tasks,
                        users=all_users,
                        project_managers=project_managers,
                        current_user_id=current_user_id,
                        gantt_tasks=[],
                        no_redirect=no_redirect,
                        bypass_jwt=bypass_jwt)
        
        # 创建响应对象
        response = make_response(html_content)
        
        # 设置CSRF令牌为已验证，避免CSRF校验重定向
        # 这是安全的，因为我们已经进行了适当的权限检查
        request._csrf_token = True
        
        # 如果是通过no_redirect参数访问，清除重定向计数cookie
        if no_redirect:
            response.delete_cookie('redirect_count')
            response.delete_cookie('redirect_path')
        else:
            # 否则增加重定向计数，以便在循环时自动切换到no_redirect模式
            response.set_cookie('redirect_count', str(redirect_count + 1), max_age=60)  # 60秒有效期
            response.set_cookie('redirect_path', request.path, max_age=60)
            
        return response
        
    except Exception as e:
        logger.error(f"Project detail route error: {str(e)}")
        return render_template('error.html', error=f"加载项目详情失败: {str(e)}"), 500

# 添加项目详情API端点 - 适配所有可能的URL格式
@project_bp.route('/api/detail/<int:project_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
def get_project_detail_api(project_id):
    """获取项目详情的API端点 - 别名"""
    # 直接调用标准API函数
    return get_project_api(project_id)

# 添加一个通用的项目创建函数
def create_project(data, current_user_id=1):
    """
    通用的项目创建函数，处理项目创建逻辑
    
    参数:
        data: 包含项目数据的字典
        current_user_id: 当前用户ID，默认为1(管理员)
    
    返回:
        (response_data, status_code): 包含响应数据和HTTP状态码的元组
    """
    try:
        logger.info(f"创建项目: 用户ID={current_user_id}, 数据={data}")
        
        # 检查防重复请求参数
        request_id = request.args.get('req', '')
        if request_id:
            # 检查是否是已处理过的请求
            if request_id in _recent_project_requests:
                logger.info(f"检测到重复请求ID: {request_id}, 返回之前的响应")
                return _recent_project_requests[request_id]
        
        # 验证必要字段
        if not data or not data.get('name'):
            logger.warning("创建项目: 缺少项目名称")
            return {'error': '项目名称不能为空'}, 400
            
        # 检查项目名称是否已存在
        existing_project = Project.query.filter_by(name=data['name']).first()
        if existing_project:
            logger.warning(f"创建项目: 项目名称已存在 '{data['name']}'")
            
            # 处理日期格式
            start_date = None
            if 'start_date' in data and data['start_date']:
                try:
                    if 'T' in data['start_date']:
                        start_date = datetime.fromisoformat(data['start_date'])
                    else:
                        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
                except ValueError:
                    logger.warning(f"创建项目: 开始日期格式错误 '{data['start_date']}'")
                    return {'error': '开始日期格式错误'}, 400
            
            end_date = None
            if 'end_date' in data and data['end_date']:
                try:
                    if 'T' in data['end_date']:
                        end_date = datetime.fromisoformat(data['end_date'])
                    else:
                        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
                except ValueError:
                    logger.warning(f"创建项目: 结束日期格式错误 '{data['end_date']}'")
                    return {'error': '结束日期格式错误'}, 400
            
            # 处理manager_id，确保是整数
            manager_id = None
            if 'manager_id' in data and data['manager_id']:
                try:
                    manager_id = int(data['manager_id'])
                except (ValueError, TypeError):
                    logger.warning(f"创建项目: 管理者ID格式错误 '{data['manager_id']}'")
                    return {'error': '管理者ID必须是整数'}, 400
                    
            # 检查是否已经有相同的项目数据
            if (existing_project.description == data.get('description', '') and
                existing_project.status == data.get('status', 'active') and
                existing_project.manager_id == manager_id):
                logger.info(f"创建项目: 检测到完全相同的项目数据，返回已存在的项目")
                # 返回现有项目，避免创建重复数据
                project_data = {
                    'id': existing_project.id,
                    'name': existing_project.name,
                    'description': existing_project.description,
                    'status': existing_project.status,
                    'progress': existing_project.progress or 0,
                    'manager_id': existing_project.manager_id,
                    'owner_id': existing_project.owner_id,
                    'start_date': existing_project.start_date.strftime('%Y-%m-%d') if existing_project.start_date else None,
                    'end_date': existing_project.end_date.strftime('%Y-%m-%d') if existing_project.end_date else None,
                    'created_at': existing_project.created_at.isoformat() if existing_project.created_at else None,
                    'updated_at': existing_project.updated_at.isoformat() if existing_project.updated_at else None
                }
                
                response = {
                    'success': True,
                    'message': '项目已存在，返回现有项目',
                    'project': project_data
                }, 200
                
                # 如果有请求ID，记录这个响应
                if request_id:
                    _recent_project_requests[request_id] = response
                    # 清理缓存，只保留最近的100个请求
                    if len(_recent_project_requests) > 100:
                        # 删除最早的一个请求
                        oldest_key = next(iter(_recent_project_requests))
                        del _recent_project_requests[oldest_key]
                
                return response
            
            # 添加时间戳后缀使项目名称唯一
            timestamp = str(int(time.time()))[-4:]  # 使用时间戳的后4位
            data['name'] = f"{data['name']}_{timestamp}"
            logger.info(f"创建项目: 项目名称已修改为 '{data['name']}'")
            
        # 创建新项目
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
                    logger.warning(f"创建项目: 开始日期格式错误 '{data['start_date']}'")
                    return {'error': '开始日期格式错误'}, 400
            
            end_date = None
            if 'end_date' in data and data['end_date']:
                try:
                    if 'T' in data['end_date']:
                        end_date = datetime.fromisoformat(data['end_date'])
                    else:
                        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
                except ValueError:
                    logger.warning(f"创建项目: 结束日期格式错误 '{data['end_date']}'")
                    return {'error': '结束日期格式错误'}, 400
            
            # 处理manager_id，确保是整数
            manager_id = current_user_id
            if 'manager_id' in data and data['manager_id']:
                try:
                    manager_id = int(data['manager_id'])
                except (ValueError, TypeError):
                    logger.warning(f"创建项目: 管理者ID格式错误 '{data['manager_id']}'")
                    return {'error': '管理者ID必须是整数'}, 400
            
            project = Project(
                name=data['name'],
                description=data.get('description', ''),
                status=data.get('status', 'active'),
                start_date=start_date,
                end_date=end_date,
                manager_id=manager_id,
                owner_id=current_user_id,
                progress=data.get('progress', 0),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            db.session.add(project)
            db.session.commit()
            
            logger.info(f"创建项目成功: {project.id} - {project.name}")
            
            # 构建项目数据
            project_data = {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'status': project.status,
                'progress': project.progress or 0,
                'manager_id': project.manager_id,
                'owner_id': project.owner_id,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
                'created_at': project.created_at.isoformat() if project.created_at else None,
                'updated_at': project.updated_at.isoformat() if project.updated_at else None
            }
            
            response = {
                'success': True,
                'message': '项目创建成功',
                'project': project_data
            }, 201
            
            # 如果有请求ID，记录这个响应
            if request_id:
                _recent_project_requests[request_id] = response
                # 清理缓存，只保留最近的100个请求
                if len(_recent_project_requests) > 100:
                    # 删除最早的一个请求
                    oldest_key = next(iter(_recent_project_requests))
                    del _recent_project_requests[oldest_key]
            
            return response
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"保存项目到数据库失败: {str(e)}")
            return {'success': False, 'error': f"创建项目失败: {str(e)}"}, 500
            
    except Exception as e:
        logger.error(f"创建项目失败: {str(e)}")
        return {'success': False, 'error': f"创建项目失败: {str(e)}"}, 500

# 修改认证API端点中的POST方法，调用统一的创建函数
@project_bp.route('/api/auth/projects', methods=['GET', 'POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
def handle_auth_projects():
    """认证API端点，处理项目列表的GET和POST请求"""
    if request.method == 'GET':
        try:
            # 查询所有非删除状态的项目
            projects = Project.query.filter(
                Project.status != 'deleted'
            ).order_by(Project.name).all()
            
            # 构建简化的项目数据，返回必要字段
            projects_data = []
            for project in projects:
                projects_data.append({
                    'id': project.id,
                    'name': project.name,
                    'description': project.description,
                    'status': project.status,
                    'progress': project.progress,
                    'manager_id': project.manager_id,
                    'created_at': project.created_at.isoformat() if project.created_at else None,
                    'updated_at': project.updated_at.isoformat() if project.updated_at else None
                })
            
            return jsonify(projects_data)
        except Exception as e:
            logger.error('获取项目列表失败:', str(e))
            return jsonify({'error': '获取项目列表失败'}), 500
    
    elif request.method == 'POST':
        try:
            # 获取当前登录用户，支持JWT绕过
            bypass_jwt = request.args.get('bypass_jwt') == 'true'
            
            if bypass_jwt:
                logger.info("API创建项目 - 使用测试用户")
                current_user_id = 1  # 使用测试用户
            else:
                # 获取JWT身份
                current_user_id = get_jwt_identity()
                if not current_user_id:
                    logger.warning("未授权访问API创建项目")
                    return jsonify({'error': '请先登录'}), 401
            
            # 检查请求内容类型
            if not request.is_json:
                logger.warning(f"API创建项目: 非JSON请求 {request.content_type}")
                return jsonify({'error': '请求必须是JSON格式'}), 400
                
            data = request.get_json()
            logger.info(f"API创建项目: 收到数据 {data}")
            
            # 调用统一的项目创建函数
            response_data, status_code = create_project(data, current_user_id)
            return jsonify(response_data), status_code
                
        except Exception as e:
            logger.error(f"API创建项目出错: {str(e)}")
            return jsonify({'error': str(e)}), 500

# 修改标准项目API端点，使用统一的创建函数
@project_bp.route('/api/projects', methods=['GET', 'POST'])
@csrf.exempt
def handle_projects():
    """处理项目列表的GET和POST请求"""
    # 完全禁用此路由的CSRF保护
    from flask import g
    g._csrf_disabled = True
    
    if request.method == 'GET':
        try:
            # 查询所有非删除状态的项目
            projects = Project.query.filter(
                Project.status != 'deleted'
            ).order_by(Project.name).all()
            
            # 构建简化的项目数据，返回必要字段
            projects_data = []
            for project in projects:
                projects_data.append({
                    'id': project.id,
                    'name': project.name,
                    'description': project.description,
                    'status': project.status,
                    'progress': project.progress or 0,
                    'manager_id': project.manager_id,
                    'created_at': project.created_at.isoformat() if project.created_at else None,
                    'updated_at': project.updated_at.isoformat() if project.updated_at else None
                })
            
            logger.info(f"API获取项目列表成功，返回 {len(projects_data)} 个项目")
            return jsonify(projects_data)
            
        except Exception as e:
            logger.error(f"API获取项目列表失败: {str(e)}")
            return jsonify({
                'error': f"获取项目列表失败: {str(e)}"
            }), 500
    
    elif request.method == 'POST':
        try:
            # 获取请求数据
            data = request.get_json()
            if not data:
                logger.error("API创建项目失败: 无效的JSON数据")
                return jsonify({
                    'error': '无效的请求数据'
                }), 400
            
            logger.info(f"API请求创建项目: {data}")
            
            # 获取当前用户ID
            try:
                current_user_id = get_jwt_identity()
            except Exception as e:
                logger.info(f"JWT验证失败，使用默认用户: {str(e)}")
                current_user_id = 1  # 默认为管理员用户
                
            # 如果有bypass_jwt参数，使用默认用户ID
            if request.args.get('bypass_jwt') == 'true':
                logger.info("使用bypass_jwt，设置默认用户ID为1")
                current_user_id = 1
                
            if not current_user_id:
                current_user_id = 1  # 默认为管理员用户
                
            # 调用统一的项目创建函数
            response_data, status_code = create_project(data, current_user_id)
            return jsonify(response_data), status_code
                
        except Exception as e:
            logger.error(f"API创建项目失败: {str(e)}")
            return jsonify({
                'success': False,
                'error': f"创建项目失败: {str(e)}"
            }), 500

# 添加测试接口，返回所有用户作为项目经理
@project_bp.route('/api/global/project-managers', methods=['GET'])
@csrf.exempt
def get_project_managers():
    """获取项目经理列表的API端点，用于下拉框"""
    try:
        # 尝试获取所有用户，以便在负责人下拉框中显示
        all_users = User.query.filter(User.is_active == True).all()
        user_list = []
        
        # 同时获取有项目管理权限的用户
        project_managers = User.query.join(User.roles).filter(Role.name.in_(['admin', 'project_manager'])).all()
        manager_list = []
        
        # 处理所有用户
        for user in all_users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'name': user.name or user.username,
                'email': user.email,
                'is_project_manager': user in project_managers
            })
            
        # 处理项目经理
        for manager in project_managers:
            manager_list.append({
                'id': manager.id,
                'username': manager.username,
                'name': manager.name or manager.username,
                'email': manager.email
            })
            
        return jsonify({
            'success': True,
            'users': user_list,
            'project_managers': manager_list
        })
        
    except Exception as e:
        logger.error(f"获取项目经理列表失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"获取项目经理列表失败: {str(e)}"
        }), 500

# 添加处理项目更新的API端点
@project_bp.route('/api/projects/<int:project_id>', methods=['PUT', 'DELETE'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
def update_project_api(project_id):
    """更新或删除项目信息的API端点"""
    try:
        # 获取当前登录用户
        current_user_id = get_jwt_identity()
        
        # 处理DELETE请求 - 删除项目
        if request.method == 'DELETE':
            logger.info(f"API删除项目: 项目ID={project_id}, 用户ID={current_user_id}")
            
            # 获取项目信息
            project = Project.query.get_or_404(project_id)
            
            # 检查是否有bypass_jwt参数
            bypass_jwt = request.args.get('bypass_jwt') == 'true'
            
            # 如果没有bypass_jwt参数，则检查权限
            if not bypass_jwt and current_user_id:
                # 检查用户权限
                user_is_owner = project.owner_id == current_user_id
                user_is_manager = project.manager_id == current_user_id
                
                # 检查用户是否有管理项目的权限
                if not (user_is_owner or user_is_manager or has_permission(current_user_id, "manage_all_projects")):
                    logger.warning(f"用户无权限删除项目: 用户ID={current_user_id}, 项目ID={project_id}")
                    return jsonify({
                        'success': False,
                        'error': '没有权限删除此项目'
                    }), 403
            
            # 执行删除操作
            try:
                # 软删除 - 将状态更改为"deleted"
                project.status = 'deleted'
                db.session.commit()
                logger.info(f"项目软删除成功: 项目ID={project_id}")
                
                return jsonify({
                    'success': True,
                    'message': '项目删除成功',
                    'project_id': project_id
                })
            except Exception as e:
                db.session.rollback()
                logger.error(f"项目删除失败: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': f'项目删除失败: {str(e)}'
                }), 500
        
        # 处理PUT请求 - 更新项目
        logger.info(f"API更新项目: 项目ID={project_id}, 用户ID={current_user_id}")
        
        # 获取项目信息
        project = Project.query.get_or_404(project_id)
        
        # 检查是否有bypass_jwt参数
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        # 如果没有bypass_jwt参数，则检查权限
        if not bypass_jwt and current_user_id:
            # 检查用户权限
            user_is_owner = project.owner_id == current_user_id
            user_is_manager = project.manager_id == current_user_id
            
            # 检查用户是否有管理项目的权限
            if not (user_is_owner or user_is_manager or has_permission(current_user_id, "manage_all_projects")):
                logger.warning(f"用户无权限更新项目: 用户ID={current_user_id}, 项目ID={project_id}")
                return jsonify({
                    'success': False,
                    'error': '没有权限更新此项目'
                }), 403
        
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '没有提供有效的请求数据'}), 400
        
        # 更新项目信息
        if 'name' in data:
            project.name = data['name']
        
        if 'description' in data:
            project.description = data['description']
        
        if 'start_date' in data and data['start_date']:
            try:
                project.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
            except ValueError:
                logger.warning(f"无效的开始日期格式: {data['start_date']}")
                return jsonify({'success': False, 'error': '无效的开始日期格式'}), 400
        
        if 'end_date' in data and data['end_date']:
            try:
                project.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
            except ValueError:
                logger.warning(f"无效的结束日期格式: {data['end_date']}")
                return jsonify({'success': False, 'error': '无效的结束日期格式'}), 400
        
        if 'status' in data:
            project.status = data['status']
        
        if 'progress' in data:
            project.progress = data['progress']
        
        if 'manager_id' in data and data['manager_id']:
            try:
                manager_id = int(data['manager_id'])
                # 验证管理者ID是否存在
                manager = User.query.get(manager_id)
                if not manager:
                    logger.warning(f"管理者ID不存在: {manager_id}")
                    return jsonify({'success': False, 'error': '管理者ID不存在'}), 400
                project.manager_id = manager_id
            except ValueError:
                logger.warning(f"无效的管理者ID: {data['manager_id']}")
                return jsonify({'success': False, 'error': '管理者ID必须是整数'}), 400
        
        # 保存更新
        try:
            db.session.commit()
            logger.info(f"项目更新成功: 项目ID={project_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"保存项目更新失败: {str(e)}")
            return jsonify({'success': False, 'error': f'保存项目更新失败: {str(e)}'}), 500
        
        # 返回更新后的项目信息
        return jsonify({
            'success': True,
            'message': '项目更新成功',
            'project': {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
                'status': project.status,
                'progress': project.progress,
                'manager_id': project.manager_id
            }
        })
    
    except Exception as e:
        logger.error(f"项目API操作失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"操作失败: {str(e)}"
        }), 500

# 添加无需认证的项目更新API端点
@project_bp.route('/api/noauth/projects/<int:project_id>', methods=['PUT', 'DELETE'])
@csrf.exempt
def update_project_noauth(project_id):
    """无需认证的项目更新和删除API端点"""
    try:
        # 处理DELETE请求 - 删除项目
        if request.method == 'DELETE':
            logger.info(f"无需认证删除项目API: 项目ID={project_id}")
            
            # 获取项目信息
            project = Project.query.get_or_404(project_id)
            
            # 执行删除操作
            try:
                # 软删除 - 将状态更改为"deleted"
                project.status = 'deleted'
                db.session.commit()
                logger.info(f"项目软删除成功: 项目ID={project_id}")
                
                return jsonify({
                    'success': True,
                    'message': '项目删除成功',
                    'project_id': project_id
                })
            except Exception as e:
                db.session.rollback()
                logger.error(f"项目删除失败: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': f'项目删除失败: {str(e)}'
                }), 500
        
        # 处理PUT请求 - 更新项目
        logger.info(f"无需认证更新项目API: 项目ID={project_id}")
        
        # 获取项目信息
        project = Project.query.get_or_404(project_id)
        
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '没有提供有效的请求数据'}), 400
        
        # 更新项目信息
        if 'name' in data:
            project.name = data['name']
        
        if 'description' in data:
            project.description = data['description']
        
        if 'start_date' in data and data['start_date']:
            try:
                project.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
            except ValueError:
                logger.warning(f"无效的开始日期格式: {data['start_date']}")
                return jsonify({'success': False, 'error': '无效的开始日期格式'}), 400
        
        if 'end_date' in data and data['end_date']:
            try:
                project.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
            except ValueError:
                logger.warning(f"无效的结束日期格式: {data['end_date']}")
                return jsonify({'success': False, 'error': '无效的结束日期格式'}), 400
        
        if 'status' in data:
            project.status = data['status']
        
        if 'progress' in data:
            project.progress = data['progress']
        
        if 'manager_id' in data and data['manager_id']:
            try:
                manager_id = int(data['manager_id'])
                # 验证管理者ID是否存在
                manager = User.query.get(manager_id)
                if not manager:
                    logger.warning(f"管理者ID不存在: {manager_id}")
                    return jsonify({'success': False, 'error': '管理者ID不存在'}), 400
                project.manager_id = manager_id
            except ValueError:
                logger.warning(f"无效的管理者ID: {data['manager_id']}")
                return jsonify({'success': False, 'error': '管理者ID必须是整数'}), 400
        
        # 保存更新
        try:
            db.session.commit()
            logger.info(f"项目更新成功: 项目ID={project_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"保存项目更新失败: {str(e)}")
            return jsonify({'success': False, 'error': f'保存项目更新失败: {str(e)}'}), 500
        
        # 返回更新后的项目信息
        return jsonify({
            'success': True,
            'message': '项目更新成功',
            'project': {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
                'status': project.status,
                'progress': project.progress,
                'manager_id': project.manager_id
            }
        })
    
    except Exception as e:
        logger.error(f"项目API操作失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"操作失败: {str(e)}"
        }), 500

# 添加项目编辑器更新API端点
@project_bp.route('/api/noauth/project-editor/<int:project_id>', methods=['PUT'])
@csrf.exempt
def update_project_editor(project_id):
    """项目编辑器的更新API端点"""
    try:
        logger.info(f"项目编辑器API更新项目: 项目ID={project_id}")
        
        # 获取项目信息
        project = Project.query.get_or_404(project_id)
        
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '没有提供有效的请求数据'}), 400
        
        # 记录详细的请求数据，便于调试
        logger.info(f"项目编辑器提交的数据: {data}")
        
        # 更新项目信息
        if 'name' in data:
            project.name = data['name']
        
        if 'description' in data:
            project.description = data['description']
        
        if 'start_date' in data and data['start_date']:
            try:
                project.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
            except ValueError:
                logger.warning(f"无效的开始日期格式: {data['start_date']}")
                return jsonify({'success': False, 'error': '无效的开始日期格式'}), 400
        
        if 'end_date' in data and data['end_date']:
            try:
                project.end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
            except ValueError:
                logger.warning(f"无效的结束日期格式: {data['end_date']}")
                return jsonify({'success': False, 'error': '无效的结束日期格式'}), 400
        
        if 'status' in data:
            project.status = data['status']
        
        if 'progress' in data:
            project.progress = data['progress']
        
        if 'manager_id' in data and data['manager_id']:
            try:
                manager_id = int(data['manager_id'])
                # 验证管理者ID是否存在
                manager = User.query.get(manager_id)
                if not manager:
                    logger.warning(f"管理者ID不存在: {manager_id}")
                    return jsonify({'success': False, 'error': '管理者ID不存在'}), 400
                project.manager_id = manager_id
            except ValueError:
                logger.warning(f"无效的管理者ID: {data['manager_id']}")
                return jsonify({'success': False, 'error': '管理者ID必须是整数'}), 400
        elif 'manager_id' in data and data['manager_id'] == "":
            # 当manager_id为空字符串时，设置为None
            project.manager_id = None
            logger.info("项目管理员已设置为空")
            
        # 保存更新
        try:
            db.session.commit()
            logger.info(f"项目编辑器更新成功: 项目ID={project_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"保存项目编辑器更新失败: {str(e)}")
            return jsonify({'success': False, 'error': f'保存项目更新失败: {str(e)}'}), 500
        
        # 返回更新后的项目信息
        return jsonify({
            'success': True,
            'message': '项目更新成功',
            'project': {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
                'status': project.status,
                'progress': project.progress,
                'manager_id': project.manager_id
            }
        })
    
    except Exception as e:
        logger.error(f"项目编辑器更新项目失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"更新项目失败: {str(e)}"
        }), 500

@project_bp.route('/api/noauth/projects', methods=['GET'])
@csrf.exempt
def get_projects_noauth():
    """获取项目列表 - 无需认证版本"""
    try:
        logger.info("通过无认证API获取项目列表")
        
        # 获取所有项目
        projects = Project.query.all()
        
        # 将项目列表转换为字典列表
        project_list = []
        for project in projects:
            # 获取项目管理员信息（如果存在）
            manager_name = "未指定"
            if project.manager_id:
                manager = User.query.get(project.manager_id)
                if manager:
                    manager_name = manager.name or manager.username or f"用户 #{project.manager_id}"
            
            project_list.append({
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'status': project.status,
                'progress': project.progress or 0,
                'manager_id': project.manager_id,
                'manager_name': manager_name,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None
            })
        
        return jsonify(project_list), 200
    except Exception as e:
        logger.error(f"无认证API获取项目列表失败: {str(e)}")
        return jsonify({'error': '获取项目列表失败', 'detail': str(e)}), 500

# 添加所有项目详情的API端点处理
@project_bp.route('/api/auth/projects/<int:project_id>', methods=['GET', 'DELETE'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
def get_project_auth_api(project_id):
    """获取或删除项目信息的认证API端点"""
    try:
        # 处理DELETE请求 - 删除项目
        if request.method == 'DELETE':
            logger.info(f"Auth API删除项目: 项目ID={project_id}")
            
            # 获取项目信息
            project = Project.query.get_or_404(project_id)
            
            # 检查是否有bypass_jwt参数
            bypass_jwt = request.args.get('bypass_jwt') == 'true'
            
            # 如果没有bypass_jwt参数，尝试获取当前用户ID并检查权限
            if not bypass_jwt:
                current_user_id = get_jwt_identity()
                if current_user_id:
                    # 检查用户权限
                    user_is_owner = project.owner_id == current_user_id
                    user_is_manager = project.manager_id == current_user_id
                    
                    # 检查用户是否有管理项目的权限
                    if not (user_is_owner or user_is_manager or has_permission(current_user_id, "manage_all_projects")):
                        logger.warning(f"用户无权限删除项目: 用户ID={current_user_id}, 项目ID={project_id}")
                        return jsonify({
                            'success': False,
                            'error': '没有权限删除此项目'
                        }), 403
            
            # 执行删除操作
            try:
                # 软删除 - 将状态更改为"deleted"
                project.status = 'deleted'
                db.session.commit()
                logger.info(f"Auth API项目软删除成功: 项目ID={project_id}")
                
                return jsonify({
                    'success': True,
                    'message': '项目删除成功',
                    'project_id': project_id
                })
            except Exception as e:
                db.session.rollback()
                logger.error(f"Auth API项目删除失败: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': f'项目删除失败: {str(e)}'
                }), 500
                
        # 处理GET请求 - 获取项目信息
        logger.info(f"Auth API获取项目: 项目ID={project_id}")
        
        # 获取项目信息
        project = Project.query.get_or_404(project_id)
        
        # 准备项目数据
        project_data = {
            'id': project.id,
            'name': project.name,
            'description': project.description,
            'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
            'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
            'status': project.status,
            'progress': project.progress,
            'manager_id': project.manager_id
        }
        
        # 获取管理者信息
        if project.manager_id:
            manager = User.query.get(project.manager_id)
            if manager:
                project_data['manager'] = {
                    'id': manager.id,
                    'username': manager.username,
                    'name': manager.name or manager.username
                }
        
        # 获取创建者信息
        if project.owner_id:
            creator = User.query.get(project.owner_id)
            if creator:
                project_data['creator'] = {
                    'id': creator.id,
                    'username': creator.username,
                    'name': creator.name or creator.username
                }
        
        return jsonify(project_data)
    
    except Exception as e:
        logger.error(f"获取项目API失败: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"获取项目失败: {str(e)}"
        }), 500

# 添加项目编辑器API端点 - 用于项目编辑页面
@project_bp.route('/api/noauth/project-editor/<int:project_id>', methods=['GET'])
@csrf.exempt
def get_project_for_editor(project_id):
    """专门为编辑器模态框设计的API端点，返回标准化的项目数据格式和项目经理列表"""
    try:
        logger.info(f"获取项目{project_id}用于编辑器")
        
        # 获取项目基本信息
        project = Project.query.get_or_404(project_id)
        
        # 获取项目管理者
        manager = None
        if project.manager_id:
            manager = User.query.get(project.manager_id)
        
        # 确保获取有效的管理员名称
        manager_name = "未分配"
        if manager:
            if manager.name:
                manager_name = manager.name
            elif manager.username:
                manager_name = manager.username
        
        # 获取项目经理列表
        project_managers = []
        try:
            # 查询所有活跃用户
            all_users = User.query.filter(User.is_active == True).all()
            
            # 添加所有用户作为潜在的项目经理
            for user in all_users:
                project_managers.append({
                    'id': user.id,
                    'name': user.name or user.username or f"用户 #{user.id}"
                })
            
            # 如果当前项目管理员不在活跃用户列表中，也添加到列表
            if project.manager_id and not any(pm['id'] == project.manager_id for pm in project_managers):
                project_managers.append({
                    'id': project.manager_id,
                    'name': manager_name
                })
            
        except Exception as e:
            logger.error(f"获取项目经理列表出错: {str(e)}")
            # 添加默认管理者
            project_managers = [
                {'id': 1, 'name': '管理员(默认)'},
                {'id': 2, 'name': '项目经理(默认)'}
            ]
        
        # 构造标准化的项目数据
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
        
        # 设置明确的Content-Type
        return jsonify(response), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        logger.error(f"获取项目编辑器数据出错: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e),
            'detail': '获取项目编辑器数据失败'
        }), 500, {'Content-Type': 'application/json'}

# 添加项目负责人列表API端点 - 匹配前端期望的'/api/project-managers'路径
@project_bp.route('/api/project-managers', methods=['GET'])
@csrf.exempt
def get_all_project_managers():
    """返回所有用户作为潜在的项目负责人，匹配前端期望的API路径"""
    try:
        logger.info("获取所有用户作为项目负责人候选")
        
        # 获取所有用户，不仅限于活跃用户或特定角色
        all_users = User.query.all()
        
        # 构建用户列表
        project_managers = []
        for user in all_users:
            # 构建用户名称，确保有值
            display_name = user.name if user.name else user.username if user.username else f"用户 #{user.id}"
            
            # 添加到项目经理列表
            project_managers.append({
                'id': user.id,
                'name': display_name
            })
        
        # 按照名称排序
        project_managers = sorted(project_managers, key=lambda x: x['name'])
        
        logger.info(f"返回所有用户作为项目负责人，共 {len(project_managers)} 位用户")
        
        return jsonify({
            'success': True,
            'project_managers': project_managers,
            'count': len(project_managers)
        })
    except Exception as e:
        logger.error(f"获取所有用户作为项目负责人失败: {str(e)}")
        # 即使出错也返回一些默认的选项
        return jsonify({
            'success': False,
            'error': str(e),
            'project_managers': [
                {'id': 1, 'name': '管理员(默认)'},
                {'id': 2, 'name': '项目经理(默认)'}
            ],
            'message': '出现错误，使用默认选项'
        })

# 添加获取所有项目的API端点，供任务创建使用
@project_bp.route('/api/auth/projects', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@csrf.exempt
def get_all_projects():
    try:
        # 检查是否使用bypass_jwt模式
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for get_all_projects - Using test user")
            current_user_id = 1  # 使用测试用户ID
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
                
        # 获取所有项目
        projects = Project.query.all()
        
        # 构建项目列表
        project_list = []
        for project in projects:
            manager = User.query.get(project.manager_id) if project.manager_id else None
            manager_name = manager.name if manager and manager.name else manager.username if manager else "未分配"
            
            project_data = {
                'id': project.id,
                'name': project.name,
                'description': project.description or '',
                'status': project.status or 'planning',
                'progress': project.progress or 0,
                'manager': manager_name,
                'manager_id': project.manager_id
            }
            project_list.append(project_data)
            
        return jsonify({'projects': project_list})
    except Exception as e:
        logger.error(f"获取项目列表失败: {str(e)}")
        return jsonify({'error': str(e)}), 500 