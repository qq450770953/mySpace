from flask import Flask, redirect, url_for, request, send_from_directory, jsonify, render_template, current_app
from app.config import Config, config
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import os
from app.extensions import init_extensions, socketio, db, migrate, mail, jwt, login_manager, bcrypt, api, csrf
from app.commands import register_commands
import win32file
import win32con
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from flask_cors import CORS
import sys
import atexit
import signal
import pytz
from datetime import datetime, timedelta
from .config import DevelopmentConfig, TestingConfig, ProductionConfig, get_log_handler
from flask_wtf.csrf import CSRFProtect
from flask import Blueprint
import uuid

# 在文件顶部确保导出csrf对象
csrf = CSRFProtect()

def create_app(config_name=None):
    """Create Flask application."""
    app = Flask(__name__)
    
    # 加载配置
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    # 设置调试标志
    app.config['FLASK_DEBUG'] = app.config.get('DEBUG', False)
    
    # JWT安全配置
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # 令牌1小时后过期
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)  # 刷新令牌30天后过期
    app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies', 'query_string', 'json']
    app.config['JWT_COOKIE_SECURE'] = False  # 开发环境设为False，生产环境应设为True
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    
    # 设置CSRF保护
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY', 'dev-csrf-secret-key')
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF令牌有效期（秒）
    app.config['WTF_CSRF_SSL_STRICT'] = False  # 开发环境可以设置为False
    app.config['WTF_CSRF_CHECK_DEFAULT'] = True  # 启用默认的CSRF检查
    app.config['WTF_CSRF_METHODS'] = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    # 从CSRF保护中排除静态文件和特定路由
    csrf.init_app(app)
    
    # 排除静态文件路由和特定API路由
    csrf.exempt(app.send_static_file)
    
    # 直接从CSRF保护中排除用户相关API
    user_api_bp = Blueprint('user_api_exempt', __name__)
    
    @user_api_bp.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @user_api_bp.route('/api/users/<int:user_id>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    def user_api_exempt_route(user_id=None):
        # 此函数不会被调用，仅用于创建路由模式匹配
        pass
    
    app.register_blueprint(user_api_bp)
    csrf.exempt(user_api_bp)
    
    # 创建任务API的CSRF豁免蓝图
    task_api_exempt_bp = Blueprint('task_api_exempt', __name__)
    
    @task_api_exempt_bp.route('/api/tasks/<int:task_id>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @task_api_exempt_bp.route('/api/tasks', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @task_api_exempt_bp.route('/api/tasks/<int:task_id>/no_csrf', methods=['GET', 'POST', 'PUT', 'DELETE'])
    @task_api_exempt_bp.route('/tasks/project/<int:project_id>/gantt/data', methods=['GET'])
    @task_api_exempt_bp.route('/tasks/project/<int:project_id>/gantt', methods=['GET'])
    @task_api_exempt_bp.route('/tasks/<int:task_id>/gantt', methods=['PUT'])
    @task_api_exempt_bp.route('/tasks/dependencies/gantt', methods=['POST'])
    @task_api_exempt_bp.route('/tasks/<int:task_id>/dependencies/<int:dependency_id>/gantt', methods=['DELETE'])
    def task_api_exempt_route(task_id=None, project_id=None, dependency_id=None):
        """
        CSRF豁免的任务API路由，将请求转发到任务的实际处理函数
        """
        # 导入任务蓝图中的路由处理函数
        from app.routes.tasks import get_task, update_task, delete_task, create_task, get_tasks, update_task_no_csrf
        from flask import jsonify, current_app as app
        
        # 检查是否请求了绕过JWT验证
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        if bypass_jwt:
            # 当bypass_jwt为true时，直接设置CSRF令牌为已验证状态，完全绕过CSRF检查
            app.logger.warning(f"绕过JWT验证和CSRF保护: {request.path}")
            request._csrf_token = True
        
        try:
            # 处理甘特图相关请求
            if '/project/' in request.path and '/gantt/data' in request.path:
                from app.routes.tasks import get_gantt_data
                return get_gantt_data(project_id)
            elif '/project/' in request.path and '/gantt' in request.path:
                from app.routes.tasks import gantt_chart
                return gantt_chart(project_id)
            elif '/dependencies/gantt' in request.path:
                from app.routes.tasks import create_gantt_dependency
                return create_gantt_dependency()
            elif '/dependencies/' in request.path and '/gantt' in request.path:
                from app.routes.tasks import delete_gantt_dependency
                return delete_gantt_dependency(task_id, dependency_id)
            elif task_id and '/gantt' in request.path and request.method == 'PUT':
                from app.routes.tasks import update_gantt_task
                return update_gantt_task(task_id)
            
            # 处理标准任务API请求
            if request.method == 'GET':
                if task_id:
                    return get_task(task_id)
                else:
                    return get_tasks()
            elif request.method == 'POST':
                if task_id:
                    # 通常POST不带ID，但如果有，仍处理
                    return create_task()
                else:
                    return create_task()
            elif request.method == 'PUT':
                if task_id:
                    # 检查是否是no_csrf路径
                    if 'no_csrf' in request.path:
                        return update_task_no_csrf(task_id)
                    else:
                        return update_task(task_id)
                else:
                    return jsonify({'error': 'Task ID is required for update'}), 400
            elif request.method == 'DELETE':
                if task_id:
                    return delete_task(task_id)
                else:
                    return jsonify({'error': 'Task ID is required for deletion'}), 400
            else:
                return jsonify({'error': 'Method not allowed'}), 405
        except Exception as e:
            app.logger.error(f"Error in task_api_exempt_route: {str(e)}")
            return jsonify({'error': 'Internal server error', 'details': str(e)}), 500
    
    # 注册蓝图并豁免CSRF检查
    app.register_blueprint(task_api_exempt_bp)
    csrf.exempt(task_api_exempt_bp)  # 豁免CSRF检查
    
    # 添加一个自定义的路由过滤器，以便在bypass_jwt=true时免除CSRF检查
    @app.before_request
    def bypass_csrf_with_jwt_bypass():
        """
        当URL参数中包含bypass_jwt=true时，绕过CSRF保护
        仅用于测试环境
        """
        if request.args.get('bypass_jwt') == 'true' and (
            request.path.startswith('/api/users') or
            request.path.startswith('/auth/users') or
            request.path.startswith('/api/auth/users')
        ):
            app.logger.warning(f"绕过JWT验证和CSRF保护: {request.path}")
            
            # 从URL或请求头中获取CSRF令牌
            csrf_token = request.args.get('csrf_token') or \
                        request.headers.get('X-CSRFToken') or \
                        request.headers.get('X-CSRF-TOKEN')
            
            # 设置请求的_csrf_token属性为True，完全绕过CSRF验证
            request._csrf_token = True
            
            # 记录详细的CSRF信息
            app.logger.info(f"CSRF令牌: {csrf_token}")
            app.logger.info(f"请求方法: {request.method}")
            app.logger.info(f"请求路径: {request.path}")
    
    # 初始化扩展
    db.init_app(app)
    migrate.init_app(app, db)
    
    # 初始化Flask-Login
    login_manager.session_protection = 'strong'
    login_manager.login_view = 'auth.login_page'
    login_manager.login_message = '请先登录以访问此页面'
    login_manager.login_message_category = 'warning'
    login_manager.init_app(app)
    
    jwt.init_app(app)
    bcrypt.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    
    # 从app.utils.jwt_callbacks导入JWT回调函数
    from app.utils.jwt_callbacks import setup_jwt_callbacks
    setup_jwt_callbacks(jwt)
    
    # 添加请求拦截器，在处理请求前调整CSRF验证行为
    @app.before_request
    def handle_csrf_for_user_apis():
        """处理用户API的CSRF验证"""
        try:
            if request and request.args.get('bypass_jwt') == 'true':
                # 检查是否访问用户API或任务API
                task_api_path = (request.path.startswith('/api/tasks/') or 
                               request.path == '/api/tasks')
                user_api_path = (request.path.startswith('/api/users') or 
                               request.path.startswith('/auth/users'))
                
                if task_api_path or user_api_path:
                    app.logger.warning(f"设置请求CSRF验证令牌: {request.path}")
                    
                    # 直接设置_csrf_token属性绕过验证
                    app.logger.info("设置请求的_csrf_token属性")
                    request._csrf_token = True
                    
                    # 记录请求详情以便调试
                    app.logger.info(f"请求方法: {request.method}")
                    app.logger.info(f"请求路径: {request.path}")
                    app.logger.info(f"请求头: {dict(request.headers)}")
                    if request.is_json:
                        try:
                            app.logger.info(f"请求数据: {request.get_json()}")
                        except:
                            app.logger.info("请求中没有有效的JSON数据")
        except Exception as e:
            app.logger.error(f"处理CSRF时出错: {str(e)}")
    
    # 启用CORS，确保正确处理CSRF
    CORS(app, supports_credentials=True, resources={
        r"/*": {
            "origins": "*",
            "allow_headers": ["Content-Type", "X-CSRF-TOKEN", "Authorization"],
            "expose_headers": ["Content-Type", "X-CSRF-TOKEN"],
            "supports_credentials": True
        }
    })
    
    # 设置日志
    setup_logging(app)
    
    # 注册蓝图
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)
    
    from app.routes.main import main_bp
    app.register_blueprint(main_bp, url_prefix='/main')
    
    from app.routes.projects import project_bp
    app.register_blueprint(project_bp, url_prefix='/projects')
    
    # 添加额外的URL前缀映射，确保API调用能正确路由，但使用不同的名称
    app.register_blueprint(project_bp, name='project_root')  # 注册到根路径，但使用唯一名称
    
    from app.routes.tasks import task_bp
    app.register_blueprint(task_bp, url_prefix='/tasks')
    
    # 注册调试API路由
    from app.routes.projects import debug_bp
    app.register_blueprint(debug_bp)  # 直接注册调试蓝图
    
    # 记录注册的路由，便于调试
    app.logger.info("已注册的路由:")
    for rule in app.url_map.iter_rules():
        app.logger.info(f"路由: {rule.rule} - 方法: {rule.methods} - 终端: {rule.endpoint}")
    
    # 注册API蓝图，使用唯一名称
    app.register_blueprint(project_bp, url_prefix='/api/auth/projects', name='projects_auth_api')
    app.register_blueprint(project_bp, url_prefix='/api/projects', name='projects_api')
    
    # 注册任务蓝图，只使用必要的前缀，避免重复和冲突 
    # 删除以下几行产生冲突的注册
    # app.register_blueprint(task_bp, url_prefix='/api/auth/tasks', name='tasks_auth_api')
    # app.register_blueprint(task_bp, url_prefix='/tasks', name='tasks_alt')  # 添加一个唯一的名称
    
    # 重新注册任务蓝图，确保唯一的URL前缀
    app.register_blueprint(task_bp, url_prefix='/api', name='tasks_api')  # 确保/api/tasks/* 端点正常工作
    
    # 确保这些蓝图已定义
    try:
        from app.routes.resources import resource_bp
        app.register_blueprint(resource_bp, url_prefix='/resources')
        
        # 使用不同的名称注册相同的蓝图，确保endpoint函数名不冲突
        resource_api_bp = resource_bp
        app.register_blueprint(resource_api_bp, url_prefix='/api/resources', name='resources_api')
    except (ImportError, NameError) as e:
        app.logger.warning(f"resource_bp 未定义或无法导入: {str(e)}")
    
    try:
        from app.routes.risk import risk_bp
        app.register_blueprint(risk_bp, url_prefix='/risks')
        app.register_blueprint(risk_bp, url_prefix='/api/risks', name='risk_api')
    except (ImportError, NameError) as e:
        app.logger.warning(f"risk_bp 未定义或无法导入: {str(e)}")
    
    try:
        from app.routes.kanban import kanban_bp
        app.register_blueprint(kanban_bp, url_prefix='/api/auth/kanban')
    except (ImportError, NameError):
        app.logger.warning("kanban_bp 未定义或无法导入")
    
    try:
        from app.routes.gantt import gantt_bp
        app.register_blueprint(gantt_bp, url_prefix='/api/auth/gantt')
    except (ImportError, NameError):
        app.logger.warning("gantt_bp 未定义或无法导入")
    
    try:
        from app.routes.users import users_bp
        app.register_blueprint(users_bp, url_prefix='/api/auth/users')
    except (ImportError, NameError):
        app.logger.warning("users_bp 未定义或无法导入")
    
    try:
        from app.routes.teams import team_bp
        app.register_blueprint(team_bp, url_prefix='/api/auth/teams')
    except (ImportError, NameError):
        app.logger.warning("team_bp 未定义或无法导入")
    
    try:
        from app.routes.reports import reports_bp
        app.register_blueprint(reports_bp)
    except (ImportError, NameError):
        app.logger.warning("reports_bp 未定义或无法导入")
    
    try:
        from app.routes.comments import comments_bp
        app.register_blueprint(comments_bp, url_prefix='/api/auth/comments')
    except (ImportError, NameError):
        app.logger.warning("comments_bp 未定义或无法导入")
    
    try:
        from app.routes.notifications import notification_bp
        app.register_blueprint(notification_bp, url_prefix='/api/auth/notifications')
    except (ImportError, NameError):
        app.logger.warning("notification_bp 未定义或无法导入")
    
    try:
        from app.routes.chat import chat_bp
        app.register_blueprint(chat_bp, url_prefix='/api/auth/chat')
    except (ImportError, NameError):
        app.logger.warning("chat_bp 未定义或无法导入")
    
    try:
        from app.routes.audit import audit_bp
        app.register_blueprint(audit_bp, url_prefix='/api/auth/audit')
    except (ImportError, NameError):
        app.logger.warning("audit_bp 未定义或无法导入")
    
    # 添加全局钩子，在请求处理前检查用户认证状态
    @app.before_request
    def check_auth_and_redirect():
        """在请求处理前检查用户是否已认证，未认证时重定向到登录页面"""
        # 白名单路径，这些路径不需要认证即可访问
        exempt_paths = [
            '/static/',
            '/login',
            '/register',
            '/auth/login',
            '/auth/register',
            '/auth/logout',
            '/auth/refresh',
            '/auth/csrf-token',
            '/auth/reset-password',
            '/auth/verify-email/confirm'
        ]
        
        # 检查是否为免认证路径
        for path in exempt_paths:
            if request.path.startswith(path):
                return None
            
        # 调试功能，仅用于开发环境    
        if request.args.get('bypass_jwt') == 'true' and app.config.get('FLASK_DEBUG', False):
            app.logger.warning(f'绕过JWT验证: {request.path}')
            return None
            
        # 尝试验证JWT
        try:
            verify_jwt_in_request(optional=True)
            current_user = get_jwt_identity()
            
            # 如果未认证且不是API路径或静态资源，重定向到登录页面
            if not current_user and not (request.path.startswith('/api/') or request.path.startswith('/static/')):
                app.logger.info(f'用户未认证，重定向到登录页面: {request.path}')
                return redirect(url_for('auth.login_page'))
                
            # 如果是API请求且未认证，返回401错误
            if not current_user and request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'message': '请先登录'}), 401
                
        except Exception as e:
            app.logger.error(f'验证JWT时出错: {str(e)}')
            # 如果验证过程出错，重定向到登录页面
            if not (request.path.startswith('/api/') or request.path.startswith('/static/')):
                return redirect(url_for('auth.login_page'))
            else:
                return jsonify({'error': 'Unauthorized', 'message': '认证失败'}), 401
            
        return None
    
    # 注册错误处理
    @app.errorhandler(400)
    def bad_request_error(error):
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Bad request'}), 400
        return render_template('error.html', error='错误请求'), 400
        
    @app.errorhandler(401)
    def unauthorized_error(error):
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Unauthorized', 'message': '请先登录'}), 401
        return redirect(url_for('auth.login_page'))
        
    @app.errorhandler(403)
    def forbidden_error(error):
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Forbidden', 'message': '权限不足'}), 403
        return render_template('error.html', error='没有权限访问此资源'), 403
        
    @app.errorhandler(404)
    def not_found_error(error):
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Not found'}), 404
        return render_template('error.html', error='资源未找到'), 404
        
    @app.errorhandler(500)
    def internal_error(error):
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('error.html', error='服务器内部错误'), 500
    
    # 注册一个通用的前端URL路由处理，将所有找不到的路径重定向到登录页面或仪表板
    @app.route('/<path:path>')
    def catch_all(path):
        """捕获所有未匹配的URL请求"""
        # 跳过API路径，确保API返回404而不是重定向
        if path.startswith('api/') or path.startswith('static/'):
            return not_found_error(None)
        
        # 尝试验证JWT
        try:
            verify_jwt_in_request(optional=True)
            current_user = get_jwt_identity()
            
            # 如果已认证，重定向到仪表板
            if current_user:
                app.logger.info(f'用户已认证，重定向到仪表板页面: /{path}')
                return redirect(url_for('main.dashboard'))
        except Exception:
            pass
            
        # 未认证或验证失败，重定向到登录页面
        app.logger.info(f'未匹配的路径 /{path}，重定向到登录页面')
        return redirect(url_for('auth.login_page'))
    
    # 重新注册根路由，确保处理优先级最高
    @app.route('/', methods=['GET', 'HEAD', 'OPTIONS', 'POST'])
    def index():
        """根路由，检查认证状态后决定重定向目标"""
        try:
            # 尝试验证JWT
            verify_jwt_in_request(optional=True)
            current_user = get_jwt_identity()
            
            # 如果已认证，重定向到仪表板
            if current_user:
                app.logger.info('用户已认证，重定向到仪表板页面')
                return redirect(url_for('main.dashboard'))
                
            # 未认证，重定向到登录页面
            app.logger.info('用户未认证，重定向到登录页面')
            return redirect(url_for('auth.login_page'))
        except Exception as e:
            app.logger.error(f'Index route error: {str(e)}')
            # 如果出错，重定向到登录页面
            return redirect(url_for('auth.login_page'))
    
    # 初始化应用 - 使用现代替代方法
    _is_first_request_done = False
    
    @app.before_request
    def initialize_app_on_first_request():
        """应用首次请求前的初始化"""
        nonlocal _is_first_request_done
        if _is_first_request_done:
            return None
            
        _is_first_request_done = True
        
        try:
            # 初始化角色和权限
            from app.utils.permissions import init_roles_permissions
            if init_roles_permissions():
                current_app.logger.info("角色和权限初始化成功")
            else:
                current_app.logger.error("角色和权限初始化失败")
        except Exception as e:
            current_app.logger.error(f"应用初始化失败: {str(e)}")
        
        current_app.logger.info("应用初始化完成")
        
        return None
    
    # 注册清理函数
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.session.remove()
    
    # 注册信号处理
    def signal_handler(signum, frame):
        cleanup_logging(app)
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    def cleanup_handler():
        cleanup_logging(app)
        
    atexit.register(cleanup_handler)
    
    @app.after_request
    def add_csrf_headers(response):
        """为API响应添加CSRF头部"""
        try:
            # 为API响应添加CSRF令牌头
            if request.path.startswith('/api/'):
                # 获取或生成CSRF令牌
                csrf_token = getattr(request, '_csrf_token', None)
                if not csrf_token:
                    try:
                        from flask_wtf.csrf import generate_csrf
                        csrf_token = generate_csrf()
                    except Exception as e:
                        app.logger.error(f"生成CSRF令牌失败: {str(e)}")
                        csrf_token = str(uuid.uuid4())
                
                # 添加到响应头
                response.headers['X-CSRF-TOKEN'] = csrf_token
                
                # 对于API响应，特别是OPTIONS请求，添加跨域头
                if request.method == 'OPTIONS':
                    response.headers['Access-Control-Allow-Origin'] = '*'
                    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
                    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-CSRF-TOKEN, Authorization'
        except Exception as e:
            app.logger.error(f"添加CSRF头部时出错: {str(e)}")
        
        return response
    
    # 添加权限检查函数到Jinja2模板中
    from app.utils.permissions import user_can_edit, user_is_regular
    app.jinja_env.globals.update(
        user_can_edit=user_can_edit,
        user_is_regular=user_is_regular
    )
    
    return app

def setup_logging(app):
    """Configure logging for the application."""
    try:
        # 确保日志目录存在
        log_dir = os.path.join(app.root_path, 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        # 设置日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 创建日志处理器
        log_file = os.path.join(log_dir, 'app.log')
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8',
            delay=True  # 延迟打开文件，直到第一次写入
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        
        # 添加错误处理器
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, 'error.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8',
            delay=True
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        
        # 添加控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # 配置应用日志
        app.logger.addHandler(file_handler)
        app.logger.addHandler(error_handler)
        app.logger.addHandler(console_handler)
        app.logger.setLevel(logging.INFO)
        
        # 配置 Werkzeug 日志
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)
        werkzeug_logger.setLevel(logging.INFO)
        
        # 配置 SQLAlchemy 日志
        sqlalchemy_logger = logging.getLogger('sqlalchemy.engine')
        sqlalchemy_logger.addHandler(file_handler)
        sqlalchemy_logger.setLevel(logging.INFO)
        
        # 存储处理器引用以便清理
        app.log_handlers = {
            'file': file_handler,
            'error': error_handler,
            'console': console_handler
        }
        
        app.logger.info('Logging setup completed successfully')
        
    except Exception as e:
        print(f"Error setting up logging: {str(e)}")
        raise

def cleanup_logging(app):
    """Clean up logging handlers."""
    try:
        if hasattr(app, 'log_handlers'):
            for handler in app.log_handlers.values():
                try:
                    handler.close()
                except Exception as e:
                    print(f"Error closing handler: {str(e)}")
        else:
            print("No log handlers to clean up")
    except Exception as e:
        print(f"Error in cleanup_logging: {str(e)}") 