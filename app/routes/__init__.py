from flask import Blueprint
from .auth import auth_bp
from .projects import project_bp
from .tasks import task_bp
from .resources import resource_bp
from .risks import risk_bp
from .main import main_bp
from .kanban import kanban_bp
from .gantt import gantt_bp
from .comments import comments_bp
from .chat import chat_bp
from .team import team_bp
from .users import users_bp
from .notifications import notification_bp
from .audit import audit_bp
# 暂时注释掉全局用户蓝图导入，避免启动错误
# from .global_users import global_users_bp

# 导出蓝图
__all__ = [
    'auth_bp', 'project_bp', 'task_bp', 'resource_bp', 
    'risk_bp', 'main_bp', 'kanban_bp', 'gantt_bp', 
    'comments_bp', 'chat_bp', 'team_bp', 'users_bp',
    'notification_bp', 'audit_bp'
    # 注释掉全局用户蓝图，避免启动错误
    # ,'global_users_bp'
]

def register_routes(app):
    """Register all blueprints with the app."""
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.project import project_bp
    from app.routes.task import task_bp
    from app.routes.user import user_bp
    from app.routes.admin import admin_bp
    from app.routes.resources import resource_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.report import report_bp
    from app.routes.risk import risk_bp
    from app.routes.wiki import wiki_bp
    
    # 注册蓝图
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(project_bp, url_prefix='/projects')
    app.register_blueprint(task_bp, url_prefix='/tasks')
    app.register_blueprint(user_bp, url_prefix='/users')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(resource_bp, url_prefix='/resources')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(report_bp, url_prefix='/reports')
    app.register_blueprint(risk_bp, url_prefix='/risks')
    app.register_blueprint(wiki_bp, url_prefix='/wiki')
    
    return app 