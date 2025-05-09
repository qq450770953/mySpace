import os
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import sys
import pytz

basedir = os.path.abspath(os.path.dirname(__file__))

# 日志配置
LOG_FOLDER = os.path.join(basedir, 'logs')
LOG_FILE = os.path.join(LOG_FOLDER, 'app.log')
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

# 确保日志目录存在
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

# 创建全局日志处理器
_log_handler = None

def get_log_handler():
    """获取日志处理器，使用单例模式避免重复记录"""
    global _log_handler
    if _log_handler is None:
        try:
            _log_handler = RotatingFileHandler(
                LOG_FILE,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding='utf-8',
                delay=True
            )
            _log_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        except Exception as e:
            print(f"Error creating log handler: {str(e)}")
            raise
    return _log_handler

class Config:
    """基础配置类"""
    # 基础配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # 自动检测断开的连接
        'pool_recycle': 3600,   # 一小时后回收连接
        'pool_timeout': 30,     # 连接超时时间
        'pool_size': 10,        # 连接池大小
        'max_overflow': 5       # 最大溢出连接数
    }
    
    # 时区配置
    TIMEZONE = pytz.timezone('Asia/Shanghai')
    
    # CORS配置
    CORS_ORIGINS = ['http://127.0.0.1:5000', 'http://localhost:5000']
    CORS_SUPPORTS_CREDENTIALS = True
    CORS_EXPOSE_HEADERS = ['Content-Type', 'Authorization', 'X-CSRF-TOKEN', 'Location']
    CORS_ALLOW_HEADERS = [
        'Content-Type',
        'Authorization',
        'X-CSRF-TOKEN',
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers'
    ]
    CORS_METHODS = ['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'PATCH', 'DELETE']
    CORS_MAX_AGE = 3600
    CORS_SEND_WILDCARD = False
    CORS_VARY_HEADER = True
    
    # JWT配置
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'dev-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_ERROR_MESSAGE_KEY = 'error'
    JWT_TOKEN_LOCATION = ['headers', 'cookies']
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_COOKIE_SAMESITE = 'Lax'
    JWT_COOKIE_NAME = 'access_token_cookie'
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'
    JWT_ALGORITHM = 'HS256'
    JWT_DECODE_ALGORITHMS = ['HS256']
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    JWT_IDENTITY_CLAIM = 'sub'
    JWT_USER_CLAIMS = 'user_claims'
    JWT_CLAIMS_IN_ACCESS_TOKEN = True
    JWT_CLAIMS_IN_REFRESH_TOKEN = True
    JWT_ACCESS_CSRF_HEADER_NAME = 'X-CSRF-TOKEN'
    JWT_REFRESH_CSRF_HEADER_NAME = 'X-CSRF-TOKEN'
    JWT_CSRF_CHECK_FORM = False
    JWT_AUDIENCE = 'task_management_system'
    JWT_QUERY_STRING_VALUE_PREFIX = 'Bearer '
    
    # 安全配置
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # 文件上传配置
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
    
    # 邮件配置
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.example.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') or True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'noreply@example.com'
    
    # 日志配置
    LOG_FOLDER = os.path.join(basedir, 'logs')
    LOG_FILE = os.path.join(LOG_FOLDER, 'app.log')
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    @staticmethod
    def init_app(app):
        """初始化应用配置"""
        try:
            # 确保上传目录存在
            if not os.path.exists(Config.UPLOAD_FOLDER):
                os.makedirs(Config.UPLOAD_FOLDER)
                app.logger.info(f"Created upload directory: {Config.UPLOAD_FOLDER}")
            
            # 确保日志目录存在
            if not os.path.exists(Config.LOG_FOLDER):
                os.makedirs(Config.LOG_FOLDER)
                app.logger.info(f"Created log directory: {Config.LOG_FOLDER}")
            
            # 配置日志
            formatter = logging.Formatter(Config.LOG_FORMAT)
            
            # 文件日志处理器
            try:
                file_handler = get_log_handler()
                file_handler.setFormatter(formatter)
                file_handler.setLevel(Config.LOG_LEVEL)
                app.logger.addHandler(file_handler)
                app.logger.info("File logging handler initialized successfully")
            except Exception as e:
                app.logger.error(f"Failed to initialize file logging handler: {str(e)}")
                
            # 控制台日志处理器
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            console_handler.setLevel(Config.LOG_LEVEL)
            app.logger.addHandler(console_handler)
            app.logger.info("Console logging handler initialized successfully")
            
            # 设置应用日志级别
            app.logger.setLevel(Config.LOG_LEVEL)
            
            # 设置 SQLAlchemy 的日志级别
            logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
            
            # 设置 Werkzeug 的日志级别
            logging.getLogger('werkzeug').setLevel(logging.WARNING)
            
            app.logger.info("Application logging configuration completed")
            
        except Exception as e:
            print(f"Critical error during application initialization: {str(e)}")
            raise

class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'dev.db')
    JWT_COOKIE_SECURE = False
    SESSION_COOKIE_SECURE = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        app.logger.info("Development configuration initialized")

class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'test.db')
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        app.logger.info("Testing configuration initialized")

class ProductionConfig(Config):
    """生产环境配置"""
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'prod.db')
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # 生产环境日志配置
        try:
            # 邮件日志处理器
            if all([cls.MAIL_SERVER, cls.MAIL_PORT, cls.MAIL_USERNAME, cls.MAIL_PASSWORD]):
                credentials = (cls.MAIL_USERNAME, cls.MAIL_PASSWORD)
                secure = () if cls.MAIL_USE_TLS else None
                
                mail_handler = SMTPHandler(
                    mailhost=(cls.MAIL_SERVER, cls.MAIL_PORT),
                    fromaddr=cls.MAIL_DEFAULT_SENDER,
                    toaddrs=[cls.MAIL_DEFAULT_SENDER],
                    subject='Application Error',
                    credentials=credentials,
                    secure=secure
                )
                mail_handler.setLevel(logging.ERROR)
                mail_handler.setFormatter(logging.Formatter(Config.LOG_FORMAT))
                app.logger.addHandler(mail_handler)
                app.logger.info("Email logging handler initialized successfully")
            else:
                app.logger.warning("Email logging handler not configured due to missing credentials")
        except Exception as e:
            app.logger.error(f"Failed to initialize email logging handler: {str(e)}")
        
        app.logger.info("Production configuration initialized")

# 配置字典
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
} 