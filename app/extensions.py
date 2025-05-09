from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO
from flask_mail import Mail
from flask_migrate import Migrate
from flask_cors import CORS
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_restful import Api
from flask_wtf.csrf import CSRFProtect
import logging

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
socketio = SocketIO()
mail = Mail()
migrate = Migrate()
cors = CORS()
login_manager = LoginManager()
bcrypt = Bcrypt()
api = Api()
csrf = CSRFProtect()

logger = logging.getLogger(__name__)

def init_extensions(app):
    """Initialize Flask extensions"""
    try:
        # Initialize database
        logger.info("Initializing SQLAlchemy")
        try:
            db.init_app(app)
            logger.info("SQLAlchemy initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SQLAlchemy: {str(e)}")
            raise
        
        # Initialize JWT with custom configuration
        logger.info("Initializing JWT")
        try:
            jwt.init_app(app)
            logger.info("JWT initialized successfully")
            
            # Setup JWT callbacks
            from app.utils.jwt_callbacks import setup_jwt_callbacks
            setup_jwt_callbacks(jwt)
            logger.info("JWT callbacks setup completed")
        except Exception as e:
            logger.error(f"Failed to initialize JWT: {str(e)}")
            raise
        
        # Initialize Socket.IO
        logger.info("Initializing Socket.IO")
        try:
            socketio.init_app(app, cors_allowed_origins="*")
            logger.info("Socket.IO initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Socket.IO: {str(e)}")
            raise
        
        # Initialize Mail
        logger.info("Initializing Mail")
        try:
            mail.init_app(app)
            logger.info("Mail initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Mail: {str(e)}")
            raise
        
        # Initialize Migrate
        logger.info("Initializing Migrate")
        try:
            migrate.init_app(app, db)
            logger.info("Migrate initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Migrate: {str(e)}")
            raise
        
        # Initialize CORS
        logger.info("Initializing CORS")
        try:
            cors.init_app(app)
            logger.info("CORS initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize CORS: {str(e)}")
            raise
        
        # Initialize Login Manager
        logger.info("Initializing Login Manager")
        try:
            login_manager.init_app(app)
            login_manager.login_view = 'auth.login'
            login_manager.login_message = '请先登录'
            login_manager.login_message_category = 'info'
            logger.info("Login Manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Login Manager: {str(e)}")
            raise
        
        # Initialize Bcrypt
        logger.info("Initializing Bcrypt")
        try:
            bcrypt.init_app(app)
            logger.info("Bcrypt initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Bcrypt: {str(e)}")
            raise
        
        # Initialize API
        logger.info("Initializing API")
        try:
            api.init_app(app)
            logger.info("API initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize API: {str(e)}")
            raise
        
        # Setup user loader
        logger.info("Setting up user loader")
        try:
            from app.models.auth import User
            
            @login_manager.user_loader
            def load_user(user_id):
                """Load user by ID."""
                try:
                    user = User.query.get(int(user_id))
                    if user is None:
                        logger.warning(f"No user found with ID: {user_id}")
                    return user
                except Exception as e:
                    logger.error(f"Error loading user {user_id}: {str(e)}")
                    return None
            
            logger.info("User loader setup completed")
        except Exception as e:
            logger.error(f"Failed to setup user loader: {str(e)}")
            raise
        
        # Create database tables
        logger.info("Creating database tables")
        try:
            with app.app_context():
                db.create_all()
                logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {str(e)}")
            raise
        
        logger.info("All extensions initialized successfully")
        
    except Exception as e:
        logger.error(f"Critical error during extension initialization: {str(e)}")
        raise 