import os
import logging
import sqlite3
from app import create_app
from app.extensions import db
from app.seed_data import create_test_data

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def reset_database():
    """重置数据库"""
    app = create_app()
    
    with app.app_context():
        # 获取数据库文件路径
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        
        # 关闭所有数据库连接
        db.session.close()
        db.engine.dispose()
        
        # 尝试删除数据库文件
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
                logger.info(f"Database file {db_path} removed successfully")
        except PermissionError as e:
            logger.error(f"Error removing database file: {e}")
            logger.error("Please make sure no other process is using the database file")
            return False
        
        # 重新创建数据库
        db.create_all()
        logger.info("Database recreated successfully")
        
        # 创建测试数据
        create_test_data(True)
        logger.info("Test data created successfully")
    
    return True

if __name__ == '__main__':
    reset_database() 