from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from app import create_app
from app.extensions import db, socketio
from app.models.resource import ResourceUsage, SystemAlert
from app.models.auth import User, Role, Permission, role_permissions
from sqlalchemy.exc import SQLAlchemyError
import psutil
import time
import threading
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import traceback
from app.utils.system_utils import check_system_resources, cleanup_old_data
from app.utils.logging_utils import setup_logging
from app.utils.permissions import init_roles_permissions

# 设置日志
setup_logging()
logger = logging.getLogger(__name__)

def init_db(app):
    """初始化数据库"""
    with app.app_context():
        try:
            # 初始化角色和权限
            if init_roles_permissions():
                logger.info("角色和权限初始化成功")
            else:
                logger.error("角色和权限初始化失败")
                return
            
            # 创建系统用户
            system_user = User.query.filter_by(username='system').first()
            if not system_user:
                system_user = User(
                    username='system',
                    email='system@example.com',
                    name='System',
                    password_hash='$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYpwBAHHKQM.Vj.',  # 'password'
                    is_active=True
                )
                db.session.add(system_user)
                logger.info("创建系统用户")
            
            # 创建测试项目
            from app.models.project import Project
            test_project = Project.query.filter_by(name='Test Project').first()
            if not test_project:
                test_project = Project(
                    name='Test Project',
                    description='A test project',
                    owner_id=system_user.id,
                    status='active',
                    start_date=datetime.utcnow(),
                    end_date=datetime.utcnow() + timedelta(days=30)
                )
                db.session.add(test_project)
                logger.info("创建测试项目")
            
            db.session.commit()
            logger.info("数据库初始化完成")
            
        except SQLAlchemyError as e:
            logger.error(f"数据库初始化失败: {str(e)}")
            db.session.rollback()
            raise

def check_system_resources(app):
    """检查系统资源使用情况"""
    with app.app_context():
        try:
            # 获取系统用户
            system_user = User.query.filter_by(username='system').first()
            if not system_user:
                logger.error('系统用户不存在')
                return
            
            # 获取系统资源使用情况
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # 记录资源使用情况
            usage = ResourceUsage(
                user_id=system_user.id,
                cpu_usage=cpu_percent,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                network_usage=0.0,  # 暂时不记录网络使用情况
                recorded_at=datetime.utcnow()
            )
            db.session.add(usage)
            
            # 检查是否需要发送警报
            if cpu_percent > 80:
                alert = SystemAlert(
                    alert_type='resource',
                    severity='high',
                    message=f'CPU使用率过高: {cpu_percent}%',
                    is_resolved=False,
                    created_at=datetime.utcnow()
                )
                db.session.add(alert)
            
            if memory.percent > 80:
                alert = SystemAlert(
                    alert_type='resource',
                    severity='high',
                    message=f'内存使用率过高: {memory.percent}%',
                    is_resolved=False,
                    created_at=datetime.utcnow()
                )
                db.session.add(alert)
            
            if disk.percent > 80:
                alert = SystemAlert(
                    alert_type='resource',
                    severity='high',
                    message=f'磁盘使用率过高: {disk.percent}%',
                    is_resolved=False,
                    created_at=datetime.utcnow()
                )
                db.session.add(alert)
            
            db.session.commit()
            logger.info('系统资源检查完成')
            
        except Exception as e:
            logger.error(f'系统资源检查失败: {str(e)}')
            logger.error(traceback.format_exc())
            db.session.rollback()

def cleanup_old_data(app):
    """清理旧数据"""
    with app.app_context():
        try:
            logger.info('开始清理旧数据')
            
            # 添加异常捕获，确保日志文件操作不会中断清理过程
            try:
                # 删除30天前的资源使用记录
                old_date = datetime.utcnow() - timedelta(days=30)
                deleted_count = ResourceUsage.query.filter(ResourceUsage.recorded_at < old_date).delete()
                logger.info(f'删除了 {deleted_count} 条过期的资源使用记录')
            except Exception as e:
                logger.error(f'清理资源使用记录失败: {str(e)}')
                # 继续执行其他清理，不要提前退出
            
            try:
                # 删除7天前已解决的警报
                old_date = datetime.utcnow() - timedelta(days=7)
                deleted_count = SystemAlert.query.filter(
                    SystemAlert.is_resolved == True,
                    SystemAlert.created_at < old_date
                ).delete()
                logger.info(f'删除了 {deleted_count} 条已解决的过期警报')
            except Exception as e:
                logger.error(f'清理系统警报失败: {str(e)}')
                # 继续执行其他清理，不要提前退出
            
            # 提交事务
            try:
                db.session.commit()
                logger.info('旧数据清理完成')
            except Exception as e:
                logger.error(f'提交清理事务失败: {str(e)}')
                db.session.rollback()
            
        except Exception as e:
            logger.error(f'旧数据清理过程中出现未处理异常: {str(e)}')
            logger.error(traceback.format_exc())
            try:
                db.session.rollback()
            except Exception as rollback_e:
                logger.error(f'回滚事务失败: {str(rollback_e)}')

def main():
    """主函数"""
    try:
        # 创建应用
        app = create_app()
        
        # 初始化数据库
        init_db(app)
        
        # 启动系统资源监控
        check_system_resources(app)
        
        # 启动数据清理任务
        cleanup_old_data(app)
        
        # 启动应用
        app.run(host='0.0.0.0', port=5000, debug=True)
        
    except Exception as e:
        logger.error(f"应用启动失败: {str(e)}")
        logger.error("Traceback:", exc_info=True)
        raise

if __name__ == '__main__':
    main() 