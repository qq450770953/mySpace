import psutil
import logging
from datetime import datetime, timedelta
from app.models.resource import ResourceUsage, SystemAlert
from app.models.auth import User
from app.extensions import db

logger = logging.getLogger(__name__)

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
            logger.error("Traceback:", exc_info=True)
            db.session.rollback()

def cleanup_old_data(app):
    """清理旧数据"""
    with app.app_context():
        try:
            # 删除30天前的资源使用记录
            old_date = datetime.utcnow() - timedelta(days=30)
            ResourceUsage.query.filter(ResourceUsage.recorded_at < old_date).delete()
            
            # 删除7天前已解决的警报
            old_date = datetime.utcnow() - timedelta(days=7)
            SystemAlert.query.filter(
                SystemAlert.is_resolved == True,
                SystemAlert.created_at < old_date
            ).delete()
            
            db.session.commit()
            logger.info('旧数据清理完成')
            
        except Exception as e:
            logger.error(f'旧数据清理失败: {str(e)}')
            logger.error("Traceback:", exc_info=True)
            db.session.rollback() 