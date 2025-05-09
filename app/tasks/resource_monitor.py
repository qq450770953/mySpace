from datetime import datetime, timedelta
from app import db, scheduler
from app.models import Resource, ResourceUtilization, ResourceAllocation
import logging

logger = logging.getLogger(__name__)

@scheduler.task('cron', id='record_resource_utilization', hour='*/1')
def record_resource_utilization():
    """每小时记录一次资源利用率"""
    try:
        # 获取所有资源
        resources = Resource.query.all()
        current_date = datetime.now().date()
        
        for resource in resources:
            # 获取当天的分配记录
            allocations = ResourceAllocation.query.filter(
                ResourceAllocation.resource_id == resource.id,
                ResourceAllocation.status == 'approved',
                ResourceAllocation.start_date <= current_date,
                ResourceAllocation.end_date >= current_date
            ).all()
            
            # 计算已分配数量
            allocated_quantity = sum(allocation.quantity for allocation in allocations)
            
            # 获取或创建当天的利用率记录
            utilization = ResourceUtilization.query.filter_by(
                resource_id=resource.id,
                date=current_date
            ).first()
            
            if not utilization:
                utilization = ResourceUtilization(
                    resource_id=resource.id,
                    date=current_date,
                    allocated_quantity=allocated_quantity
                )
                db.session.add(utilization)
            else:
                utilization.allocated_quantity = allocated_quantity
            
            # 计算利用率
            if resource.total_quantity > 0:
                utilization.utilization_rate = (allocated_quantity / resource.total_quantity) * 100
            else:
                utilization.utilization_rate = 0
            
            # 添加备注
            utilization.notes = f"自动记录于 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        db.session.commit()
        logger.info("资源利用率记录完成")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"记录资源利用率时发生错误: {str(e)}")

@scheduler.task('cron', id='cleanup_old_records', day_of_week='0', hour='0')
def cleanup_old_records():
    """每周清理一次旧记录"""
    try:
        # 保留最近90天的记录
        cutoff_date = datetime.now().date() - timedelta(days=90)
        
        # 删除旧的利用率记录
        ResourceUtilization.query.filter(
            ResourceUtilization.date < cutoff_date
        ).delete()
        
        # 删除旧的预测记录
        ResourcePrediction.query.filter(
            ResourcePrediction.date < cutoff_date
        ).delete()
        
        db.session.commit()
        logger.info("旧记录清理完成")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"清理旧记录时发生错误: {str(e)}")

@scheduler.task('cron', id='generate_resource_alerts', hour='*/4')
def generate_resource_alerts():
    """每4小时检查一次资源使用情况并生成预警"""
    try:
        resources = Resource.query.all()
        current_date = datetime.now().date()
        
        for resource in resources:
            # 获取最近的利用率记录
            utilization = ResourceUtilization.query.filter_by(
                resource_id=resource.id,
                date=current_date
            ).first()
            
            if utilization and utilization.utilization_rate > 90:
                # 资源使用率超过90%，生成预警
                alert = SystemAlert(
                    alert_type='resource',
                    severity='high',
                    message=f"资源 {resource.name} 使用率过高 ({utilization.utilization_rate:.1f}%)",
                    is_resolved=False
                )
                db.session.add(alert)
            
            # 检查资源可用性
            if resource.available_quantity < resource.total_quantity * 0.1:
                # 可用资源少于10%，生成预警
                alert = SystemAlert(
                    alert_type='resource',
                    severity='critical',
                    message=f"资源 {resource.name} 可用数量不足 (剩余: {resource.available_quantity})",
                    is_resolved=False
                )
                db.session.add(alert)
        
        db.session.commit()
        logger.info("资源预警生成完成")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"生成资源预警时发生错误: {str(e)}") 