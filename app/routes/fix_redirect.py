"""
项目详情页重定向循环修复模块
此文件提供直接渲染项目详情页的功能，避免重定向循环
"""

from flask import render_template
from app.models.project import Project
from app.models.auth import User
import logging

# 设置日志
logger = logging.getLogger(__name__)

def handle_project_detail_redirect(target_url=None):
    """
    直接渲染项目详情页，避免重定向循环
    
    Args:
        target_url: 目标URL，包含项目ID
        
    Returns:
        渲染的项目详情页模板
    """
    # 如果是项目详情页的重定向
    if target_url and '/projects/detail/' in target_url:
        # 提取项目ID
        try:
            project_id = int(target_url.split('/projects/detail/')[1].split('?')[0])
            logger.info(f"重定向循环处理: 直接渲染项目 {project_id} 的详情页")
            
            # 直接获取项目并渲染详情页，不进行重定向
            project = Project.query.get_or_404(project_id)
            
            # 获取项目管理员
            manager = None
            if project.manager_id:
                manager = User.query.get(project.manager_id)
            
            manager_name = manager.name if manager and manager.name else manager.username if manager else "未分配"
            manager_id = int(project.manager_id) if project.manager_id else None
            
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
            
            # 渲染精简版本的项目详情页
            return render_template('projects/detail_minimal.html', project=project_data)
        except Exception as inner_e:
            logger.error(f"处理重定向循环时出错: {str(inner_e)}")
    
    # 返回友好的错误页面
    return render_template('error.html', error='页面加载失败，可能存在重定向循环'), 500 