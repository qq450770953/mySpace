from flask import jsonify, request, current_app, send_file, render_template
from app import db
from app.models import Task, Project, User, ResourceUsage, UserWorkload, Risk, Resource, TeamMember
from app.routes import bp
from app.auth import token_required
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from io import BytesIO
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import json
import psutil
from flask_jwt_extended import jwt_required, get_jwt_identity

@bp.route('/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard():
    """获取仪表板数据"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取用户参与的项目
        projects = Project.query.join(TeamMember).filter(
            TeamMember.user_id == current_user_id
        ).all()
        project_ids = [p.id for p in projects]
        
        # 获取项目任务统计
        tasks = Task.query.filter(Task.project_id.in_(project_ids)).all()
        total_tasks = len(tasks)
        completed_tasks = len([t for t in tasks if t.status == 'completed'])
        in_progress_tasks = len([t for t in tasks if t.status == 'in_progress'])
        pending_tasks = len([t for t in tasks if t.status == 'pending'])
        
        # 获取项目风险统计
        risks = Risk.query.filter(Risk.project_id.in_(project_ids)).all()
        total_risks = len(risks)
        high_risks = len([r for r in risks if r.probability * r.impact >= 0.6])
        medium_risks = len([r for r in risks if 0.3 <= r.probability * r.impact < 0.6])
        low_risks = len([r for r in risks if r.probability * r.impact < 0.3])
        
        # 获取资源使用情况
        resources = Resource.query.join(ResourceAllocation).join(Task).filter(
            Task.project_id.in_(project_ids)
        ).distinct().all()
        total_resources = len(resources)
        allocated_resources = len([r for r in resources if r.current_usage > 0])
        
        # 获取系统资源使用情况
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        
        # 获取最近的活动
        recent_tasks = Task.query.filter(
            Task.project_id.in_(project_ids),
            Task.updated_at >= datetime.utcnow() - timedelta(days=7)
        ).order_by(Task.updated_at.desc()).limit(5).all()
        
        recent_risks = Risk.query.filter(
            Risk.project_id.in_(project_ids),
            Risk.updated_at >= datetime.utcnow() - timedelta(days=7)
        ).order_by(Risk.updated_at.desc()).limit(5).all()
        
        return jsonify({
            'projects': {
                'total': len(projects),
                'active': len([p for p in projects if p.status == 'active']),
                'completed': len([p for p in projects if p.status == 'completed'])
            },
            'tasks': {
                'total': total_tasks,
                'completed': completed_tasks,
                'in_progress': in_progress_tasks,
                'pending': pending_tasks,
                'completion_rate': (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
            },
            'risks': {
                'total': total_risks,
                'high': high_risks,
                'medium': medium_risks,
                'low': low_risks
            },
            'resources': {
                'total': total_resources,
                'allocated': allocated_resources,
                'utilization_rate': (allocated_resources / total_resources * 100) if total_resources > 0 else 0
            },
            'system': {
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage
            },
            'recent_activities': {
                'tasks': [{
                    'id': task.id,
                    'title': task.title,
                    'status': task.status,
                    'project_id': task.project_id,
                    'project_name': task.project.name if task.project else None,
                    'updated_at': task.updated_at.isoformat()
                } for task in recent_tasks],
                'risks': [{
                    'id': risk.id,
                    'title': risk.title,
                    'status': risk.status,
                    'project_id': risk.project_id,
                    'project_name': risk.project.name if risk.project else None,
                    'updated_at': risk.updated_at.isoformat()
                } for risk in recent_risks]
            }
        }), 200
    except Exception as e:
        print(f"Dashboard error: {str(e)}")  # 添加错误日志
        return jsonify({'error': '获取仪表板数据失败'}), 500

@bp.route('/dashboard/projects/<int:project_id>', methods=['GET'])
@jwt_required()
def get_project_dashboard(project_id):
    """获取项目仪表板数据"""
    try:
        current_user_id = get_jwt_identity()
        
        # 验证用户是否有权限访问该项目
        project = Project.query.join(TeamMember).filter(
            Project.id == project_id,
            TeamMember.user_id == current_user_id
        ).first_or_404()
        
        # 获取项目任务统计
        tasks = Task.query.filter_by(project_id=project_id).all()
        total_tasks = len(tasks)
        completed_tasks = len([t for t in tasks if t.status == 'completed'])
        in_progress_tasks = len([t for t in tasks if t.status == 'in_progress'])
        pending_tasks = len([t for t in tasks if t.status == 'pending'])
        
        # 获取项目风险统计
        risks = Risk.query.filter_by(project_id=project_id).all()
        total_risks = len(risks)
        high_risks = len([r for r in risks if r.probability * r.impact >= 0.6])
        medium_risks = len([r for r in risks if 0.3 <= r.probability * r.impact < 0.6])
        low_risks = len([r for r in risks if r.probability * r.impact < 0.3])
        
        # 获取项目资源使用情况
        resources = Resource.query.join(ResourceAllocation).join(Task).filter(
            Task.project_id == project_id
        ).distinct().all()
        total_resources = len(resources)
        allocated_resources = len([r for r in resources if r.current_usage > 0])
        
        # 获取项目进度
        project_progress = project.progress
        
        # 获取项目成员统计
        members = TeamMember.query.filter_by(project_id=project_id).all()
        total_members = len(members)
        active_members = len([m for m in members if m.status == 'active'])
        
        return jsonify({
            'project': {
                'id': project.id,
                'name': project.name,
                'status': project.status,
                'progress': project_progress,
                'start_date': project.start_date.isoformat() if project.start_date else None,
                'end_date': project.end_date.isoformat() if project.end_date else None
            },
            'tasks': {
                'total': total_tasks,
                'completed': completed_tasks,
                'in_progress': in_progress_tasks,
                'pending': pending_tasks,
                'completion_rate': (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
            },
            'risks': {
                'total': total_risks,
                'high': high_risks,
                'medium': medium_risks,
                'low': low_risks
            },
            'resources': {
                'total': total_resources,
                'allocated': allocated_resources,
                'utilization_rate': (allocated_resources / total_resources * 100) if total_resources > 0 else 0
            },
            'team': {
                'total_members': total_members,
                'active_members': active_members
            }
        }), 200
    except Exception as e:
        print(f"Project dashboard error: {str(e)}")
        return jsonify({'error': '获取项目仪表板数据失败'}), 500

@bp.route('/dashboard/statistics', methods=['GET'])
@jwt_required()
def get_statistics():
    """获取统计数据"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取用户参与的项目
        projects = Project.query.join(TeamMember).filter(
            TeamMember.user_id == current_user_id
        ).all()
        project_ids = [p.id for p in projects]
        
        # 获取任务完成趋势
        tasks = Task.query.filter(Task.project_id.in_(project_ids)).all()
        task_trends = []
        for i in range(6, -1, -1):
            date = datetime.utcnow() - timedelta(days=i)
            completed = len([t for t in tasks if t.status == 'completed' and t.updated_at.date() == date.date()])
            task_trends.append({
                'date': date.strftime('%Y-%m-%d'),
                'completed': completed
            })
        
        # 获取风险趋势
        risks = Risk.query.filter(Risk.project_id.in_(project_ids)).all()
        risk_trends = []
        for i in range(6, -1, -1):
            date = datetime.utcnow() - timedelta(days=i)
            new_risks = len([r for r in risks if r.created_at.date() == date.date()])
            resolved_risks = len([r for r in risks if r.status == 'resolved' and r.updated_at.date() == date.date()])
            risk_trends.append({
                'date': date.strftime('%Y-%m-%d'),
                'new': new_risks,
                'resolved': resolved_risks
            })
        
        # 获取资源使用趋势
        resources = Resource.query.join(ResourceAllocation).join(Task).filter(
            Task.project_id.in_(project_ids)
        ).distinct().all()
        resource_trends = []
        for i in range(6, -1, -1):
            date = datetime.utcnow() - timedelta(days=i)
            usage = sum([r.current_usage for r in resources])
            capacity = sum([r.capacity for r in resources])
            resource_trends.append({
                'date': date.strftime('%Y-%m-%d'),
                'usage': usage,
                'capacity': capacity,
                'utilization_rate': (usage / capacity * 100) if capacity > 0 else 0
            })
        
        return jsonify({
            'task_trends': task_trends,
            'risk_trends': risk_trends,
            'resource_trends': resource_trends
        }), 200
    except Exception as e:
        print(f"Statistics error: {str(e)}")
        return jsonify({'error': '获取统计数据失败'}), 500

@bp.route('/api/dashboard/metrics', methods=['GET'])
@token_required
def get_dashboard_metrics(current_user):
    """获取仪表盘核心指标"""
    project_id = request.args.get('project_id', type=int)
    if not project_id:
        return jsonify({'error': '缺少项目ID'}), 400

    project = Project.query.get_or_404(project_id)
    if not project.has_member(current_user):
        return jsonify({'error': '无权访问此项目'}), 403

    # 计算项目完成率
    total_tasks = Task.query.filter_by(project_id=project_id).count()
    completed_tasks = Task.query.filter_by(project_id=project_id, status='completed').count()
    completion_rate = round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 2)

    # 计算资源消耗比
    resource_usage = ResourceUsage.query.filter_by(project_id=project_id).order_by(ResourceUsage.timestamp.desc()).first()
    resource_usage_rate = round(resource_usage.cpu_usage if resource_usage else 0, 2)

    # 计算风险指数
    overdue_tasks = Task.query.filter(
        Task.project_id == project_id,
        Task.status != 'completed',
        Task.end_date < datetime.utcnow()
    ).count()
    risk_index = round((overdue_tasks / total_tasks * 100) if total_tasks > 0 else 0, 2)

    # 计算延期任务比例
    overdue_rate = round((overdue_tasks / total_tasks * 100) if total_tasks > 0 else 0, 2)

    return jsonify({
        'completion_rate': completion_rate,
        'resource_usage_rate': resource_usage_rate,
        'risk_index': risk_index,
        'overdue_rate': overdue_rate
    })

@bp.route('/api/dashboard/task-trend', methods=['GET'])
@token_required
def get_task_trend(current_user):
    """获取任务完成趋势数据"""
    project_id = request.args.get('project_id', type=int)
    if not project_id:
        return jsonify({'error': '缺少项目ID'}), 400

    project = Project.query.get_or_404(project_id)
    if not project.has_member(current_user):
        return jsonify({'error': '无权访问此项目'}), 403

    # 获取最近30天的数据
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)

    # 查询任务数据
    tasks = Task.query.filter(
        Task.project_id == project_id,
        Task.created_at >= start_date
    ).all()

    # 按日期统计
    dates = pd.date_range(start=start_date, end=end_date, freq='D')
    completed_data = {date: 0 for date in dates}
    created_data = {date: 0 for date in dates}

    for task in tasks:
        date = task.created_at.date()
        if date in created_data:
            created_data[date] += 1
        if task.status == 'completed' and task.completed_at:
            date = task.completed_at.date()
            if date in completed_data:
                completed_data[date] += 1

    return jsonify({
        'labels': [date.strftime('%Y-%m-%d') for date in dates],
        'completed': list(completed_data.values()),
        'created': list(created_data.values())
    })

@bp.route('/api/dashboard/task-status', methods=['GET'])
@token_required
def get_task_status(current_user):
    """获取任务状态分布数据"""
    project_id = request.args.get('project_id', type=int)
    if not project_id:
        return jsonify({'error': '缺少项目ID'}), 400

    project = Project.query.get_or_404(project_id)
    if not project.has_member(current_user):
        return jsonify({'error': '无权访问此项目'}), 403

    # 统计各状态任务数量
    todo = Task.query.filter_by(project_id=project_id, status='todo').count()
    in_progress = Task.query.filter_by(project_id=project_id, status='in_progress').count()
    completed = Task.query.filter_by(project_id=project_id, status='completed').count()
    overdue = Task.query.filter(
        Task.project_id == project_id,
        Task.status != 'completed',
        Task.end_date < datetime.utcnow()
    ).count()

    return jsonify({
        'todo': todo,
        'in_progress': in_progress,
        'completed': completed,
        'overdue': overdue
    })

@bp.route('/api/dashboard/resource-usage', methods=['GET'])
@token_required
def get_resource_usage(current_user):
    """获取资源使用趋势数据"""
    project_id = request.args.get('project_id', type=int)
    if not project_id:
        return jsonify({'error': '缺少项目ID'}), 400

    project = Project.query.get_or_404(project_id)
    if not project.has_member(current_user):
        return jsonify({'error': '无权访问此项目'}), 403

    # 获取最近24小时的数据
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    resource_usage = ResourceUsage.query.filter(
        ResourceUsage.project_id == project_id,
        ResourceUsage.timestamp >= start_time
    ).order_by(ResourceUsage.timestamp).all()

    # 按小时统计
    hours = pd.date_range(start=start_time, end=end_time, freq='H')
    cpu_data = {hour: 0 for hour in hours}
    memory_data = {hour: 0 for hour in hours}
    disk_data = {hour: 0 for hour in hours}

    for usage in resource_usage:
        hour = usage.timestamp.replace(minute=0, second=0, microsecond=0)
        if hour in cpu_data:
            cpu_data[hour] = usage.cpu_usage
            memory_data[hour] = usage.memory_usage
            disk_data[hour] = usage.disk_usage

    return jsonify({
        'labels': [hour.strftime('%H:%M') for hour in hours],
        'cpu': list(cpu_data.values()),
        'memory': list(memory_data.values()),
        'disk': list(disk_data.values())
    })

@bp.route('/api/dashboard/workload', methods=['GET'])
@token_required
def get_workload(current_user):
    """获取成员工作负载数据"""
    project_id = request.args.get('project_id', type=int)
    if not project_id:
        return jsonify({'error': '缺少项目ID'}), 400

    project = Project.query.get_or_404(project_id)
    if not project.has_member(current_user):
        return jsonify({'error': '无权访问此项目'}), 403

    # 获取所有成员的工作负载
    workloads = UserWorkload.query.filter_by(project_id=project_id).all()
    
    return jsonify({
        'members': [workload.user.name for workload in workloads],
        'loads': [workload.workload_score for workload in workloads]
    })

@bp.route('/api/reports/generate', methods=['POST'])
@token_required
def generate_report(current_user):
    """生成项目报表"""
    data = request.get_json()
    if not data:
        return jsonify({'error': '缺少必要参数'}), 400

    project_id = data.get('project_id')
    if not project_id:
        return jsonify({'error': '缺少项目ID'}), 400

    project = Project.query.get_or_404(project_id)
    if not project.has_member(current_user):
        return jsonify({'error': '无权访问此项目'}), 403

    report_type = data.get('report_type', 'summary')
    format_type = data.get('format', 'pdf')
    start_date = datetime.strptime(data.get('start_date'), '%Y-%m-%d')
    end_date = datetime.strptime(data.get('end_date'), '%Y-%m-%d')
    assignee_id = data.get('assignee_id')

    # 根据报表类型生成不同的内容
    if format_type == 'pdf':
        return generate_pdf_report(project, report_type, start_date, end_date, assignee_id)
    else:
        return generate_excel_report(project, report_type, start_date, end_date, assignee_id)

def generate_pdf_report(project, report_type, start_date, end_date, assignee_id):
    """生成PDF格式报表"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # 添加标题
    title = Paragraph(f"{project.name} - {report_type}报表", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # 添加项目基本信息
    info = [
        ['项目名称', project.name],
        ['开始日期', start_date.strftime('%Y-%m-%d')],
        ['结束日期', end_date.strftime('%Y-%m-%d')],
        ['项目状态', project.status]
    ]
    table = Table(info, colWidths=[100, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))

    # 根据报表类型添加不同内容
    if report_type == 'summary':
        # 添加项目概览数据
        tasks = Task.query.filter(
            Task.project_id == project.id,
            Task.created_at >= start_date,
            Task.created_at <= end_date
        ).all()

        summary_data = [
            ['总任务数', len(tasks)],
            ['已完成任务', len([t for t in tasks if t.status == 'completed'])],
            ['进行中任务', len([t for t in tasks if t.status == 'in_progress'])],
            ['待办任务', len([t for t in tasks if t.status == 'todo'])],
            ['延期任务', len([t for t in tasks if t.status != 'completed' and t.end_date < datetime.utcnow()])]
        ]

        table = Table(summary_data, colWidths=[200, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(table)

    # 生成PDF
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"{project.name}_{report_type}_report.pdf"
    )

def generate_excel_report(project, report_type, start_date, end_date, assignee_id):
    """生成Excel格式报表"""
    buffer = BytesIO()
    writer = pd.ExcelWriter(buffer, engine='xlsxwriter')
    workbook = writer.book

    # 根据报表类型生成不同的工作表
    if report_type == 'summary':
        # 生成项目概览工作表
        tasks = Task.query.filter(
            Task.project_id == project.id,
            Task.created_at >= start_date,
            Task.created_at <= end_date
        ).all()

        summary_data = {
            '指标': ['总任务数', '已完成任务', '进行中任务', '待办任务', '延期任务'],
            '数量': [
                len(tasks),
                len([t for t in tasks if t.status == 'completed']),
                len([t for t in tasks if t.status == 'in_progress']),
                len([t for t in tasks if t.status == 'todo']),
                len([t for t in tasks if t.status != 'completed' and t.end_date < datetime.utcnow()])
            ]
        }
        df = pd.DataFrame(summary_data)
        df.to_excel(writer, sheet_name='项目概览', index=False)

    writer.close()
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f"{project.name}_{report_type}_report.xlsx"
    ) 