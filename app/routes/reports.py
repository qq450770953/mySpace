from flask import Blueprint, jsonify, request, current_app, render_template_string, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models.auth import User
from app.models.project import Project
from app.models.task import Task
from app.models.risk import Risk
from app.models.resource import Resource
import logging
import json
from datetime import datetime, timedelta
from io import BytesIO
import pandas as pd  # 用于Excel生成

reports_bp = Blueprint('reports', __name__)
logger = logging.getLogger(__name__)

@reports_bp.route('/api/auth/reports/preview', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def preview_report():
    """预览报表数据"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        if bypass_jwt:
            logger.info("JWT bypass enabled for report preview")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        project_id = data.get('project_id')
        if not project_id:
            return jsonify({'error': '项目ID是必需的'}), 400
        
        # 验证项目存在且用户有权限
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'error': '项目不存在'}), 404
        
        # 检查用户权限（如果不使用bypass_jwt）
        if not bypass_jwt and not project.is_accessible_by(current_user_id):
            return jsonify({'error': '没有权限访问此项目'}), 403
        
        # 获取报表类型
        report_type = data.get('report_type', 'summary')
        
        # 获取日期范围
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
            
            if not start_date:
                start_date = datetime.now() - timedelta(days=30)
            
            if not end_date:
                end_date = datetime.now()
                
            # 确保结束日期在开始日期之后
            if start_date > end_date:
                start_date, end_date = end_date, start_date
                
        except ValueError:
            return jsonify({'error': '日期格式无效，请使用YYYY-MM-DD格式'}), 400
        
        # 获取责任人过滤条件
        assignee_id = data.get('assignee_id')
        
        # 根据报表类型获取报表数据
        report_data = {}
        
        if report_type == 'summary':
            report_data = generate_summary_report(project_id, start_date, end_date, assignee_id)
        elif report_type == 'progress':
            report_data = generate_progress_report(project_id, start_date, end_date, assignee_id)
        elif report_type == 'resource':
            report_data = generate_resource_report(project_id, start_date, end_date, assignee_id)
        elif report_type == 'performance':
            report_data = generate_performance_report(project_id, start_date, end_date, assignee_id)
        else:
            return jsonify({'error': '无效的报表类型'}), 400
        
        return jsonify({
            'success': True,
            'message': '报表预览生成成功',
            'data': report_data
        })
        
    except Exception as e:
        logger.exception(f"报表预览生成失败: {str(e)}")
        return jsonify({'error': f'报表生成失败: {str(e)}'}), 500

@reports_bp.route('/api/auth/reports/generate', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def generate_report():
    """生成并下载报表"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        if bypass_jwt:
            logger.info("JWT bypass enabled for report generation")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        project_id = data.get('project_id')
        if not project_id:
            return jsonify({'error': '项目ID是必需的'}), 400
        
        # 验证项目存在且用户有权限
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'error': '项目不存在'}), 404
        
        # 检查用户权限（如果不使用bypass_jwt）
        if not bypass_jwt and not project.is_accessible_by(current_user_id):
            return jsonify({'error': '没有权限访问此项目'}), 403
        
        # 获取报表格式
        report_format = data.get('format', 'pdf')
        if report_format not in ['pdf', 'excel']:
            return jsonify({'error': '无效的报表格式，支持的格式：pdf、excel'}), 400
        
        # 获取报表类型
        report_type = data.get('report_type', 'summary')
        
        # 获取日期范围
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')
        
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
            
            if not start_date:
                start_date = datetime.now() - timedelta(days=30)
            
            if not end_date:
                end_date = datetime.now()
                
            # 确保结束日期在开始日期之后
            if start_date > end_date:
                start_date, end_date = end_date, start_date
                
        except ValueError:
            return jsonify({'error': '日期格式无效，请使用YYYY-MM-DD格式'}), 400
        
        # 获取责任人过滤条件
        assignee_id = data.get('assignee_id')
        
        # 根据报表类型和格式生成报表
        if report_format == 'pdf':
            return generate_pdf_report(project, report_type, start_date, end_date, assignee_id)
        else:  # excel
            return generate_excel_report(project, report_type, start_date, end_date, assignee_id)
        
    except Exception as e:
        logger.exception(f"报表生成失败: {str(e)}")
        return jsonify({'error': f'报表生成失败: {str(e)}'}), 500

@reports_bp.route('/api/auth/reports/projects', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_projects_for_report():
    """获取所有可用于报表的项目"""
    try:
        # 检查是否使用bypass_jwt
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        if bypass_jwt:
            logger.info("JWT bypass enabled for projects API")
            current_user_id = None  # 不需要用户ID过滤
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 查询所有非删除状态的项目
        projects = Project.query.filter(Project.status != 'deleted').all()
        
        # 格式化项目列表数据
        project_list = []
        for project in projects:
            # 如果不是bypass模式，检查用户是否有权限访问此项目
            if not bypass_jwt and current_user_id and not project.is_accessible_by(current_user_id):
                continue
                
            project_list.append({
                'id': project.id,
                'name': project.name,
                'start_date': project.start_date.strftime('%Y-%m-%d') if project.start_date else None,
                'end_date': project.end_date.strftime('%Y-%m-%d') if project.end_date else None,
                'status': project.status
            })
        
        return jsonify({
            'success': True,
            'message': '项目列表获取成功',
            'data': project_list
        })
    except Exception as e:
        logger.exception(f"获取项目列表失败: {str(e)}")
        return jsonify({'error': f'获取项目列表失败: {str(e)}'}), 500

def generate_pdf_report(project, report_type, start_date, end_date, assignee_id=None):
    """生成PDF格式报表"""
    try:
        # 创建一个PDF流
        buffer = BytesIO()
        
        # 获取报表数据
        if report_type == 'summary':
            report_data = generate_summary_report(project.id, start_date, end_date, assignee_id)
        elif report_type == 'progress':
            report_data = generate_progress_report(project.id, start_date, end_date, assignee_id)
        elif report_type == 'resource':
            report_data = generate_resource_report(project.id, start_date, end_date, assignee_id)
        elif report_type == 'performance':
            report_data = generate_performance_report(project.id, start_date, end_date, assignee_id)
        
        try:
            # 尝试导入ReportLab库
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            
            # 使用ReportLab创建PDF
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
                ['项目状态', project.status if hasattr(project, 'status') else '未知']
            ]
            table = Table(info, colWidths=[100, 300])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (0, -1), 10),
                ('BOTTOMPADDING', (0, 0), (0, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 12))
            
            # 根据报表类型添加不同内容
            if report_type == 'summary':
                # 添加项目概览数据
                summary_data = [
                    ['项目完成度', f"{report_data['project_completion']}%"],
                    ['已完成任务', str(report_data['task_status']['completed'])],
                    ['进行中任务', str(report_data['task_status']['in_progress'])],
                    ['待办任务', str(report_data['task_status']['pending'])],
                    ['高风险数量', str(report_data['risk_status']['high'])],
                    ['中风险数量', str(report_data['risk_status']['medium'])],
                    ['低风险数量', str(report_data['risk_status']['low'])]
                ]
                
                summary_title = Paragraph("项目概览", styles['Heading2'])
                elements.append(summary_title)
                elements.append(Spacer(1, 6))
                
                summary_table = Table(summary_data, colWidths=[100, 300])
                summary_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ]))
                elements.append(summary_table)
                
            elif report_type == 'progress':
                # 添加进度详情
                progress_title = Paragraph("任务列表", styles['Heading2'])
                elements.append(progress_title)
                elements.append(Spacer(1, 6))
                
                task_headers = ['任务名称', '负责人', '开始日期', '结束日期', '状态', '进度']
                task_data = [task_headers]
                
                for task in report_data['tasks']:
                    task_data.append([
                        task['name'],
                        task['assignee'],
                        task['start_date'],
                        task['end_date'],
                        task['status'],
                        f"{task['progress']}%"
                    ])
                
                task_table = Table(task_data, colWidths=[80, 60, 70, 70, 60, 40])
                task_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ]))
                elements.append(task_table)
                
            elif report_type == 'resource':
                # 添加资源使用信息
                resource_title = Paragraph("资源使用情况", styles['Heading2'])
                elements.append(resource_title)
                elements.append(Spacer(1, 6))
                
                resource_headers = ['资源名称', '类型', '分配期间', '使用率', '状态']
                resource_data = [resource_headers]
                
                for resource in report_data['resources']:
                    resource_data.append([
                        resource['name'],
                        resource['type'],
                        resource['allocation_period'],
                        f"{resource['utilization']}%",
                        resource['status']
                    ])
                
                resource_table = Table(resource_data, colWidths=[100, 80, 120, 60, 60])
                resource_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ]))
                elements.append(resource_table)
                
            elif report_type == 'performance':
                # 添加绩效分析信息
                performance_title = Paragraph("团队成员贡献", styles['Heading2'])
                elements.append(performance_title)
                elements.append(Spacer(1, 6))
                
                perf_headers = ['成员', '已完成任务', '进行中任务', '平均完成时间', '及时率', '质量评分']
                perf_data = [perf_headers]
                
                for member in report_data['member_contributions']:
                    perf_data.append([
                        member['member'],
                        str(member['completed_tasks']),
                        str(member['in_progress_tasks']),
                        f"{member['avg_completion_time']}天",
                        f"{member['timeliness_rate']}%",
                        f"{member['quality_score']}/5"
                    ])
                
                perf_table = Table(perf_data, colWidths=[70, 60, 60, 80, 60, 60])
                perf_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ]))
                elements.append(perf_table)
            
            # 生成PDF
            doc.build(elements)
            buffer.seek(0)
            
            # 生成文件名
            filename = f"{project.name}_{report_type}_{datetime.now().strftime('%Y%m%d')}.pdf"
            
            return send_file(
                buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
            
        except ImportError:
            # 如果ReportLab未安装，则回退到文本文件
            logger.warning("ReportLab未安装，使用文本文件作为备选")
            
            # 创建一个简单的文本文件，模拟PDF
            content = f"""
{project.name} - {report_type} 报表

报表期间: {start_date.strftime('%Y-%m-%d')} 至 {end_date.strftime('%Y-%m-%d')}

报表内容:
{json.dumps(report_data, indent=2, ensure_ascii=False)}
            """
            
            buffer = BytesIO()
            buffer.write(content.encode('utf-8'))
            buffer.seek(0)
            
            # 生成文件名
            filename = f"{project.name}_{report_type}_{datetime.now().strftime('%Y%m%d')}.txt"
            
            return send_file(
                buffer,
                mimetype='text/plain',
                as_attachment=True,
                download_name=filename
            )
            
    except Exception as e:
        logger.exception(f"PDF报表生成失败: {str(e)}")
        raise

def generate_excel_report(project, report_type, start_date, end_date, assignee_id=None):
    """生成Excel格式报表"""
    try:
        # 创建一个Excel内存流
        buffer = BytesIO()
        
        # 获取报表数据
        if report_type == 'summary':
            report_data = generate_summary_report(project.id, start_date, end_date, assignee_id)
        elif report_type == 'progress':
            report_data = generate_progress_report(project.id, start_date, end_date, assignee_id)
        elif report_type == 'resource':
            report_data = generate_resource_report(project.id, start_date, end_date, assignee_id)
        elif report_type == 'performance':
            report_data = generate_performance_report(project.id, start_date, end_date, assignee_id)
        
        # 使用pandas创建Excel文件 (使用openpyxl引擎而不是xlsxwriter)
        writer = pd.ExcelWriter(buffer, engine='openpyxl')
        
        # 创建基本信息工作表
        info_df = pd.DataFrame([
            ['项目名称', project.name],
            ['报表类型', report_type],
            ['开始日期', start_date.strftime('%Y-%m-%d')],
            ['结束日期', end_date.strftime('%Y-%m-%d')],
        ], columns=['指标', '值'])
        
        info_df.to_excel(writer, sheet_name='基本信息', index=False)
        
        # 根据报表类型创建不同的数据工作表
        if report_type == 'summary':
            # 项目完成度
            completion_df = pd.DataFrame([['项目完成度', f"{report_data['project_completion']}%"]], 
                                      columns=['指标', '值'])
            completion_df.to_excel(writer, sheet_name='项目完成度', index=False)
            
            # 任务状态
            task_status_df = pd.DataFrame([
                ['已完成任务', report_data['task_status']['completed']],
                ['进行中任务', report_data['task_status']['in_progress']],
                ['待处理任务', report_data['task_status']['pending']]
            ], columns=['任务状态', '数量'])
            task_status_df.to_excel(writer, sheet_name='任务状态', index=False)
            
            # 风险状态
            risk_status_df = pd.DataFrame([
                ['高风险', report_data['risk_status']['high']],
                ['中风险', report_data['risk_status']['medium']],
                ['低风险', report_data['risk_status']['low']]
            ], columns=['风险级别', '数量'])
            risk_status_df.to_excel(writer, sheet_name='风险状态', index=False)
            
        elif report_type == 'progress':
            # 完成趋势
            trend_df = pd.DataFrame(report_data['completion_trend'])
            trend_df.to_excel(writer, sheet_name='完成趋势', index=False)
            
            # 任务列表
            tasks_df = pd.DataFrame(report_data['tasks'])
            tasks_df.to_excel(writer, sheet_name='任务列表', index=False)
            
        elif report_type == 'resource':
            # 资源分配
            allocation_df = pd.DataFrame(report_data['resource_allocation'])
            allocation_df.to_excel(writer, sheet_name='资源分配', index=False)
            
            # 部门参与度
            dept_df = pd.DataFrame(report_data['department_involvement'])
            dept_df.to_excel(writer, sheet_name='部门参与度', index=False)
            
            # 资源列表
            resources_df = pd.DataFrame(report_data['resources'])
            resources_df.to_excel(writer, sheet_name='资源列表', index=False)
            
        elif report_type == 'performance':
            # 团队效率
            efficiency_df = pd.DataFrame(report_data['team_efficiency'])
            efficiency_df.to_excel(writer, sheet_name='团队效率', index=False)
            
            # 任务完成及时率
            timeliness_df = pd.DataFrame(report_data['task_timeliness'])
            timeliness_df.to_excel(writer, sheet_name='任务完成及时率', index=False)
            
            # 成员贡献
            contrib_df = pd.DataFrame(report_data['member_contributions'])
            contrib_df.to_excel(writer, sheet_name='成员贡献', index=False)
        
        # 保存Excel文件
        writer.close()
        buffer.seek(0)
        
        # 生成文件名
        filename = f"{project.name}_{report_type}_{datetime.now().strftime('%Y%m%d')}.xlsx"
        
        return send_file(
            buffer,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.exception(f"Excel报表生成失败: {str(e)}")
        raise

# 辅助函数：生成各类报表数据
def generate_summary_report(project_id, start_date, end_date, assignee_id=None):
    """生成项目概览报表数据"""
    # 这里实现实际的数据查询和处理逻辑
    # 由于是示例，返回模拟数据
    return {
        'project_completion': 65,  # 项目完成度百分比
        'task_status': {
            'completed': 10,  # 已完成任务数
            'in_progress': 15,  # 进行中任务数
            'pending': 5  # 待处理任务数
        },
        'risk_status': {
            'high': 2,  # 高风险数
            'medium': 3,  # 中风险数
            'low': 1  # 低风险数
        }
    }

def generate_progress_report(project_id, start_date, end_date, assignee_id=None):
    """生成进度详情报表数据"""
    # 这里实现实际的数据查询和处理逻辑
    # 由于是示例，返回模拟数据
    return {
        'completion_trend': [
            {'date': '2023-01-01', 'completed': 2},
            {'date': '2023-01-08', 'completed': 5},
            {'date': '2023-01-15', 'completed': 8},
            {'date': '2023-01-22', 'completed': 10},
            {'date': '2023-01-29', 'completed': 12}
        ],
        'tasks': [
            {
                'name': '需求分析',
                'assignee': '张三',
                'start_date': '2023-01-01',
                'end_date': '2023-01-15',
                'status': 'completed',
                'progress': 100
            },
            {
                'name': '系统设计',
                'assignee': '李四',
                'start_date': '2023-01-16',
                'end_date': '2023-02-15',
                'status': 'in_progress',
                'progress': 75
            },
            {
                'name': '前端开发',
                'assignee': '王五',
                'start_date': '2023-02-01',
                'end_date': '2023-03-15',
                'status': 'in_progress',
                'progress': 60
            }
        ]
    }

def generate_resource_report(project_id, start_date, end_date, assignee_id=None):
    """生成资源使用报表数据"""
    # 这里实现实际的数据查询和处理逻辑
    # 由于是示例，返回模拟数据
    return {
        'resource_allocation': [
            {'type': '开发人员', 'count': 5, 'percentage': 50},
            {'type': '测试人员', 'count': 2, 'percentage': 20},
            {'type': '设计师', 'count': 1, 'percentage': 10},
            {'type': '产品经理', 'count': 1, 'percentage': 10},
            {'type': '项目经理', 'count': 1, 'percentage': 10}
        ],
        'department_involvement': [
            {'department': '研发部', 'involvement': 60},
            {'department': '测试部', 'involvement': 20},
            {'department': '设计部', 'involvement': 10},
            {'department': '产品部', 'involvement': 10}
        ],
        'resources': [
            {
                'name': '开发团队A',
                'type': '人力资源',
                'allocation_period': '2023-01-01 ~ 2023-03-31',
                'utilization': 85,
                'status': 'normal'
            },
            {
                'name': '测试服务器',
                'type': '设备资源',
                'allocation_period': '2023-01-15 ~ 2023-04-15',
                'utilization': 60,
                'status': 'normal'
            },
            {
                'name': '设计工具许可证',
                'type': '软件资源',
                'allocation_period': '2023-01-01 ~ 2023-12-31',
                'utilization': 40,
                'status': 'over_allocated'
            }
        ]
    }

def generate_performance_report(project_id, start_date, end_date, assignee_id=None):
    """生成绩效分析报表数据"""
    # 这里实现实际的数据查询和处理逻辑
    # 由于是示例，返回模拟数据
    return {
        'team_efficiency': [
            {'member': '张三', 'task_completion': 95, 'quality': 90, 'timeliness': 85, 'teamwork': 92, 'innovation': 88},
            {'member': '李四', 'task_completion': 90, 'quality': 92, 'timeliness': 80, 'teamwork': 85, 'innovation': 90},
            {'member': '王五', 'task_completion': 92, 'quality': 88, 'timeliness': 90, 'teamwork': 90, 'innovation': 85}
        ],
        'task_timeliness': [
            {'week': '第1周', 'on_time': 90, 'delayed': 10},
            {'week': '第2周', 'on_time': 85, 'delayed': 15},
            {'week': '第3周', 'on_time': 95, 'delayed': 5},
            {'week': '第4周', 'on_time': 88, 'delayed': 12}
        ],
        'member_contributions': [
            {
                'member': '张三',
                'completed_tasks': 12,
                'in_progress_tasks': 3,
                'avg_completion_time': 3.5,
                'timeliness_rate': 95,
                'quality_score': 4.8
            },
            {
                'member': '李四',
                'completed_tasks': 8,
                'in_progress_tasks': 4,
                'avg_completion_time': 4.2,
                'timeliness_rate': 85,
                'quality_score': 4.5
            },
            {
                'member': '王五',
                'completed_tasks': 10,
                'in_progress_tasks': 2,
                'avg_completion_time': 3.8,
                'timeliness_rate': 90,
                'quality_score': 4.7
            }
        ]
    } 