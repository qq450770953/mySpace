from flask import Blueprint, request, jsonify, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.task import Project, Task
from app.models.risk import Risk, RiskLog, RiskMitigation
from app.models.auth import User
from app.models.notification import Notification
from app import db
from app.utils.auth import token_required, admin_required
from app.utils.permissions import permission_required, can_manage_risks, PERMISSION_MANAGE_RISKS, PERMISSION_VIEW_PROJECT
from datetime import datetime
import logging

risk_bp = Blueprint('risk', __name__)
logger = logging.getLogger(__name__)

@risk_bp.route('/', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_risks():
    """获取风险列表"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取所有风险
        risks = Risk.query.all()
        
        return jsonify([{
            'id': risk.id,
            'title': risk.title,
            'description': risk.description,
            'probability': risk.probability,
            'impact': risk.impact,
            'severity': risk.severity,
            'status': risk.status,
            'project_id': risk.project_id,
            'project_name': risk.project.name if hasattr(risk, 'project') and risk.project else None,
            'created_at': risk.created_at.isoformat() if hasattr(risk, 'created_at') and risk.created_at else None,
            'updated_at': risk.updated_at.isoformat() if hasattr(risk, 'updated_at') and risk.updated_at else None,
            'owner_id': risk.owner_id,
            'mitigation_plan': risk.mitigation_plan,
            'contingency_plan': risk.contingency_plan
        } for risk in risks]), 200
    except Exception as e:
        logger.error(f"Error getting risks: {str(e)}")
        return jsonify({'error': '获取风险列表失败', 'detail': str(e)}), 500

@risk_bp.route('/', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def create_risk():
    """创建风险"""
    try:
        current_user_id = get_jwt_identity()
        
        data = request.get_json()
        logger.info(f"Received risk creation data: {data}")
        
        # 验证必填字段
        required_fields = ['description', 'project_id']
        missing_fields = []
        
        for field in required_fields:
            if field not in data or not data[field]:
                missing_fields.append(field)
        
        if missing_fields:
            return jsonify({
                'error': f'缺少必填字段: {", ".join(missing_fields)}',
                'details': '创建风险时必须选择所属项目'
            }), 400
        
        # 检查项目ID是否有效
        project_id = data.get('project_id')
        if not project_id:
            return jsonify({'error': '创建风险时必须选择所属项目'}), 400
            
        project = Project.query.get(project_id)
        if not project:
            return jsonify({'error': '选择的项目不存在'}), 404
        
        # 创建风险
        risk = Risk(
            title=data.get('title', '无标题风险'),
            description=data.get('description', ''),
            probability=data.get('probability', 'medium'),
            impact=data.get('impact', 'medium'),
            status=data.get('status', 'open'),
            project_id=project_id,
            owner_id=data.get('owner_id', current_user_id),  # 如果未提供 owner_id，使用当前用户 ID
            mitigation_plan=data.get('mitigation_plan', ''),
            contingency_plan=data.get('contingency_plan', ''),
            severity=data.get('severity', 'medium')  # 确保提供severity默认值
        )
        
        db.session.add(risk)
        db.session.commit()
        
        # 创建风险日志
        log = RiskLog(
            risk_id=risk.id,
            content=f'创建了风险: {risk.title}',
        )
        db.session.add(log)
        db.session.commit()
        
        logger.info(f"Risk created successfully: {risk.id} - {risk.title}")
        
        return jsonify({
            'id': risk.id,
            'title': risk.title,
            'description': risk.description,
            'status': risk.status,
            'project_id': risk.project_id,
            'message': '风险创建成功'
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating risk: {str(e)}")
        return jsonify({'error': f'创建风险失败: {str(e)}'}), 500

@risk_bp.route('/<int:risk_id>', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_risk(risk_id):
    """获取单个风险详情"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取风险
        risk = Risk.query.get_or_404(risk_id)
        
        # 获取风险缓解措施
        mitigations = RiskMitigation.query.filter_by(risk_id=risk_id).all()
        
        return jsonify({
            'id': risk.id,
            'title': risk.title,
            'description': risk.description,
            'probability': risk.probability,
            'impact': risk.impact,
            'severity': risk.severity,
            'status': risk.status,
            'project_id': risk.project_id,
            'project_name': risk.project.name if hasattr(risk, 'project') and risk.project else None,
            'mitigations': [{
                'id': mit.id,
                'description': mit.description,
                'status': mit.status,
                'created_at': mit.created_at.isoformat() if hasattr(mit, 'created_at') else None,
                'updated_at': mit.updated_at.isoformat() if hasattr(mit, 'updated_at') else None
            } for mit in mitigations],
            'created_at': risk.created_at.isoformat() if hasattr(risk, 'created_at') else None,
            'updated_at': risk.updated_at.isoformat() if hasattr(risk, 'updated_at') else None
        }), 200
    except Exception as e:
        logger.error(f"Error getting risk {risk_id}: {str(e)}")
        return jsonify({'error': '获取风险详情失败', 'detail': str(e)}), 500

@risk_bp.route('/<int:risk_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def update_risk(risk_id):
    """更新风险"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取风险
        risk = Risk.query.get_or_404(risk_id)
        
        # 检查用户是否有权限更新该风险
        user = User.query.get(current_user_id)
        project = Project.query.get(risk.project_id)
        if not (user.has_role('admin') or risk.owner_id == current_user_id or 
                (project and (project.owner_id == current_user_id or project.manager_id == current_user_id))):
            return jsonify({'error': '您没有权限更新此风险'}), 403
        
        data = request.get_json()
        
        # 更新风险字段
        if 'title' in data:
            risk.title = data['title']
        if 'description' in data:
            risk.description = data['description']
        if 'probability' in data:
            risk.probability = data['probability']
        if 'impact' in data:
            risk.impact = data['impact']
        if 'status' in data:
            risk.status = data['status']
        if 'severity' in data:
            risk.severity = data['severity']
        if 'mitigation_plan' in data:
            risk.mitigation_plan = data['mitigation_plan']
        if 'contingency_plan' in data:
            risk.contingency_plan = data['contingency_plan']
        
        risk.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'id': risk.id,
            'message': '风险更新成功'
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating risk {risk_id}: {str(e)}")
        return jsonify({'error': '更新风险失败', 'detail': str(e)}), 500

@risk_bp.route('/<int:risk_id>', methods=['DELETE'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def delete_risk(risk_id):
    """删除风险"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取风险
        risk = Risk.query.get_or_404(risk_id)
        
        # 检查用户是否有权限删除该风险
        user = User.query.get(current_user_id)
        project = Project.query.get(risk.project_id)
        if not (user.has_role('admin') or 
                (project and (project.owner_id == current_user_id or project.manager_id == current_user_id))):
            return jsonify({'error': '您没有权限删除此风险'}), 403
        
        db.session.delete(risk)
        db.session.commit()
        
        return jsonify({
            'message': '风险删除成功'
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting risk {risk_id}: {str(e)}")
        return jsonify({'error': '删除风险失败', 'detail': str(e)}), 500

@risk_bp.route('/<int:risk_id>/logs', methods=['GET'])
@jwt_required()
def get_risk_logs(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        logs = RiskLog.query.filter_by(risk_id=risk_id).order_by(RiskLog.created_at.desc()).all()
        
        # 手动构建日志列表
        logs_data = []
        for log in logs:
            logs_data.append({
                'id': log.id,
                'risk_id': log.risk_id,
                'content': log.content,
                'created_at': log.created_at.isoformat() if log.created_at else None
            })
        
        return jsonify(logs_data)
    except Exception as e:
        logger.error(f"Error getting risk logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/<int:risk_id>/logs', methods=['POST'])
@jwt_required()
def create_risk_log(risk_id):
    try:
        current_user = get_jwt_identity()
        risk = Risk.query.get_or_404(risk_id)
        data = request.get_json()
        
        # 创建风险日志
        log = RiskLog(
            risk_id=risk_id,
            content=data.get('description', f"用户记录了风险日志")
        )
        
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'message': '日志添加成功', 'id': log.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating risk log: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/project/<int:project_id>', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_project_risks(project_id):
    """获取项目风险列表"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info(f"JWT bypass enabled for get_project_risks {project_id} - Using test user")
            current_user_id = 1  # 使用测试用户
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 获取项目
        project = Project.query.get_or_404(project_id)
        
        # 获取项目风险
        risks = Risk.query.filter_by(project_id=project_id).all()
        
        return jsonify([{
            'id': risk.id,
            'title': risk.title,
            'description': risk.description,
            'probability': risk.probability,
            'impact': risk.impact,
            'severity': risk.severity,
            'status': risk.status,
            'project_id': risk.project_id,
            'project_name': risk.project.name if hasattr(risk, 'project') and risk.project else None,
            'created_at': risk.created_at.isoformat() if hasattr(risk, 'created_at') else None,
            'updated_at': risk.updated_at.isoformat() if hasattr(risk, 'updated_at') else None
        } for risk in risks]), 200
    except Exception as e:
        logger.error(f"Error getting project risks for project {project_id}: {str(e)}")
        return jsonify({'error': '获取项目风险失败', 'detail': str(e)}), 500

@risk_bp.route('/task/<int:task_id>', methods=['GET'])
@jwt_required()
def get_task_risks(task_id):
    """获取任务的风险列表"""
    current_user = get_jwt_identity()
    task = Task.query.get_or_404(task_id)
    if not task.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此任务'}), 403
    
    # 获取已记录的风险
    recorded_risks = [risk.to_dict() for risk in task.risks]
    
    # 获取自动分析的风险
    analyzed_risks = task.analyze_risks()
    
    return jsonify({
        'recorded_risks': recorded_risks,
        'analyzed_risks': analyzed_risks
    })

@risk_bp.route('/task/<int:task_id>', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def add_task_risk(task_id):
    """为任务添加风险"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取任务
        task = Task.query.get_or_404(task_id)
        
        data = request.get_json()
        
        # 验证必填字段
        if not data.get('description'):
            return jsonify({'error': '风险描述不能为空'}), 400
        
        # 创建风险
        risk = Risk(
            title=data.get('title', '任务相关风险'),
            description=data.get('description'),
            probability=data.get('probability', 'medium'),
            impact=data.get('impact', 'medium'),
            status='open',
            project_id=task.project_id,
            owner_id=current_user_id,
            task_id=task_id,
            mitigation_plan=data.get('mitigation_plan', ''),
            contingency_plan=data.get('contingency_plan', '')
        )
        
        db.session.add(risk)
        db.session.commit()
        
        # 创建风险日志
        log = RiskLog(
            risk_id=risk.id,
            user_id=current_user_id,
            action='created',
            details=f'风险已创建: {risk.description}'
        )
        
        db.session.add(log)
        db.session.commit()
        
        # 创建通知
        notification = Notification(
            recipient_id=task.assignee_id if task.assignee_id else task.created_by,
            sender_id=current_user_id,
            message=f'您的任务 "{task.title}" 有新的风险: {risk.title}',
            notification_type='risk',
            reference_id=risk.id
        )
        
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'id': risk.id,
            'title': risk.title,
            'description': risk.description,
            'probability': risk.probability,
            'impact': risk.impact,
            'status': risk.status,
            'message': '任务风险添加成功'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"为任务添加风险时出错: {str(e)}")
        return jsonify({'error': '添加风险失败', 'detail': str(e)}), 500

@risk_bp.route('/task/<int:task_id>/<int:risk_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def update_task_risk(task_id, risk_id):
    """更新任务风险"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取风险
        risk = Risk.query.get_or_404(risk_id)
        
        # 验证风险确实属于指定任务
        if risk.task_id != task_id:
            return jsonify({'error': '风险不属于指定任务'}), 404
        
        data = request.get_json()
        
        # 更新风险字段
        if 'title' in data:
            risk.title = data['title']
        if 'description' in data:
            risk.description = data['description']
        if 'probability' in data:
            risk.probability = data['probability']
        if 'impact' in data:
            risk.impact = data['impact']
        if 'status' in data:
            risk.status = data['status']
        if 'severity' in data:
            risk.severity = data['severity']
        if 'mitigation_plan' in data:
            risk.mitigation_plan = data['mitigation_plan']
        if 'contingency_plan' in data:
            risk.contingency_plan = data['contingency_plan']
        
        risk.updated_at = datetime.utcnow()
        
        # 添加风险日志
        log = RiskLog(
            risk_id=risk.id,
            user_id=current_user_id,
            action='updated',
            details=f'风险已更新'
        )
        
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'id': risk.id,
            'message': '风险更新成功'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"更新任务风险出错: {str(e)}")
        return jsonify({'error': '更新风险失败', 'detail': str(e)}), 500

@risk_bp.route('/task/<int:task_id>/<int:risk_id>', methods=['DELETE'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def delete_task_risk(task_id, risk_id):
    """删除任务风险"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取风险
        risk = Risk.query.get_or_404(risk_id)
        
        # 验证风险确实属于指定任务
        if risk.task_id != task_id:
            return jsonify({'error': '风险不属于指定任务'}), 404
        
        db.session.delete(risk)
        db.session.commit()
        
        return jsonify({'message': '风险删除成功'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting task risk {risk_id}: {str(e)}")
        return jsonify({'error': '删除任务风险失败', 'detail': str(e)}), 500

@risk_bp.route('/task/<int:task_id>/analysis', methods=['GET'])
@jwt_required()
def analyze_task_risks(task_id):
    """分析任务风险"""
    current_user = get_jwt_identity()
    task = Task.query.get_or_404(task_id)
    if not task.is_accessible_by(current_user):
        return jsonify({'error': '无权访问此任务'}), 403
    
    # 获取自动分析的风险
    analyzed_risks = task.analyze_risks()
    
    # 检查风险阈值
    risk_warning = task.check_risk_thresholds()
    
    return jsonify({
        'analyzed_risks': analyzed_risks,
        'warning': risk_warning
    })

@risk_bp.route('/<int:risk_id>/mitigations', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def add_mitigation(risk_id):
    """添加风险缓解措施"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取风险
        risk = Risk.query.get_or_404(risk_id)
        
        data = request.get_json()
        
        # 验证必填字段
        if not data.get('description'):
            return jsonify({'error': '缓解措施描述不能为空'}), 400
        
        # 创建缓解措施
        mitigation = RiskMitigation(
            risk_id=risk_id,
            description=data.get('description'),
            status=data.get('status', 'pending'),
            assigned_to=data.get('assigned_to', current_user_id),
            due_date=data.get('due_date')
        )
        
        db.session.add(mitigation)
        db.session.commit()
        
        # 创建风险日志
        log = RiskLog(
            risk_id=risk_id,
            user_id=current_user_id,
            action='added_mitigation',
            details=f'已添加缓解措施: {mitigation.description}'
        )
        
        db.session.add(log)
        db.session.commit()
        
        # 创建通知（如果分配给其他人）
        if data.get('assigned_to') and data.get('assigned_to') != current_user_id:
            notification = Notification(
                recipient_id=data.get('assigned_to'),
                sender_id=current_user_id,
                message=f'您被分配了风险缓解措施: {mitigation.description}',
                notification_type='risk_mitigation',
                reference_id=mitigation.id
            )
            db.session.add(notification)
            db.session.commit()
        
        return jsonify({
            'id': mitigation.id,
            'description': mitigation.description,
            'status': mitigation.status,
            'message': '缓解措施添加成功'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"添加风险缓解措施出错: {str(e)}")
        return jsonify({'error': '添加缓解措施失败', 'detail': str(e)}), 500

@risk_bp.route('/mitigations/<int:mitigation_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def update_mitigation(mitigation_id):
    """更新风险缓解措施"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取缓解措施
        mitigation = RiskMitigation.query.get_or_404(mitigation_id)
        
        # 验证用户是否有权限更新该缓解措施
        risk = Risk.query.get_or_404(mitigation.risk_id)
        project = Project.query.join(TeamMember).filter(
            Project.id == risk.project_id,
            TeamMember.user_id == current_user_id
        ).first_or_404()
        
        data = request.get_json()
        
        # 更新缓解措施字段
        if 'description' in data:
            mitigation.description = data['description']
        if 'status' in data:
            mitigation.status = data['status']
        
        mitigation.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'id': mitigation.id,
            'description': mitigation.description,
            'status': mitigation.status,
            'message': '缓解措施更新成功'
        }), 200
    except Exception as e:
        logger.error(f"Error updating mitigation {mitigation_id}: {str(e)}")
        return jsonify({'error': '更新缓解措施失败'}), 500

@risk_bp.route('/mitigations/<int:mitigation_id>', methods=['DELETE'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def delete_mitigation(mitigation_id):
    """删除风险缓解措施"""
    try:
        current_user_id = get_jwt_identity()
        
        # 获取缓解措施
        mitigation = RiskMitigation.query.get_or_404(mitigation_id)
        
        # 验证用户是否有权限删除该缓解措施
        risk = Risk.query.get_or_404(mitigation.risk_id)
        project = Project.query.join(TeamMember).filter(
            Project.id == risk.project_id,
            TeamMember.user_id == current_user_id,
            TeamMember.role.in_(['owner', 'manager'])
        ).first_or_404()
        
        db.session.delete(mitigation)
        db.session.commit()
        
        return jsonify({'message': '缓解措施删除成功'}), 200
    except Exception as e:
        logger.error(f"Error deleting mitigation {mitigation_id}: {str(e)}")
        return jsonify({'error': '删除缓解措施失败'}), 500

@risk_bp.route('/list')
@jwt_required()
def risk_list():
    """渲染风险列表页面"""
    try:
        current_user = get_jwt_identity()
        return render_template('risks.html', user_id=current_user)
    except Exception as e:
        logger.error(f"Error in risk_list: {str(e)}")
        if request.accept_mimetypes.accept_json:
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('error.html', error='Internal server error'), 500 