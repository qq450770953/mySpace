from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.risk import Risk, RiskLog
from app import db
from datetime import datetime
import logging
from app.models.project import Project
from app.utils.permissions import permission_required, PERMISSION_MANAGE_RISKS, PERMISSION_VIEW_PROJECT

risk_bp = Blueprint('risk', __name__)
logger = logging.getLogger(__name__)

@risk_bp.route('/api/risks', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_risks():
    try:
        risks = Risk.query.all()
        return jsonify([risk.to_dict() for risk in risks])
    except Exception as e:
        logger.error(f"Error getting risks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/projects', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_projects_for_risks():
    """获取项目列表供风险模块使用"""
    try:
        # 检查是否为测试模式
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        if bypass_jwt:
            logger.info("JWT验证已绕过用于测试 - 获取项目列表")
            current_user_id = 1  # 使用测试用户ID
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '未认证，请登录'}), 401
        
        # 获取所有活跃项目
        projects = Project.query.filter(Project.status != 'deleted').all()
        
        # 将项目转换为简单列表返回
        project_list = []
        for project in projects:
            project_list.append({
                'id': project.id,
                'name': project.name,
                'status': project.status
            })
            
        return jsonify(project_list)
    except Exception as e:
        logger.error(f"获取项目列表错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/risks', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def create_risk():
    try:
        current_user = get_jwt_identity()
        
        # 获取请求数据
        data = request.get_json()
        
        # 验证必须的字段
        required_fields = ['title', 'description', 'project_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
                
        # 创建风险
        risk = Risk(
            title=data['title'],
            description=data['description'],
            project_id=data['project_id'],
            probability=data.get('probability', 'medium'),
            impact=data.get('impact', 'medium'),
            status=data.get('status', 'open'),
            mitigation_plan=data.get('mitigation_plan', ''),
            created_by=current_user,
            updated_by=current_user
        )
        
        db.session.add(risk)
        db.session.commit()
        
        # 创建风险日志
        log = RiskLog(
            risk_id=risk.id,
            action='created',
            details=f'Risk created by user {current_user}',
            user_id=current_user
        )
        
        db.session.add(log)
        db.session.commit()
        
        return jsonify(risk.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating risk: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/risks/<int:risk_id>', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_risk(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        return jsonify(risk.to_dict())
    except Exception as e:
        logger.error(f"Error getting risk: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/risks/<int:risk_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def update_risk(risk_id):
    try:
        current_user = get_jwt_identity()
        risk = Risk.query.get_or_404(risk_id)
        data = request.get_json()
        
        risk.title = data.get('title', risk.title)
        risk.description = data.get('description', risk.description)
        risk.impact = data.get('impact', risk.impact)
        risk.probability = data.get('probability', risk.probability)
        risk.status = data.get('status', risk.status)
        risk.mitigation_plan = data.get('mitigation_plan', risk.mitigation_plan)
        risk.updated_by = current_user
        risk.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify(risk.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating risk: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def delete_risk(risk_id):
    try:
        current_user = get_jwt_identity()
        risk = Risk.query.get_or_404(risk_id)
        
        # 检查该风险是否存在关联的风险日志
        logs = RiskLog.query.filter_by(risk_id=risk_id).all()
        for log in logs:
            db.session.delete(log)
        
        db.session.delete(risk)
        db.session.commit()
        
        return jsonify({'message': 'Risk deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting risk: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/risks/<int:risk_id>/logs', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_risk_logs(risk_id):
    try:
        logs = RiskLog.query.filter_by(risk_id=risk_id).order_by(RiskLog.created_at.desc()).all()
        return jsonify([log.to_dict() for log in logs])
    except Exception as e:
        logger.error(f"Error getting risk logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/risks/<int:risk_id>/logs', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RISKS)
def add_risk_log(risk_id):
    try:
        current_user = get_jwt_identity()
        risk = Risk.query.get_or_404(risk_id)
        
        data = request.get_json()
        
        # 验证必须的字段
        if 'action' not in data or 'details' not in data:
            return jsonify({'error': 'Missing required fields: action, details'}), 400
            
        # 创建风险日志
        log = RiskLog(
            risk_id=risk_id,
            action=data['action'],
            details=data['details'],
            user_id=current_user
        )
        
        db.session.add(log)
        db.session.commit()
        
        return jsonify(log.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding risk log: {str(e)}")
        return jsonify({'error': str(e)}), 500

@risk_bp.route('/api/projects/<int:project_id>/risks', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_project_risks(project_id):
    try:
        # 检查项目是否存在
        project = Project.query.get_or_404(project_id)
        
        # 获取项目风险
        risks = Risk.query.filter_by(project_id=project_id).all()
        
        return jsonify([risk.to_dict() for risk in risks])
    except Exception as e:
        logger.error(f"Error getting project risks: {str(e)}")
        return jsonify({'error': str(e)}), 500 