from flask import Blueprint, jsonify, request, render_template, url_for, redirect
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.resource import Resource, ResourceAllocation, ResourceUtilization, ResourceReport, ResourceEfficiency, ResourceUsage, ResourceType, UserWorkload, SystemAlert
from app.models.task import Project, Task
from app.models.auth import User
from app.extensions import db
from datetime import datetime, timedelta
import psutil
import pandas as pd
from app.utils.auth import token_required, admin_required
import random
import statistics
from flask import current_app
import json
import numpy as np
import logging
from sqlalchemy import or_, and_
from flask_login import login_required, current_user
from app.utils.permissions import permission_required, PERMISSION_MANAGE_RESOURCES, PERMISSION_VIEW_PROJECT

def simple_linear_regression(x, y):
    """Simple linear regression implementation using numpy"""
    x_mean = np.mean(x)
    y_mean = np.mean(y)
    
    # Calculate slope (beta)
    numerator = np.sum((x - x_mean) * (y - y_mean))
    denominator = np.sum((x - x_mean) ** 2)
    slope = numerator / denominator if denominator != 0 else 0
    
    # Calculate intercept (alpha)
    intercept = y_mean - slope * x_mean
    
    # Calculate R-squared
    y_pred = slope * x + intercept
    r_squared = 1 - np.sum((y - y_pred) ** 2) / np.sum((y - y_mean) ** 2)
    
    return slope, intercept, r_squared

resource_bp = Blueprint('resources', __name__)
logger = logging.getLogger(__name__)

@resource_bp.route('/resources/usage', methods=['GET'])
@jwt_required()
def get_resource_usage():
    # Get current system resource usage
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    network = psutil.net_io_counters()
    
    # Record the usage
    usage = ResourceUsage(
        user_id=get_jwt_identity(),
        cpu_usage=cpu_usage,
        memory_usage=memory.percent,
        disk_usage=disk.percent,
        network_usage=network.bytes_sent + network.bytes_recv
    )
    
    db.session.add(usage)
    db.session.commit()
    
    return jsonify(usage.to_dict())

@resource_bp.route('/resources/workload', methods=['GET'])
@jwt_required()
def get_workload():
    user_id = get_jwt_identity()
    
    # Calculate workload metrics
    total_tasks = Task.query.filter_by(assignee_id=user_id).count()
    completed_tasks = Task.query.filter_by(assignee_id=user_id, status='completed').count()
    in_progress_tasks = Task.query.filter_by(assignee_id=user_id, status='in_progress').count()
    overdue_tasks = Task.query.filter(
        Task.assignee_id == user_id,
        Task.status != 'completed',
        Task.due_date < datetime.utcnow()
    ).count()
    
    # Calculate workload score (simple example)
    workload_score = (in_progress_tasks * 0.5 + overdue_tasks) / max(total_tasks, 1)
    
    # Record workload
    workload = UserWorkload(
        user_id=user_id,
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        in_progress_tasks=in_progress_tasks,
        overdue_tasks=overdue_tasks,
        workload_score=workload_score
    )
    
    db.session.add(workload)
    db.session.commit()
    
    return jsonify(workload.to_dict())

@resource_bp.route('/resources/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    alerts = SystemAlert.query.filter_by(is_resolved=False).order_by(SystemAlert.created_at.desc()).all()
    return jsonify([alert.to_dict() for alert in alerts])

@resource_bp.route('/resources/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    user_id = get_jwt_identity()
    
    # Get resource usage data for the last 24 hours
    start_time = datetime.utcnow() - timedelta(days=1)
    usage_data = ResourceUsage.query.filter(
        ResourceUsage.user_id == user_id,
        ResourceUsage.recorded_at >= start_time
    ).all()
    
    # Convert to DataFrame for analysis
    df = pd.DataFrame([u.to_dict() for u in usage_data])
    
    # Calculate statistics
    stats = {
        'cpu': {
            'mean': df['cpu_usage'].mean(),
            'max': df['cpu_usage'].max(),
            'min': df['cpu_usage'].min()
        },
        'memory': {
            'mean': df['memory_usage'].mean(),
            'max': df['memory_usage'].max(),
            'min': df['memory_usage'].min()
        },
        'disk': {
            'mean': df['disk_usage'].mean(),
            'max': df['disk_usage'].max(),
            'min': df['disk_usage'].min()
        },
        'network': {
            'total': df['network_usage'].sum(),
            'mean': df['network_usage'].mean()
        }
    }
    
    return jsonify(stats)

@resource_bp.route('/resources/predictions', methods=['GET'])
@jwt_required()
def get_predictions():
    user_id = get_jwt_identity()
    
    # Get workload data for the last 7 days
    start_time = datetime.utcnow() - timedelta(days=7)
    workload_data = UserWorkload.query.filter(
        UserWorkload.user_id == user_id,
        UserWorkload.recorded_at >= start_time
    ).all()
    
    # Convert to DataFrame for analysis
    df = pd.DataFrame([w.to_dict() for w in workload_data])
    
    # Simple prediction based on trends
    predictions = {
        'completion_rate': df['completed_tasks'].mean() / max(df['total_tasks'].mean(), 1),
        'overdue_risk': df['overdue_tasks'].mean() / max(df['total_tasks'].mean(), 1),
        'workload_trend': 'increasing' if df['workload_score'].iloc[-1] > df['workload_score'].iloc[0] else 'decreasing'
    }
    
    return jsonify(predictions)

@resource_bp.route('/api/projects/<int:project_id>/resources', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_project_resources(project_id):
    """Get all resources for a project"""
    resources = Resource.query.filter_by(project_id=project_id).all()
    return jsonify([{
        'id': r.id,
        'name': r.name,
        'type': r.type.name if hasattr(r, 'type') and r.type else None,
        'type_id': r.type_id,
        'quantity': r.capacity if hasattr(r, 'capacity') else r.quantity,
        'unit': r.unit,
        'cost_per_unit': r.cost_per_unit,
        'start_date': r.start_date.isoformat() if r.start_date else None,
        'end_date': r.end_date.isoformat() if r.end_date else None,
        'status': r.status,
        'allocated_quantity': sum(a.allocated_quantity for a in r.allocations if a.status == 'active') if hasattr(r, 'allocations') and r.allocations else 0,
        'utilization_rate': calculate_utilization_rate(r)
    } for r in resources])

@resource_bp.route('/api/projects/<int:project_id>/resources', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RESOURCES)
def create_project_resource(project_id):
    """Create a new resource for a project"""
    data = request.get_json()
    
    resource = Resource(
        project_id=project_id,
        name=data['name'],
        resource_type=data['type'],
        quantity=data['quantity'],
        unit=data.get('unit'),
        cost_per_unit=data.get('cost_per_unit'),
        start_date=datetime.fromisoformat(data['start_date']) if data.get('start_date') else None,
        end_date=datetime.fromisoformat(data['end_date']) if data.get('end_date') else None
    )
    
    db.session.add(resource)
    db.session.commit()
    
    return jsonify({
        'id': resource.id,
        'message': 'Resource created successfully'
    }), 201

@resource_bp.route('/api/resources/<int:resource_id>', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_resource(resource_id):
    """获取单个资源详情"""
    try:
        resource = Resource.query.get_or_404(resource_id)
        return jsonify(resource.to_dict())
        
    except Exception as e:
        logger.error(f"Error getting resource: {str(e)}")
        return jsonify({'error': f'获取资源详情失败: {str(e)}'}), 500

@resource_bp.route('/<int:resource_id>', methods=['PUT'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_RESOURCES)
def update_resource(resource_id):
    """更新资源"""
    try:
        # 获取当前用户ID
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        if bypass_jwt:
            current_user_id = 1  # 使用测试用户ID
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 获取资源
        resource = Resource.query.get_or_404(resource_id)
        
        # 获取项目，检查权限
        project = Project.query.get(resource.project_id)
        if not project:
            return jsonify({'error': '资源所属项目不存在'}), 404
        
        # 用户需要有资源管理权限
        user = User.query.get(current_user_id)
        if not user.has_permission(PERMISSION_MANAGE_RESOURCES):
            return jsonify({'error': '您没有资源管理权限'}), 403
        
        data = request.get_json()
        
        # Update the resource with the provided data
        if 'name' in data:
            resource.name = data['name']
        if 'resource_type' in data:
            resource.resource_type = data['resource_type']
        if 'quantity' in data:
            resource.quantity = data['quantity']
        if 'unit' in data:
            resource.unit = data['unit']
        if 'cost_per_unit' in data:
            resource.cost_per_unit = data['cost_per_unit']
        if 'start_date' in data and data['start_date']:
            try:
                resource.start_date = datetime.fromisoformat(data['start_date'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'error': 'Invalid start date format'}), 400
        if 'end_date' in data and data['end_date']:
            try:
                resource.end_date = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))
            except ValueError:
                return jsonify({'error': 'Invalid end date format'}), 400
        if 'status' in data:
            resource.status = data['status']
        if 'description' in data:
            resource.description = data['description']
        
        db.session.commit()
        
        return jsonify({
            'id': resource.id,
            'name': resource.name,
            'type': resource.resource_type,
            'quantity': resource.quantity,
            'unit': resource.unit,
            'cost_per_unit': resource.cost_per_unit,
            'start_date': resource.start_date.isoformat() if resource.start_date else None,
            'end_date': resource.end_date.isoformat() if resource.end_date else None,
            'status': resource.status,
            'description': resource.description
        })
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating resource: {str(e)}")
        return jsonify({'error': 'Failed to update resource', 'details': str(e)}), 500

@resource_bp.route('/<int:resource_id>', methods=['DELETE'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_RESOURCES)
def delete_resource(resource_id):
    """删除资源"""
    try:
        # 获取当前用户ID
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        if bypass_jwt:
            current_user_id = 1  # 使用测试用户ID
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                return jsonify({'error': '认证失败，请登录'}), 401
        
        # 获取资源
        resource = Resource.query.get_or_404(resource_id)
        
        # 获取项目，检查权限
        project = Project.query.get(resource.project_id)
        if not project:
            return jsonify({'error': '资源所属项目不存在'}), 404
        
        # 用户需要有资源管理权限
        user = User.query.get(current_user_id)
        if not user.has_permission(PERMISSION_MANAGE_RESOURCES):
            return jsonify({'error': '您没有资源管理权限'}), 403
        
        # 检查资源是否正在使用
        active_allocations = ResourceAllocation.query.filter_by(
            resource_id=resource_id, 
            status='active'
        ).count()
        
        if active_allocations > 0:
            return jsonify({'error': '无法删除正在使用的资源'}), 400
            
        # 删除资源
        db.session.delete(resource)
        db.session.commit()
        
        return jsonify({
            'message': '资源删除成功',
            'resource_id': resource_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting resource: {str(e)}")
        return jsonify({'error': f'删除资源失败: {str(e)}'}), 500

@resource_bp.route('/api/resources/<int:resource_id>/usage', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_resource_usage_api(resource_id):
    """获取资源用量记录"""
    resource = Resource.query.get_or_404(resource_id)
    
    # 验证用户是否有权访问该资源所属项目
    if not can_access_project(resource.project_id):
        return jsonify({'error': '没有权限访问该资源'}), 403
    
    # 获取资源的使用记录
    usage_records = ResourceUtilization.query.filter_by(resource_id=resource_id).order_by(ResourceUtilization.recorded_at.desc()).all()
    
    return jsonify([{
        'id': record.id,
        'quantity_used': record.quantity_used,
        'recorded_at': record.recorded_at.isoformat() if record.recorded_at else None,
        'recorded_by': record.recorded_by,
        'notes': record.notes
    } for record in usage_records])

@resource_bp.route('/api/resources/<int:resource_id>/usage', methods=['POST'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RESOURCES)
def record_resource_usage(resource_id):
    """记录资源使用情况"""
    try:
        current_user = get_jwt_identity()
        resource = Resource.query.get_or_404(resource_id)
        data = request.get_json()
        
        usage = ResourceUsage(
            resource_id=resource_id,
            user_id=current_user,
            usage=data['usage'],
            description=data.get('description'),
            created_at=datetime.utcnow()
        )
        
        db.session.add(usage)
        db.session.commit()
        return jsonify(usage.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating resource usage: {str(e)}")
        return jsonify({'error': str(e)}), 500

@resource_bp.route('/api/resources', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_VIEW_PROJECT)
def get_resources():
    """获取资源列表，支持多种过滤条件、排序和分页"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        logger.info(f"API request to get_resources with bypass_jwt={bypass_jwt}, path={request.path}, url={request.url}")
        logger.info(f"Headers: {dict(request.headers)}")
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for get_resources - Using test user")
            current_user_id = 1  # Replace with a valid user ID in your database
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                logger.warning("Unauthorized access to get_resources", extra={
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string
                })
                return jsonify({'error': '认证失败，请登录', 'detail': 'No JWT token found or token invalid'}), 401
        
        # 获取查询参数
        type_id = request.args.get('type_id', type=int)
        status = request.args.getlist('status')  # 支持多状态过滤
        search = request.args.get('search', '')  # 搜索名称和描述
        
        # 分页参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        per_page = min(per_page, 100)  # 限制每页最大数量
        
        # 排序参数
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # 构建查询
        query = Resource.query
        
        # 基本过滤条件
        if type_id:
            query = query.filter(Resource.type_id == type_id)
        if status:
            query = query.filter(Resource.status.in_(status))
            
        # 搜索名称和描述
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Resource.name.ilike(search_term),
                    Resource.description.ilike(search_term)
                )
            )
            
        # 排序
        valid_sort_fields = {
            'created_at': Resource.created_at,
            'updated_at': Resource.updated_at,
            'name': Resource.name,
            'status': Resource.status,
            'type_id': Resource.type_id
        }
        
        sort_field = valid_sort_fields.get(sort_by, Resource.created_at)
        if sort_order == 'desc':
            sort_field = sort_field.desc()
        query = query.order_by(sort_field)
        
        # 预加载关联数据
        try:
            query = query.options(
                db.joinedload(Resource.type),
                db.joinedload(Resource.allocations)
            )
        except Exception as e:
            logger.warning(f"Error loading relationships: {str(e)}")
        
        # 执行分页查询
        try:
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            resources = pagination.items
            logger.info(f"Found {len(resources)} resources")
        except Exception as e:
            logger.error(f"Error during pagination: {str(e)}")
            return jsonify({'error': 'Failed to paginate resources'}), 500
        
        # 构建响应数据
        try:
            # Simple approach in case to_dict method causes issues
            resource_list = []
            for resource in resources:
                try:
                    resource_data = resource.to_dict()
                except Exception as e:
                    logger.warning(f"Error converting resource {resource.id} to dict: {str(e)}")
                    # Fallback to basic attributes
                    resource_data = {
                        'id': resource.id,
                        'name': resource.name,
                        'type_id': resource.type_id,
                        'description': resource.description,
                        'capacity': resource.capacity,
                        'unit': resource.unit,
                        'status': resource.status
                    }
                resource_list.append(resource_data)
                
            response = {
                'resources': resource_list,
                'pagination': {
                    'total': pagination.total,
                    'pages': pagination.pages,
                    'current_page': page,
                    'per_page': per_page,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                }
            }
            
            # Ensure we're returning JSON and set Content-Type explicitly
            resp = jsonify(response)
            resp.headers['Content-Type'] = 'application/json'
            logger.info(f"Successfully returned {len(resource_list)} resources as JSON")
            return resp
            
        except Exception as e:
            logger.error(f"Error serializing resources: {str(e)}")
            return jsonify({'error': 'Failed to serialize resources'}), 500
            
    except Exception as e:
        logger.error(f"Error in get_resources: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@resource_bp.route('/', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_resources_root():
    """Get all resources"""
    search_query = request.args.get('search', '')
    resource_type = request.args.get('type', '')
    status = request.args.get('status', '')
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')
    limit = int(request.args.get('limit', 20))
    offset = int(request.args.get('offset', 0))
    
    # 构建查询
    query = Resource.query
    
    # 应用过滤条件
    if search_query:
        query = query.filter(Resource.name.like(f'%{search_query}%'))
    if resource_type:
        query = query.filter(Resource.resource_type == resource_type)
    if status:
        query = query.filter(Resource.status == status)
    
    # 应用排序
    if sort_order.lower() == 'asc':
        query = query.order_by(getattr(Resource, sort_by).asc())
    else:
        query = query.order_by(getattr(Resource, sort_by).desc())
    
    # 获取总数
    total_count = query.count()
    
    # 应用分页
    resources = query.limit(limit).offset(offset).all()
    
    # 转换为字典列表并添加利用率信息
    resource_list = [
        {
            'id': r.id,
            'name': r.name,
            'type': r.type.name if hasattr(r, 'type') and r.type else None,
            'type_id': r.type_id,
            'quantity': r.capacity,
            'unit': r.unit,
            'cost_per_unit': r.cost_per_unit,
            'start_date': r.start_date.isoformat() if hasattr(r, 'start_date') and r.start_date else None,
            'end_date': r.end_date.isoformat() if hasattr(r, 'end_date') and r.end_date else None,
            'status': r.status,
            'description': r.description,
            'utilization_rate': calculate_utilization_rate(r),
            'allocated_quantity': sum(a.allocated_quantity for a in r.allocations if a.status == 'active') if hasattr(r, 'allocations') else 0,
            'created_at': r.created_at.isoformat(),
            'updated_at': r.updated_at.isoformat() if r.updated_at else None
        }
        for r in resources
    ]
    
    # 请求返回HTML
    if 'text/html' in request.headers.get('Accept', ''):
        from app.models.common import Pagination
        
        # 创建分页对象
        pagination = Pagination(None, offset // limit + 1, limit, total_count, None)
        
        return render_template(
            'resources/index.html',
            resources=resources,
            pagination=pagination,
            search_query=search_query,
            resource_type=resource_type,
            status=status,
            sort_by=sort_by,
            sort_order=sort_order,
            resource_types=ResourceType.query.all()
        )
    
    # API请求返回JSON
    return jsonify({
        'resources': resource_list,
        'pagination': {
            'limit': limit,
            'offset': offset,
            'total': total_count
        }
    })

@resource_bp.route('/', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_RESOURCES)
def create_resource():
    """创建新资源"""
    try:
        # Check if bypass_jwt is true in query params for testing
        bypass_jwt = request.args.get('bypass_jwt') == 'true'
        
        logger.info(f"API request to create_resource with bypass_jwt={bypass_jwt}")
        
        if bypass_jwt:
            logger.info("JWT bypass enabled for create_resource - Using test user")
            current_user_id = 1  # Replace with a valid user ID in your database
        else:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                logger.warning("Unauthorized access to create_resource", extra={
                    'ip': request.remote_addr,
                    'user_agent': request.user_agent.string
                })
                return jsonify({'error': '认证失败，请登录', 'detail': 'No JWT token found or token invalid'}), 401
        
        # Log the request content type
        logger.info(f"Request Content-Type: {request.headers.get('Content-Type', 'Not specified')}")
        
        data = request.get_json()
        logger.info(f"Received resource creation data: {data}")
        
        # 验证必要字段
        if not data or not data.get('name'):
            return jsonify({'error': '资源名称不能为空'}), 400
            
        # 创建新资源
        resource = Resource(
            name=data['name'],
            type_id=data.get('type_id', 1),  # 默认使用ID为1的资源类型
            capacity=data.get('capacity', 1.0),
            unit=data.get('unit', '个'),
            cost_per_unit=data.get('cost_per_unit', 0.0),
            description=data.get('description', ''),
            status=data.get('status', 'available')
        )
        
        db.session.add(resource)
        db.session.commit()
        
        logger.info(f"Resource created successfully: {resource.id} - {resource.name}")
        
        # Create the response with explicit Content-Type header
        response_data = {
            'message': '资源创建成功',
            'resource': resource.to_dict()
        }
        
        resp = jsonify(response_data)
        resp.headers['Content-Type'] = 'application/json'
        
        return resp, 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating resource: {str(e)}", exc_info=True)
        
        error_resp = jsonify({'error': f'创建资源失败: {str(e)}'})
        error_resp.headers['Content-Type'] = 'application/json'
        
        return error_resp, 500

@resource_bp.route('/api/resources/<int:resource_id>/allocations', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_VIEW_PROJECT)
def get_resource_allocations(resource_id):
    """获取资源分配列表"""
    try:
        resource = Resource.query.get_or_404(resource_id)
        allocations = ResourceAllocation.query.filter_by(resource_id=resource_id).all()
        return jsonify([allocation.to_dict() for allocation in allocations])
    except Exception as e:
        logger.error(f"Error getting resource allocations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@resource_bp.route('/api/allocations/pending', methods=['GET'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_RESOURCES)
def get_pending_allocations():
    """获取待审批的资源分配列表"""
    current_user_id = get_jwt_identity()
    
    # 检查权限
    if not current_user.has_role('manager'):
        return jsonify({'error': '没有权限查看待审批列表'}), 403
    
    pending_allocations = ResourceAllocation.query.filter_by(status='pending').all()
    return jsonify([allocation.to_dict() for allocation in pending_allocations])

@resource_bp.route('/api/resources/predictions/accuracy', methods=['GET'])
@jwt_required()
def get_prediction_accuracy():
    """获取预测准确度统计"""
    days = int(request.args.get('days', 7))  # 默认统计最近7天的预测准确度
    
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=days)
    
    # 获取预测和实际使用数据
    predictions = ResourcePrediction.query.filter(
        ResourcePrediction.date >= start_date,
        ResourcePrediction.date <= end_date
    ).all()
    
    accuracy_data = []
    for prediction in predictions:
        # 获取当天的实际使用数据
        utilization = ResourceUtilization.query.filter_by(
            resource_id=prediction.resource_id,
            date=prediction.date
        ).first()
        
        if utilization and utilization.actual_quantity is not None:
            actual = utilization.actual_quantity
            predicted = prediction.predicted_quantity
            error = abs(actual - predicted) / actual if actual > 0 else 0
            accuracy = 1 - error
            
            accuracy_data.append({
                'resource_id': prediction.resource_id,
                'resource_name': prediction.resource.name,
                'date': prediction.date.strftime('%Y-%m-%d'),
                'predicted': predicted,
                'actual': actual,
                'accuracy': accuracy,
                'confidence': prediction.confidence_level
            })
    
    return jsonify(accuracy_data)

@resource_bp.route('/api/resources/optimize', methods=['POST'])
@jwt_required()
def generate_optimizations():
    """生成资源优化建议"""
    try:
        # 获取所有资源
        resources = Resource.query.all()
        optimizations = []
        
        for resource in resources:
            # 1. 检查资源利用率
            if resource.utilization_rate < 50:
                # 低利用率建议
                optimization = ResourceOptimization(
                    resource_id=resource.id,
                    suggestion_type='utilization',
                    title=f'提高 {resource.name} 的利用率',
                    description=f'当前利用率仅为 {resource.utilization_rate:.1f}%，建议重新评估资源分配或考虑共享资源。',
                    impact='medium',
                    estimated_savings=resource.quantity * (50 - resource.utilization_rate) / 100 * resource.cost_per_unit if resource.cost_per_unit else None
                )
                optimizations.append(optimization)
            
            # 2. 检查资源分配冲突
            overlapping_allocations = ResourceAllocation.query.filter(
                ResourceAllocation.resource_id == resource.id,
                ResourceAllocation.status == 'approved'
            ).filter(
                ResourceAllocation.start_date <= datetime.now().date(),
                ResourceAllocation.end_date >= datetime.now().date()
            ).all()
            
            if len(overlapping_allocations) > 1:
                # 分配冲突建议
                optimization = ResourceOptimization(
                    resource_id=resource.id,
                    suggestion_type='allocation',
                    title=f'优化 {resource.name} 的分配计划',
                    description=f'当前有 {len(overlapping_allocations)} 个任务同时使用该资源，建议调整任务时间安排以减少冲突。',
                    impact='high',
                    estimated_savings=None
                )
                optimizations.append(optimization)
            
            # 3. 检查资源成本
            if resource.cost_per_unit and resource.quantity > 10:
                # 高成本资源建议
                optimization = ResourceOptimization(
                    resource_id=resource.id,
                    suggestion_type='cost',
                    title=f'降低 {resource.name} 的使用成本',
                    description=f'该资源单位成本较高，建议考虑替代方案或批量采购以降低成本。',
                    impact='high',
                    estimated_savings=resource.quantity * resource.cost_per_unit * 0.1  # 假设可以降低10%成本
                )
                optimizations.append(optimization)
        
        # 保存优化建议
        for optimization in optimizations:
            db.session.add(optimization)
        
        db.session.commit()
        return jsonify([opt.to_dict() for opt in optimizations]), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"生成优化建议失败: {str(e)}")
        return jsonify({'error': '生成优化建议失败'}), 500

@resource_bp.route('/api/resources/optimizations', methods=['GET'])
@jwt_required()
def get_optimizations():
    current_user = get_jwt_identity()
    optimizations = ResourceOptimization.query.filter_by(user_id=current_user).all()
    return jsonify([opt.to_dict() for opt in optimizations])

@resource_bp.route('/api/resources/optimizations/<int:optimization_id>', methods=['PUT'])
@jwt_required()
def update_optimization(optimization_id):
    """更新优化建议状态"""
    try:
        optimization = ResourceOptimization.query.get_or_404(optimization_id)
        data = request.get_json()
        
        if 'status' in data:
            optimization.status = data['status']
            db.session.commit()
        
        return jsonify(optimization.to_dict())
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"更新优化建议失败: {str(e)}")
        return jsonify({'error': '更新优化建议失败'}), 500

@resource_bp.route('/api/resources/cost-analysis', methods=['POST'])
@jwt_required()
def generate_cost_analysis():
    current_user = get_jwt_identity()
    data = request.get_json()
    start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
    end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
    
    # 获取指定日期范围内的资源分配和利用率数据
    allocations = ResourceAllocation.query.filter(
        ResourceAllocation.start_date <= end_date,
        ResourceAllocation.end_date >= start_date
    ).all()
    
    utilizations = ResourceUtilization.query.filter(
        ResourceUtilization.date >= start_date,
        ResourceUtilization.date <= end_date
    ).all()
    
    # 计算总成本和成本效率
    total_cost = 0
    cost_efficiency = 0
    resource_costs = {}
    
    for allocation in allocations:
        # 计算分配成本
        allocation_days = (min(allocation.end_date, end_date) - max(allocation.start_date, start_date)).days + 1
        allocation_cost = allocation.resource.cost_per_unit * allocation.allocated_quantity * allocation_days
        
        # 计算实际使用成本
        actual_cost = 0
        for utilization in utilizations:
            if utilization.resource_id == allocation.resource_id:
                actual_cost += utilization.resource.cost_per_unit * utilization.quantity
        
        # 计算成本效率
        if allocation_cost > 0:
            efficiency = actual_cost / allocation_cost
        else:
            efficiency = 0
        
        resource_costs[allocation.resource_id] = {
            'resource_name': allocation.resource.name,
            'allocation_cost': allocation_cost,
            'actual_cost': actual_cost,
            'efficiency': efficiency
        }
        
        total_cost += allocation_cost
        cost_efficiency += efficiency
    
    # 计算平均成本效率
    if len(resource_costs) > 0:
        cost_efficiency /= len(resource_costs)
    
    # 计算成本趋势
    cost_trends = []
    for i in range(7, 0, -1):
        date = datetime.now() - timedelta(days=i)
        day_allocations = [a for a in allocations if a.start_date <= date.date() <= a.end_date]
        day_utilizations = [u for u in utilizations if u.date == date.date()]
        
        day_cost = sum(a.resource.cost_per_unit * a.allocated_quantity for a in day_allocations)
        day_actual_cost = sum(u.resource.cost_per_unit * u.quantity for u in day_utilizations)
        
        if day_cost > 0:
            day_efficiency = day_actual_cost / day_cost
        else:
            day_efficiency = 0
        
        cost_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'allocation_cost': day_cost,
            'actual_cost': day_actual_cost,
            'efficiency': day_efficiency
        })
    
    # 保存成本分析结果
    cost_analysis = ResourceCostAnalysis(
        start_date=start_date,
        end_date=end_date,
        total_cost=total_cost,
        cost_efficiency=cost_efficiency,
        resource_costs=json.dumps(resource_costs),
        cost_trends=json.dumps(cost_trends)
    )
    
    db.session.add(cost_analysis)
    db.session.commit()
    
    return jsonify(cost_analysis.to_dict())

@resource_bp.route('/api/resources/cost-analysis', methods=['GET'])
@jwt_required()
def get_cost_analysis():
    current_user = get_jwt_identity()
    resource_id = request.args.get('resource_id', type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = ResourceCostAnalysis.query
    
    if resource_id:
        query = query.filter(ResourceCostAnalysis.resource_costs.like(f'%{resource_id}%'))
    if start_date:
        query = query.filter(ResourceCostAnalysis.start_date >= datetime.strptime(start_date, '%Y-%m-%d').date())
    if end_date:
        query = query.filter(ResourceCostAnalysis.end_date <= datetime.strptime(end_date, '%Y-%m-%d').date())
    
    analyses = query.order_by(ResourceCostAnalysis.created_at.desc()).all()
    return jsonify([analysis.to_dict() for analysis in analyses])

@resource_bp.route('/api/resources/cost-analysis/summary', methods=['GET'])
@jwt_required()
def get_cost_summary():
    current_user = get_jwt_identity()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = ResourceCostAnalysis.query
    
    if start_date:
        query = query.filter(ResourceCostAnalysis.start_date >= datetime.strptime(start_date, '%Y-%m-%d').date())
    if end_date:
        query = query.filter(ResourceCostAnalysis.end_date <= datetime.strptime(end_date, '%Y-%m-%d').date())
    
    analyses = query.all()
    
    if not analyses:
        return jsonify({
            'total_resources': 0,
            'total_cost': 0,
            'average_efficiency': 0,
            'cost_trend': 'stable'
        })
    
    # 计算总资源数和总成本
    total_resources = 0
    total_cost = 0
    total_efficiency = 0
    
    for analysis in analyses:
        resource_costs = json.loads(analysis.resource_costs)
        total_resources += len(resource_costs)
        total_cost += analysis.total_cost
        total_efficiency += analysis.cost_efficiency
    
    # 计算平均成本效率
    average_efficiency = total_efficiency / len(analyses) if analyses else 0
    
    # 分析成本趋势
    cost_trends = []
    for analysis in analyses:
        trends = json.loads(analysis.cost_trends)
        cost_trends.extend(trends)
    
    if len(cost_trends) >= 2:
        # 使用线性回归分析趋势
        x = np.arange(len(cost_trends))
        y = np.array([t['efficiency'] for t in cost_trends])
        slope, _, _ = simple_linear_regression(x, y)
        
        if slope > 0.1:
            trend = 'increasing'
        elif slope < -0.1:
            trend = 'decreasing'
        else:
            trend = 'stable'
    else:
        trend = 'stable'
    
    return jsonify({
        'total_resources': total_resources,
        'total_cost': total_cost,
        'average_efficiency': average_efficiency,
        'cost_trend': trend
    })

@resource_bp.route('/api/resources/efficiency', methods=['GET'])
@jwt_required()
def get_efficiency_analysis():
    try:
        resource_id = request.args.get('resource_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        query = ResourceEfficiency.query
        
        if resource_id:
            query = query.filter_by(resource_id=resource_id)
            
        if start_date and end_date:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d')
            query = query.filter(ResourceEfficiency.analysis_date.between(start, end))
            
        efficiencies = query.all()
        
        return jsonify([{
            'id': e.id,
            'resource_id': e.resource_id,
            'resource_name': e.resource.name,
            'allocation_efficiency': e.allocation_efficiency,
            'cost_efficiency': e.cost_efficiency,
            'efficiency_score': e.efficiency_score,
            'efficiency_trend': e.efficiency_trend,
            'analysis_date': e.analysis_date.strftime('%Y-%m-%d')
        } for e in efficiencies])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@resource_bp.route('/api/resources/efficiency/summary', methods=['GET'])
@jwt_required()
def get_efficiency_summary():
    current_user = get_jwt_identity()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = ResourceEfficiency.query
    
    if start_date and end_date:
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d')
        query = query.filter(ResourceEfficiency.analysis_date.between(start, end))
        
    efficiencies = query.all()
    
    if not efficiencies:
        return jsonify({'error': 'No efficiency data found'}), 404
        
    # 计算汇总统计
    total_resources = len(set(e.resource_id for e in efficiencies))
    avg_efficiency_score = np.mean([e.efficiency_score for e in efficiencies])
    avg_allocation_efficiency = np.mean([e.allocation_efficiency for e in efficiencies])
    avg_cost_efficiency = np.mean([e.cost_efficiency for e in efficiencies])
    
    # 计算效率趋势分布
    trend_distribution = {
        'improving': len([e for e in efficiencies if e.efficiency_trend == 'improving']),
        'stable': len([e for e in efficiencies if e.efficiency_trend == 'stable']),
        'declining': len([e for e in efficiencies if e.efficiency_trend == 'declining'])
    }
    
    return jsonify({
        'total_resources': total_resources,
        'avg_efficiency_score': avg_efficiency_score,
        'avg_allocation_efficiency': avg_allocation_efficiency,
        'avg_cost_efficiency': avg_cost_efficiency,
        'trend_distribution': trend_distribution
    })

def calculate_allocation_efficiency(allocation, utilization):
    """计算资源分配效率"""
    if allocation.allocated_hours == 0:
        return 0
    return min(utilization.actual_hours / allocation.allocated_hours, 1.0)

def calculate_cost_efficiency(allocation, utilization):
    """计算资源成本效率"""
    if allocation.allocated_cost == 0:
        return 0
    return min(allocation.allocated_cost / utilization.actual_cost, 1.0)

def calculate_efficiency_score(allocation_efficiency, cost_efficiency):
    """计算总体效率得分"""
    return (allocation_efficiency * 0.6 + cost_efficiency * 0.4) * 100

def calculate_efficiency_trend(resource_id, start_date, end_date):
    """计算资源效率趋势"""
    # 获取过去一周的效率数据
    week_ago = end_date - timedelta(days=7)
    efficiencies = ResourceEfficiency.query.filter(
        ResourceEfficiency.resource_id == resource_id,
        ResourceEfficiency.analysis_date.between(week_ago, end_date)
    ).order_by(ResourceEfficiency.analysis_date).all()
    
    if len(efficiencies) < 2:
        return 'stable'
        
    # 计算效率得分的变化趋势
    scores = [e.efficiency_score for e in efficiencies]
    slope, _, _ = simple_linear_regression(range(len(scores)), scores)
    
    if slope > 0.5:
        return 'improving'
    elif slope < -0.5:
        return 'declining'
    else:
        return 'stable'

@resource_bp.route('/api/resources/trends', methods=['POST'])
def generate_trend_analysis():
    """生成资源使用趋势分析"""
    try:
        data = request.get_json()
        start_date = datetime.strptime(data.get('start_date'), '%Y-%m-%d').date()
        end_date = datetime.strptime(data.get('end_date'), '%Y-%m-%d').date()
        
        # 获取所有资源
        resources = Resource.query.all()
        
        for resource in resources:
            # 获取指定日期范围内的使用数据
            utilizations = ResourceUtilization.query.filter(
                ResourceUtilization.resource_id == resource.id,
                ResourceUtilization.date.between(start_date, end_date)
            ).order_by(ResourceUtilization.date).all()
            
            if not utilizations:
                continue
                
            # 计算使用率趋势
            utilization_rates = [u.utilization_rate for u in utilizations]
            dates = [u.date for u in utilizations]
            
            # 使用线性回归分析趋势
            x = np.arange(len(utilization_rates))
            y = np.array(utilization_rates)
            slope, _, _ = simple_linear_regression(x, y)
            
            # 根据斜率判断趋势
            if slope > 0.1:
                trend = 'increasing'
            elif slope < -0.1:
                trend = 'decreasing'
            else:
                trend = 'stable'
            
            # 保存趋势数据
            trend = ResourceTrend(
                resource_id=resource.id,
                date=end_date,
                utilization_rate=utilization_rates[-1],
                trend=trend
            )
            db.session.add(trend)
        
        db.session.commit()
        return jsonify({'message': '趋势分析生成成功'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'生成趋势分析失败: {str(e)}')
        return jsonify({'error': '生成趋势分析失败'}), 500

@resource_bp.route('/api/resources/trends', methods=['GET'])
def get_trend_analysis():
    """获取资源使用趋势分析"""
    try:
        resource_id = request.args.get('resource_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        query = ResourceTrend.query
        
        if resource_id:
            query = query.filter(ResourceTrend.resource_id == resource_id)
        if start_date:
            query = query.filter(ResourceTrend.date >= start_date)
        if end_date:
            query = query.filter(ResourceTrend.date <= end_date)
            
        trends = query.order_by(ResourceTrend.date.desc()).all()
        return jsonify([trend.to_dict() for trend in trends]), 200
        
    except Exception as e:
        current_app.logger.error(f'获取趋势分析失败: {str(e)}')
        return jsonify({'error': '获取趋势分析失败'}), 500

@resource_bp.route('/api/resources/trends/summary', methods=['GET'])
def get_trend_summary():
    """获取资源使用趋势摘要"""
    try:
        # 获取最近30天的趋势数据
        end_date = datetime.utcnow().date()
        start_date = end_date - timedelta(days=30)
        
        trends = ResourceTrend.query.filter(
            ResourceTrend.date.between(start_date, end_date)
        ).all()
        
        # 按资源分组统计
        resource_trends = {}
        for trend in trends:
            if trend.resource_id not in resource_trends:
                resource_trends[trend.resource_id] = {
                    'resource_name': trend.resource_name,
                    'trends': []
                }
            resource_trends[trend.resource_id]['trends'].append(trend.to_dict())
        
        # 计算每个资源的趋势统计
        summary = []
        for resource_id, data in resource_trends.items():
            trends = data['trends']
            increasing_count = sum(1 for t in trends if t['trend'] == 'increasing')
            decreasing_count = sum(1 for t in trends if t['trend'] == 'decreasing')
            stable_count = sum(1 for t in trends if t['trend'] == 'stable')
            
            # 确定主要趋势
            if increasing_count > decreasing_count and increasing_count > stable_count:
                main_trend = 'increasing'
            elif decreasing_count > increasing_count and decreasing_count > stable_count:
                main_trend = 'decreasing'
            else:
                main_trend = 'stable'
            
            summary.append({
                'resource_id': resource_id,
                'resource_name': data['resource_name'],
                'main_trend': main_trend,
                'increasing_days': increasing_count,
                'decreasing_days': decreasing_count,
                'stable_days': stable_count,
                'latest_utilization': trends[0]['utilization_rate'] if trends else 0
            })
        
        return jsonify(summary), 200
        
    except Exception as e:
        current_app.logger.error(f'获取趋势摘要失败: {str(e)}')
        return jsonify({'error': '获取趋势摘要失败'}), 500

@resource_bp.route('/list')
@jwt_required()
def resource_list():
    """渲染资源列表页面"""
    try:
        current_user = get_jwt_identity()
        if not current_user:
            if request.accept_mimetypes.accept_json:
                return jsonify({'error': 'User not found'}), 404
            return render_template('error.html', error='User not found'), 404
            
        return render_template('resources.html', user_id=current_user)
    except Exception as e:
        logger.error(f"Error in resource_list: {str(e)}")
        if request.accept_mimetypes.accept_json:
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('error.html', error='Internal server error'), 500

@resource_bp.route('/resource-types', methods=['GET'])
@login_required
def get_resource_types():
    """获取资源类型列表"""
    try:
        resource_types = ResourceType.query.all()
        return jsonify([rt.to_dict() for rt in resource_types]), 200
    except Exception as e:
        logger.error(f"Error getting resource types: {str(e)}")
        return jsonify({'error': 'Failed to get resource types'}), 500

@resource_bp.route('/resource-types', methods=['POST'])
@login_required
def create_resource_type():
    """创建资源类型"""
    try:
        data = request.get_json()
        
        # 验证必要字段
        if 'name' not in data:
            return jsonify({'error': 'Missing required field: name'}), 400
            
        # 检查名称是否已存在
        if ResourceType.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'Resource type with this name already exists'}), 400
            
        # 创建资源类型
        resource_type = ResourceType(
            name=data['name'],
            description=data.get('description'),
            unit=data.get('unit')
        )
        
        db.session.add(resource_type)
        db.session.commit()
        
        logger.info(f"Resource type {resource_type.id} created by user {current_user.id}")
        return jsonify(resource_type.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating resource type: {str(e)}")
        return jsonify({'error': 'Failed to create resource type'}), 500

@resource_bp.route('/resource-types/<int:type_id>', methods=['PUT'])
@login_required
def update_resource_type(type_id):
    """更新资源类型"""
    try:
        resource_type = ResourceType.query.get_or_404(type_id)
        data = request.get_json()
        
        # 更新字段
        if 'name' in data:
            # 检查名称是否已存在
            existing = ResourceType.query.filter_by(name=data['name']).first()
            if existing and existing.id != type_id:
                return jsonify({'error': 'Resource type with this name already exists'}), 400
            resource_type.name = data['name']
        if 'description' in data:
            resource_type.description = data['description']
        if 'unit' in data:
            resource_type.unit = data['unit']
            
        db.session.commit()
        
        logger.info(f"Resource type {type_id} updated by user {current_user.id}")
        return jsonify(resource_type.to_dict()), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating resource type {type_id}: {str(e)}")
        return jsonify({'error': 'Failed to update resource type'}), 500

@resource_bp.route('/resource-types/<int:type_id>', methods=['DELETE'])
@login_required
def delete_resource_type(type_id):
    """删除资源类型"""
    try:
        resource_type = ResourceType.query.get_or_404(type_id)
        
        # 检查是否有资源使用此类型
        if Resource.query.filter_by(type_id=type_id).first():
            return jsonify({'error': 'Cannot delete resource type that is in use'}), 400
            
        db.session.delete(resource_type)
        db.session.commit()
        
        logger.info(f"Resource type {type_id} deleted by user {current_user.id}")
        return jsonify({'message': 'Resource type deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting resource type {type_id}: {str(e)}")
        return jsonify({'error': 'Failed to delete resource type'}), 500

@resource_bp.route('/api/resources/', methods=['GET'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
def get_resources_trailing_slash():
    """Redirect trailing slash requests to the canonical URL"""
    return get_resources()

@resource_bp.route('/api/resources/', methods=['POST'])
@jwt_required(locations=['headers', 'cookies', 'query_string'], optional=True)
@permission_required(PERMISSION_MANAGE_RESOURCES)
def create_resource_trailing_slash():
    """API endpoint with trailing slash to create a new resource"""
    return create_resource()

@resource_bp.route('/api/auth/resources', methods=['GET'])
@resource_bp.route('/api/auth/resources/', methods=['GET'])
def redirect_old_resources_endpoint():
    """将旧的API路径重定向到新的路径"""
    target = "/api/resources"
    # 保留所有查询参数
    if request.query_string:
        target = f"{target}?{request.query_string.decode('utf-8')}"
    logger.info(f"Redirecting from old API path to: {target}")
    return redirect(target, code=308)  # 使用308永久重定向

@resource_bp.route('/api/auth/resources/export', methods=['GET'])
def redirect_old_export_endpoint():
    """将旧的导出API路径重定向到新的路径"""
    target = "/api/resources/export"
    # 保留所有查询参数
    if request.query_string:
        target = f"{target}?{request.query_string.decode('utf-8')}"
    logger.info(f"Redirecting from old export API path to: {target}")
    return redirect(target, code=308)  # 使用308永久重定向

@resource_bp.route('/api/auth/resources/<int:resource_id>', methods=['GET', 'PUT', 'DELETE'])
def redirect_old_resource_detail_endpoint(resource_id):
    """将旧的资源详情API路径重定向到新的路径"""
    target = f"/api/resources/{resource_id}"
    # 保留所有查询参数
    if request.query_string:
        target = f"{target}?{request.query_string.decode('utf-8')}"
    logger.info(f"Redirecting from old resource detail API path to: {target}")
    return redirect(target, code=308)  # 使用308永久重定向 