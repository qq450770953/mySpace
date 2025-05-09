from datetime import datetime
from app.extensions import db
import json

class ResourceUsage(db.Model):
    """资源使用情况模型"""
    __tablename__ = 'resource_usages'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cpu_usage = db.Column(db.Float)  # CPU usage percentage
    memory_usage = db.Column(db.Float)  # Memory usage percentage
    disk_usage = db.Column(db.Float)  # Disk usage percentage
    network_usage = db.Column(db.Float)  # Network usage in MB
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship
    user = db.relationship('User', back_populates='resource_usages')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'network_usage': self.network_usage,
            'recorded_at': self.recorded_at.isoformat()
        }

class UserWorkload(db.Model):
    """用户工作量模型"""
    __tablename__ = 'user_workloads'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_tasks = db.Column(db.Integer, default=0)
    completed_tasks = db.Column(db.Integer, default=0)
    in_progress_tasks = db.Column(db.Integer, default=0)
    overdue_tasks = db.Column(db.Integer, default=0)
    workload_score = db.Column(db.Float)  # Calculated workload score
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'total_tasks': self.total_tasks,
            'completed_tasks': self.completed_tasks,
            'in_progress_tasks': self.in_progress_tasks,
            'overdue_tasks': self.overdue_tasks,
            'workload_score': self.workload_score,
            'recorded_at': self.recorded_at.isoformat()
        }

class SystemAlert(db.Model):
    """系统告警模型"""
    __tablename__ = 'system_alerts'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # resource, performance, security
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    message = db.Column(db.Text, nullable=False)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'message': self.message,
            'is_resolved': self.is_resolved,
            'created_at': self.created_at.isoformat(),
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }

class ResourceType(db.Model):
    """资源类型模型"""
    __tablename__ = 'resource_types'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.Text)
    unit = db.Column(db.String(32), nullable=False)  # 计量单位
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Update relationship
    resources = db.relationship('Resource', back_populates='type', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'unit': self.unit,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Resource(db.Model):
    """资源模型"""
    __tablename__ = 'resources'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    type_id = db.Column(db.Integer, db.ForeignKey('resource_types.id'), nullable=False)
    capacity = db.Column(db.Float, nullable=False, default=1.0)
    unit = db.Column(db.String(32))  # e.g., hours, pieces, etc.
    cost_per_unit = db.Column(db.Float)
    status = db.Column(db.String(32), nullable=False, default='available')  # available, in_use, maintenance, retired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Update relationships
    type = db.relationship('ResourceType', back_populates='resources')
    allocations = db.relationship('ResourceAllocation', back_populates='resource', cascade='all, delete-orphan')
    tasks = db.relationship('Task', secondary='resource_allocations', back_populates='resources', viewonly=True, overlaps="resource_allocations")
    predictions = db.relationship('ResourcePrediction', back_populates='resource', lazy='dynamic')
    alerts = db.relationship('ResourceAlert', back_populates='resource', lazy='dynamic')
    optimizations = db.relationship('ResourceOptimization', back_populates='resource', lazy='dynamic')
    reports = db.relationship('ResourceReport', back_populates='resource', lazy='dynamic')
    utilizations = db.relationship('ResourceUtilization', back_populates='resource', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'type_id': self.type_id,
            'capacity': self.capacity,
            'unit': self.unit,
            'cost_per_unit': self.cost_per_unit,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ResourceAllocation(db.Model):
    """资源分配模型"""
    __tablename__ = 'resource_allocations'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(32), nullable=False, default='pending')  # pending, active, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Update relationships
    resource = db.relationship('Resource', back_populates='allocations')
    task = db.relationship('Task', back_populates='resource_allocations')
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'task_id': self.task_id,
            'quantity': self.quantity,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ResourceUtilization(db.Model):
    """资源使用率模型"""
    __tablename__ = 'resource_utilizations'
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    utilized_quantity = db.Column(db.Integer, nullable=False, default=1)
    utilization_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='active')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Update relationships
    resource = db.relationship('Resource', back_populates='utilizations')
    project = db.relationship('Project', back_populates='resource_utilizations')
    task = db.relationship('Task', back_populates='resource_utilizations')
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'project_id': self.project_id,
            'task_id': self.task_id,
            'utilized_quantity': self.utilized_quantity,
            'utilization_date': self.utilization_date.isoformat() if self.utilization_date else None,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ResourcePrediction(db.Model):
    """资源预测模型"""
    __tablename__ = 'resource_predictions'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    predicted_usage = db.Column(db.Float, nullable=False)
    confidence_level = db.Column(db.Float)
    prediction_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Update relationship
    resource = db.relationship('Resource', back_populates='predictions')
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'predicted_usage': self.predicted_usage,
            'confidence_level': self.confidence_level,
            'prediction_date': self.prediction_date.isoformat() if self.prediction_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ResourceAlert(db.Model):
    """资源告警模型"""
    __tablename__ = 'resource_alerts'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    alert_type = db.Column(db.String(32), nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Update relationship
    resource = db.relationship('Resource', back_populates='alerts')
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'message': self.message,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }

class ResourceOptimization(db.Model):
    """资源优化建议模型"""
    __tablename__ = 'resource_optimizations'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    optimization_type = db.Column(db.String(32), nullable=False)
    suggestion = db.Column(db.Text, nullable=False)
    potential_savings = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    implemented_at = db.Column(db.DateTime)
    
    # Update relationship
    resource = db.relationship('Resource', back_populates='optimizations')
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'optimization_type': self.optimization_type,
            'suggestion': self.suggestion,
            'potential_savings': self.potential_savings,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'implemented_at': self.implemented_at.isoformat() if self.implemented_at else None
        }

class ResourceReport(db.Model):
    """资源报告模型"""
    __tablename__ = 'resource_reports'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'), nullable=False)
    report_type = db.Column(db.String(32), nullable=False)
    content = db.Column(db.Text, nullable=False)
    report_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Update relationship
    resource = db.relationship('Resource', back_populates='reports')
    
    def to_dict(self):
        return {
            'id': self.id,
            'resource_id': self.resource_id,
            'report_type': self.report_type,
            'content': self.content,
            'report_date': self.report_date.isoformat() if self.report_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ResourceCostAnalysis(db.Model):
    """资源成本分析模型"""
    __tablename__ = 'resource_cost_analyses'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'))
    period = db.Column(db.String(32), nullable=False)  # 日/周/月
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    total_cost = db.Column(db.Float, default=0.0)
    average_cost = db.Column(db.Float, default=0.0)
    cost_trend = db.Column(db.String(32))  # 上升/下降/稳定
    
    def __repr__(self):
        return f'<ResourceCostAnalysis {self.id}>'

class ResourceEfficiency(db.Model):
    """资源效率模型"""
    __tablename__ = 'resource_efficiencies'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'))
    date = db.Column(db.Date, nullable=False)
    efficiency_score = db.Column(db.Float)  # 0-100
    utilization_rate = db.Column(db.Float)  # 0-100%
    cost_efficiency = db.Column(db.Float)  # 产出/成本
    
    def __repr__(self):
        return f'<ResourceEfficiency {self.id}>'

class ResourceTrend(db.Model):
    """资源趋势模型"""
    __tablename__ = 'resource_trends'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resources.id'))
    metric = db.Column(db.String(32), nullable=False)  # 使用率/成本/效率
    period = db.Column(db.String(32), nullable=False)  # 日/周/月
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    trend_data = db.Column(db.JSON)
    trend_direction = db.Column(db.String(32))  # 上升/下降/稳定
    
    def __repr__(self):
        return f'<ResourceTrend {self.id}>' 