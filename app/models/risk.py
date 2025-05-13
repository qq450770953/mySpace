from app.extensions import db
from datetime import datetime

class Risk(db.Model):
    """Risk model"""
    __tablename__ = 'risks'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')
    severity = db.Column(db.String(20), nullable=False)
    probability = db.Column(db.String(20), nullable=False)
    impact = db.Column(db.String(20), nullable=False)
    mitigation_plan = db.Column(db.Text)
    contingency_plan = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    
    # Relationships
    project = db.relationship('Project', back_populates='risks')
    owner = db.relationship('User', back_populates='owned_risks')
    task = db.relationship('Task', back_populates='risks')
    mitigations = db.relationship('RiskMitigation', back_populates='risk', lazy='dynamic', cascade='all, delete-orphan')
    logs = db.relationship('RiskLog', back_populates='risk', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Risk {self.title}>'
    
    def to_dict(self, include_relationships=False):
        """转换为字典表示"""
        risk_dict = {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'probability': self.probability,
            'impact': self.impact,
            'severity': self.severity,
            'risk_level': self.risk_level,
            'mitigation_plan': self.mitigation_plan,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'task_id': self.task_id,
            'project_id': self.project_id,
            'owner_id': self.owner_id
        }
        
        # 添加关联对象数据
        if include_relationships:
            risk_dict.update({
                'task': self.task.to_dict() if self.task else None,
                'project': self.project.to_dict() if self.project else None,
                'owner': self.owner.to_dict() if self.owner else None,
                'logs_count': self.logs.count() if hasattr(self, 'logs') else 0
            })
            
        return risk_dict

    # 风险级别计算属性
    @property
    def risk_level(self):
        """计算风险级别 - 基于概率和影响的组合"""
        # 风险级别映射：低、中、高
        risk_matrix = {
            # 概率: { 影响: 风险级别 }
            'low': {
                'low': 'low',
                'medium': 'low',
                'high': 'medium'
            },
            'medium': {
                'low': 'low',
                'medium': 'medium',
                'high': 'high'
            },
            'high': {
                'low': 'medium',
                'medium': 'high',
                'high': 'high'
            }
        }
        
        prob = self.probability.lower() if self.probability else 'medium'
        impact = self.impact.lower() if self.impact else 'medium'
        
        # 如果概率或影响不在矩阵中，使用默认值
        if prob not in risk_matrix:
            prob = 'medium'
        if impact not in risk_matrix[prob]:
            impact = 'medium'
            
        return risk_matrix[prob][impact]

class RiskLog(db.Model):
    """风险日志模型"""
    __tablename__ = 'risk_logs'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # 关系
    risk = db.relationship('Risk', back_populates='logs')
    user = db.relationship('User', backref='risk_logs')
    
    def __repr__(self):
        return f'<RiskLog {self.id}>'

class RiskMitigation(db.Model):
    """风险缓解措施模型"""
    __tablename__ = 'risk_mitigations'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, in-progress, completed
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    due_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关系
    assignee = db.relationship('User', back_populates='risk_mitigations')
    risk = db.relationship('Risk', back_populates='mitigations')
    
    def __repr__(self):
        return f'<RiskMitigation {self.id}>'
        
    def to_dict(self):
        return {
            'id': self.id,
            'risk_id': self.risk_id,
            'description': self.description,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        } 