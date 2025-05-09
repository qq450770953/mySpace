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
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'severity': self.severity,
            'probability': self.probability,
            'impact': self.impact,
            'mitigation_plan': self.mitigation_plan,
            'contingency_plan': self.contingency_plan,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'project_id': self.project_id,
            'owner_id': self.owner_id,
            'task_id': self.task_id,
            'owner': self.owner.to_dict() if self.owner else None
        }
    
    def __repr__(self):
        return f'<Risk {self.title}>'

class RiskLog(db.Model):
    """风险日志模型"""
    __tablename__ = 'risk_logs'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    risk = db.relationship('Risk', back_populates='logs')
    
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