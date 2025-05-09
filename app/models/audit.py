from datetime import datetime
from app.extensions import db

class AuditLog(db.Model):
    """审计日志模型"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # 操作类型
    resource_type = db.Column(db.String(50), nullable=False)  # 资源类型
    resource_id = db.Column(db.Integer, nullable=True)  # 资源ID
    details = db.Column(db.Text, nullable=True)  # 详细信息
    ip_address = db.Column(db.String(50), nullable=True)  # IP地址
    user_agent = db.Column(db.String(255), nullable=True)  # 用户代理
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    user = db.relationship('User', backref=db.backref('audit_logs', lazy='dynamic'))
    
    def __repr__(self):
        return f'<AuditLog {self.action} {self.resource_type}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None
        } 