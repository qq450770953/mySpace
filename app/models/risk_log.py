from datetime import datetime
from app import db

class RiskLog(db.Model):
    __tablename__ = 'risk_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # created, updated, closed, etc.
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    risk = db.relationship('Risk', back_populates='logs')
    user = db.relationship('User', backref=db.backref('risk_logs', lazy='dynamic'))
    
    def __repr__(self):
        return f'<RiskLog {self.action} on Risk {self.risk_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'risk_id': self.risk_id,
            'user_id': self.user_id,
            'action': self.action,
            'details': self.details,
            'created_at': self.created_at.isoformat()
        } 