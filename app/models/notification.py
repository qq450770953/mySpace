from datetime import datetime
from app.extensions import db

class Notification(db.Model):
    """通知模型"""
    __tablename__ = 'notifications'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text)
    notification_type = db.Column(db.String(50))  # task, risk, system
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Notification {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'content': self.content,
            'type': self.notification_type,
            'status': 'read' if self.is_read else 'unread',
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } 