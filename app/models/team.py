from datetime import datetime
from app.extensions import db
from sqlalchemy import event
from app.models.resource import ResourceAllocation

class Team(db.Model):
    """Team model"""
    __tablename__ = 'teams'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    leader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    project = db.relationship('Project', back_populates='teams')
    leader = db.relationship('User', back_populates='led_teams')
    members = db.relationship('TeamMember', back_populates='team', cascade='all, delete-orphan')
    messages = db.relationship('TeamMessage', back_populates='team', cascade='all, delete-orphan')
    tasks = db.relationship('Task', back_populates='team', lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'project_id': self.project_id,
            'leader_id': self.leader_id,
            'leader': self.leader.to_dict() if self.leader else None,
            'members': [member.to_dict() for member in self.members],
            'message_count': len(self.messages)
        }
    
    def __repr__(self):
        return f'<Team {self.name}>'

class TeamMember(db.Model):
    """Team member model"""
    __tablename__ = 'team_members'
    
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    team = db.relationship('Team', back_populates='members')
    user = db.relationship('User', back_populates='team_memberships')
    
    def to_dict(self):
        return {
            'id': self.id,
            'role': self.role,
            'joined_at': self.joined_at.isoformat() if self.joined_at else None,
            'team_id': self.team_id,
            'user_id': self.user_id,
            'user': self.user.to_dict() if self.user else None
        }
    
    def __repr__(self):
        return f'<TeamMember {self.user.username} in {self.team.name}>'

class TeamMessage(db.Model):
    """Team message model"""
    __tablename__ = 'team_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    team = db.relationship('Team', back_populates='messages')
    sender = db.relationship('User', back_populates='team_messages')
    
    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'team_id': self.team_id,
            'sender_id': self.sender_id,
            'sender': self.sender.to_dict() if self.sender else None
        }
    
    def __repr__(self):
        return f'<TeamMessage from {self.sender.username} in {self.team.name}>'

class TeamNotification(db.Model):
    """团队通知模型"""
    __tablename__ = 'team_notifications'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(20), default='info')  # info, warning, error
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    project = db.relationship('Project', backref=db.backref('team_notifications', lazy='dynamic'))
    user = db.relationship('User', backref=db.backref('team_notifications', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'title': self.title,
            'content': self.content,
            'notification_type': self.notification_type,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat()
        }

# 事件监听器
@event.listens_for(TeamMember, 'after_update')
def update_workload(mapper, connection, target):
    """更新团队成员工作负载"""
    if target.workload > 100:
        target.workload = 100
    elif target.workload < 0:
        target.workload = 0 