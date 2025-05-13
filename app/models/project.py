from datetime import datetime
from app.extensions import db
from app.models.auth import User

class Project(db.Model):
    """Project model"""
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')  # active, completed, cancelled
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    progress = db.Column(db.Integer, default=0)  # 新增：项目进度（0-100）
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    manager_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    tasks = db.relationship('Task', back_populates='project', lazy='dynamic')
    members = db.relationship('ProjectMember', back_populates='project', lazy='dynamic')
    risks = db.relationship('Risk', back_populates='project', lazy='dynamic')
    resource_utilizations = db.relationship('ResourceUtilization', back_populates='project', lazy='dynamic')
    manager = db.relationship('User', foreign_keys=[manager_id], back_populates='managed_projects')
    owner = db.relationship('User', foreign_keys=[owner_id], back_populates='owned_projects')
    teams = db.relationship('Team', back_populates='project', lazy='dynamic')
    
    def to_dict(self):
        """将项目对象转换为字典"""
        manager = User.query.get(self.manager_id) if self.manager_id else None
        
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'progress': self.progress or 0,
            'start_date': self.start_date.strftime('%Y-%m-%d') if self.start_date else None,
            'end_date': self.end_date.strftime('%Y-%m-%d') if self.end_date else None,
            'manager_id': self.manager_id,
            'manager_name': manager.name if manager else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<Project {self.name}>'
        
    def is_accessible_by(self, user_id):
        """检查用户是否有权限访问该项目"""
        # 项目创建者、所有者或管理员有权限访问
        if self.owner_id == user_id or self.manager_id == user_id:
            return True
            
        # 检查用户是否是项目团队成员
        for team in self.teams:
            for member in team.members:
                if member.user_id == user_id:
                    return True
        
        # 默认不允许访问
        return False
        
    def calculate_progress(self):
        """计算项目的整体进度"""
        tasks = self.tasks.all()
        if not tasks:
            return 0
            
        total_progress = sum(task.progress for task in tasks)
        project_progress = round(total_progress / len(tasks))
        
        return project_progress

class ProjectMember(db.Model):
    """Project member model"""
    __tablename__ = 'project_members'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # project_manager, team_leader, member
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project = db.relationship('Project', back_populates='members')
    user = db.relationship('User', back_populates='project_memberships')
    
    def to_dict(self):
        return {
            'id': self.id,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user': self.user.to_dict() if self.user else None
        }
    
    def __repr__(self):
        return f'<ProjectMember {self.user_id} in {self.project_id}>' 