from datetime import datetime
from app.extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask import current_app

# 角色-权限关联表
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True),
    info={'bind_key': None}
)

# 用户-角色关联表
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    info={'bind_key': None}
)

class Permission(db.Model):
    """权限模型"""
    __tablename__ = 'permissions'
    __table_args__ = {'info': {'bind_key': None}}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    roles = db.relationship('Role', secondary=role_permissions, back_populates='permissions')
    
    def __repr__(self):
        return f'<Permission {self.name}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id or '',
            'name': self.name or '',
            'description': self.description or '',
            'created_at': self.created_at.isoformat() if self.created_at else ''
        }

class Role(db.Model):
    """角色模型"""
    __tablename__ = 'roles'
    __table_args__ = {'info': {'bind_key': None}}
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates='roles')
    users = db.relationship('User', secondary=user_roles, back_populates='roles')
    
    def __repr__(self):
        return f'<Role {self.name}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id or '',
            'name': self.name or '',
            'description': self.description or '',
            'created_at': self.created_at.isoformat() if self.created_at else '',
            'permissions': [p.name for p in self.permissions] if self.permissions else []
        }
    
    def has_permission(self, permission_name):
        """检查角色是否有指定权限"""
        return any(p.name == permission_name for p in self.permissions)

class User(UserMixin, db.Model):
    """用户模型"""
    __tablename__ = 'users'
    __table_args__ = {'info': {'bind_key': None}}
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(64))
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # 关系
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assignee_id', back_populates='assignee')
    created_tasks = db.relationship('Task', foreign_keys='Task.created_by', back_populates='creator')
    task_logs = db.relationship('TaskLog', back_populates='user')
    task_comments = db.relationship('TaskComment', back_populates='user', lazy='dynamic')
    task_progress_changes = db.relationship('TaskProgressHistory', back_populates='user')
    progress_requests = db.relationship('TaskProgressApproval', foreign_keys='TaskProgressApproval.user_id', back_populates='user')
    progress_approvals = db.relationship('TaskProgressApproval', foreign_keys='TaskProgressApproval.approver_id', back_populates='approver')
    project_memberships = db.relationship('ProjectMember', back_populates='user', lazy='dynamic')
    owned_risks = db.relationship('Risk', back_populates='owner', lazy='dynamic')
    led_teams = db.relationship('Team', back_populates='leader', lazy='dynamic')
    team_memberships = db.relationship('TeamMember', back_populates='user', lazy='dynamic')
    team_messages = db.relationship('TeamMessage', back_populates='sender', lazy='dynamic')
    risk_mitigations = db.relationship('RiskMitigation', foreign_keys='RiskMitigation.assigned_to', back_populates='assignee', lazy='dynamic')
    resource_usages = db.relationship('ResourceUsage', back_populates='user', lazy='dynamic')
    owned_projects = db.relationship('Project', foreign_keys='Project.owner_id', back_populates='owner', lazy='dynamic')
    managed_projects = db.relationship('Project', foreign_keys='Project.manager_id', back_populates='manager', lazy='dynamic')
    
    def __init__(self, **kwargs):
        password = kwargs.pop('password', None)
        super(User, self).__init__(**kwargs)
        if password:
            self.set_password(password)
    
    def set_role(self, role):
        """设置用户角色"""
        self.roles = [role]
    
    def get_role(self):
        """获取用户角色"""
        return self.roles[0] if self.roles else None
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """设置密码"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        """检查用户是否有指定角色"""
        return any(role.name == role_name for role in self.roles)
    
    def to_dict(self):
        """转换为字典"""
        # 获取角色和权限信息
        roles = [role.name for role in self.roles] if self.roles else []
        permissions = []
        if self.roles:
            for role in self.roles:
                if role.permissions:
                    permissions.extend([perm.name for perm in role.permissions])
        
        # 去重权限列表
        permissions = list(set(permissions))
        
        # 构建用户字典
        user_dict = {
            'id': self.id or '',
            'username': self.username or '',
            'email': self.email or '',
            'name': self.name or '',
            'is_active': self.is_active if self.is_active is not None else True,
            'created_at': self.created_at.isoformat() if self.created_at else '',
            'last_login': self.last_login.isoformat() if self.last_login else '',
            'roles': roles,
            'permissions': permissions
        }
        
        return user_dict
    
    def has_permission(self, permission_name):
        """检查用户是否有指定权限"""
        return any(role.has_permission(permission_name) for role in self.roles)

class TokenBlacklist(db.Model):
    """Token黑名单模型"""
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)  # JWT ID
    token_type = db.Column(db.String(10), nullable=False)  # access/refresh
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # 关系
    user = db.relationship('User', backref=db.backref('blacklisted_tokens', lazy='dynamic'))
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'
    
    def to_dict(self):
        """转换为字典"""
        return {
            'id': self.id or '',
            'jti': self.jti or '',
            'token_type': self.token_type or '',
            'user_id': self.user_id or '',
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else '',
            'expires_at': self.expires_at.isoformat() if self.expires_at else ''
        }

    @classmethod
    def is_blacklisted(cls, jti):
        """检查token是否在黑名单中"""
        return cls.query.filter_by(jti=jti).first() is not None
    
    @classmethod
    def revoke_token(cls, jti, token_type, user_id, expires_at):
        """将token加入黑名单"""
        blacklisted_token = cls(jti=jti, token_type=token_type, user_id=user_id, expires_at=expires_at)
        db.session.add(blacklisted_token)
        db.session.commit()
    
    @classmethod
    def cleanup_expired_tokens(cls):
        """清理过期的黑名单token"""
        expired = cls.query.filter(cls.expires_at < datetime.utcnow()).all()
        for token in expired:
            db.session.delete(token)
        db.session.commit() 