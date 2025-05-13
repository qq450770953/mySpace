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
        # 如果是admin用户，自动确保admin角色存在
        if self.username == 'admin' or kwargs.get('id') == 1:
            self.ensure_admin_role()
    
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
        # admin用户或ID为1的用户始终有admin角色
        if role_name == 'admin' and (self.username == 'admin' or self.id == 1):
            return True
            
        return any(role.name == role_name for role in self.roles)
    
    def to_dict(self):
        """将用户对象转换为字典，用于API返回"""
        # 确保获取用户角色数据
        user_roles = [role.name for role in self.roles] if self.roles else []
        
        # 记录转换过程中的角色信息
        print(f"[User.to_dict] 用户 {self.username} (ID: {self.id}) 角色: {user_roles}")
        
        # 特殊处理admin用户，确保有admin角色
        if self.username == 'admin' or self.id == 1:
            if 'admin' not in user_roles:
                user_roles.append('admin')
                print(f"[User.to_dict] 为admin用户添加admin角色，更新后: {user_roles}")
        
        # 获取用户所有权限
        try:
            all_permissions = self.get_all_permissions() if hasattr(self, 'get_all_permissions') else []
            permissions = [perm.name for perm in all_permissions]
            print(f"[User.to_dict] 用户 {self.username} 权限: {permissions}")
        except Exception as e:
            print(f"[User.to_dict] 获取权限出错: {e}")
            permissions = []
        
        # 创建基本用户数据字典
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': self.email or '',
            'name': self.name or self.username,
            'is_active': self.is_active if self.is_active is not None else True,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'roles': user_roles,  # 始终是数组
            'permissions': permissions,  # 始终是数组
            'is_admin': False  # 默认为False，下面会检查并设置
        }
        
        # 明确设置is_admin标志
        if 'admin' in user_roles or self.username == 'admin' or self.id == 1:
            user_dict['is_admin'] = True
            print(f"[User.to_dict] 用户 {self.username} 被标记为管理员")
        
        print(f"[User.to_dict] 最终用户数据: id={user_dict['id']}, username={user_dict['username']}, roles={user_dict['roles']}, is_admin={user_dict['is_admin']}")
        return user_dict
    
    def has_permission(self, permission_name):
        """检查用户是否有指定权限"""
        return any(role.has_permission(permission_name) for role in self.roles)
        
    def get_all_permissions(self):
        """获取用户的所有权限"""
        print(f"[User.get_all_permissions] 开始获取用户 {self.username} 的所有权限")
        
        # 收集所有权限
        permissions = []
        if self.roles:
            for role in self.roles:
                if role.permissions:
                    for perm in role.permissions:
                        if perm not in permissions:
                            permissions.append(perm)
            print(f"[User.get_all_permissions] 从角色中收集到 {len(permissions)} 个权限")
        
        # 如果用户是admin，添加所有权限
        if self.username == 'admin' or self.id == 1:
            try:
                from app.utils.permissions import ROLE_PERMISSIONS, ROLE_ADMIN
                admin_permissions = ROLE_PERMISSIONS.get(ROLE_ADMIN, [])
                print(f"[User.get_all_permissions] Admin权限列表: {admin_permissions}")
                
                # 获取所有权限对象
                from app.models.auth import Permission
                for perm_name in admin_permissions:
                    perm = Permission.query.filter_by(name=perm_name).first()
                    if perm and perm not in permissions:
                        permissions.append(perm)
            except Exception as e:
                print(f"[User.get_all_permissions] 获取admin权限出错: {e}")
        
        print(f"[User.get_all_permissions] 用户 {self.username} 最终权限数量: {len(permissions)}")
        return permissions

    def ensure_admin_role(self):
        """确保admin用户拥有admin角色"""
        try:
            # 查找admin角色
            from app import db
            admin_role = Role.query.filter_by(name='admin').first()
            
            if not admin_role:
                print(f"[User.ensure_admin_role] admin角色不存在，创建新角色")
                # 如果admin角色不存在，创建它
                admin_role = Role(name='admin', description='Administrator')
                db.session.add(admin_role)
                
            # 检查用户是否已有此角色
            has_role = False
            if self.roles:
                for role in self.roles:
                    if role.name == 'admin':
                        has_role = True
                        break
                        
            # 如果没有admin角色，添加它
            if not has_role:
                print(f"[User.ensure_admin_role] 为用户 {self.username} 添加admin角色")
                self.roles.append(admin_role)
                
            return True
        except Exception as e:
            print(f"[User.ensure_admin_role] 确保admin角色出错: {str(e)}")
            return False

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