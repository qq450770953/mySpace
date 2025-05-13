from datetime import datetime
from app.extensions import db
from sqlalchemy import event
from app.models.risk import Risk
from app.models.attachment import TaskAttachment
from app.models.auth import User
from app.models.project import Project

class Task(db.Model):
    """Task model"""
    __tablename__ = 'tasks'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, completed, cancelled
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, urgent
    progress = db.Column(db.Integer, nullable=False, default=0)  # 0-100
    start_date = db.Column(db.Date)  # 添加开始日期字段
    due_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'))
    parent_id = db.Column(db.Integer, db.ForeignKey('tasks.id', name='fk_task_parent'))
    
    # Relationships
    project = db.relationship('Project', back_populates='tasks')
    assignee = db.relationship('User', foreign_keys=[assignee_id], back_populates='assigned_tasks')
    creator = db.relationship('User', foreign_keys=[created_by], back_populates='created_tasks')
    team = db.relationship('Team', back_populates='tasks')
    parent = db.relationship('Task', backref=db.backref('children', lazy='dynamic'), remote_side=[id])
    
    logs = db.relationship('TaskLog', back_populates='task', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('TaskComment', back_populates='task', lazy='dynamic', cascade='all, delete-orphan')
    progress_history = db.relationship('TaskProgressHistory', back_populates='task', lazy='dynamic', cascade='all, delete-orphan')
    progress_approvals = db.relationship('TaskProgressApproval', back_populates='task', lazy='dynamic', cascade='all, delete-orphan')
    risks = db.relationship('Risk', back_populates='task', lazy='dynamic', cascade='all, delete-orphan')
    resource_allocations = db.relationship('ResourceAllocation', back_populates='task', lazy='dynamic', cascade='all, delete-orphan')
    resources = db.relationship('Resource', secondary='resource_allocations', back_populates='tasks', lazy='dynamic', viewonly=True, overlaps="resource_allocations")
    resource_utilizations = db.relationship('ResourceUtilization', back_populates='task', lazy='dynamic')
    
    dependencies = db.relationship('TaskDependency',
                                 foreign_keys='TaskDependency.task_id',
                                 back_populates='task',
                                 lazy='dynamic',
                                 cascade='all, delete-orphan')
    dependents = db.relationship('TaskDependency',
                               foreign_keys='TaskDependency.dependent_id',
                               back_populates='dependent',
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Task {self.title}>'
    
    def to_dict(self, include_relationships=False, include_details=False):
        """Convert task to dictionary representation"""
        task_dict = {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'priority': self.priority,
            'progress': self.progress,
            'start_date': self.start_date.isoformat() if self.start_date else None,  # 添加开始日期字段
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'project_id': self.project_id,
            'assignee_id': self.assignee_id,
            'created_by': self.created_by,
            'team_id': self.team_id,
        }
        
        # 增加关联关系数据，需要包含关系数据时
        if include_relationships:
            task_dict.update({
                'project': self.project.to_dict() if self.project else None,
                'assignee': self.assignee.to_dict() if self.assignee else None,
                'creator': self.creator.to_dict() if self.creator else None,
                'team': self.team.to_dict() if self.team else None,
            })
            
        # 增加统计数据，需要包含详细数据时
        if include_details:
            task_dict.update({
                'logs_count': self.logs.count(),
                'comments_count': self.comments.count(),
                'risks_count': self.risks.count(),
                'resources_count': self.resources.count() if hasattr(self, 'resources') else 0,
                'dependencies_count': self.dependencies.count() if hasattr(self, 'dependencies') else 0,
                'dependents_count': self.dependents.count() if hasattr(self, 'dependents') else 0
            })
        
        return task_dict
    
    def calculate_progress(self):
        """计算任务进度"""
        # 如果有子任务，根据子任务进度计算
        if hasattr(self, 'subtasks') and self.subtasks:
            total_progress = sum(subtask.progress for subtask in self.subtasks)
            self.progress = round(total_progress / len(self.subtasks))
        # 如果没有子任务，检查依赖任务
        elif hasattr(self, 'dependencies') and self.dependencies:
            # 获取所有前置任务的进度
            predecessor_progress = []
            for dep in self.dependencies:
                if dep.dependency_type in ['finish-to-start', 'finish-to-finish']:
                    predecessor_progress.append(dep.dependent.progress)
            
            if predecessor_progress:
                # 如果所有前置任务都完成，则任务可以开始
                if all(p == 100 for p in predecessor_progress):
                    self.progress = max(0, self.progress)  # 保持当前进度或从0开始
                else:
                    # 前置任务未完成，进度不能超过前置任务的最小进度
                    self.progress = min(self.progress, min(predecessor_progress))
        
        # 更新父任务进度
        if hasattr(self, 'parent') and self.parent:
            self.parent.calculate_progress()
        
        return self.progress

    def update_progress(self, new_progress, user_id=None, change_reason=None):
        """更新任务进度并记录历史"""
        if new_progress < 0:
            new_progress = 0
        elif new_progress > 100:
            new_progress = 100
            
        # 记录进度变更历史
        if user_id:
            history = TaskProgressHistory(
                task_id=self.id,
                user_id=user_id,
                progress=new_progress,
                previous_progress=self.progress,
                change_reason=change_reason
            )
            db.session.add(history)
        
        self.progress = new_progress
        
        # 更新状态
        if new_progress == 100:
            self.status = 'completed'
        elif new_progress > 0:
            self.status = 'in_progress'
        else:
            self.status = 'todo'
        
        # 触发父任务进度计算
        if hasattr(self, 'parent') and self.parent:
            self.parent.calculate_progress()
        
        # 触发依赖任务的进度计算
        if hasattr(self, 'dependents'):
            for dep in self.dependents:
                dep.task.calculate_progress()
        
        return self.progress

    @classmethod
    def recalculate_all_progress(cls):
        """重新计算所有任务的进度"""
        # 获取所有没有子任务的任务（叶子任务）
        leaf_tasks = cls.query.filter(~cls.subtasks.any()).all()
        
        # 从叶子任务开始向上计算
        for task in leaf_tasks:
            if task.parent:
                task.parent.calculate_progress()

    def analyze_risks(self):
        """分析任务风险"""
        risks = []
        
        # 检查时间风险
        if self.end_date and self.start_date:
            days_left = (self.end_date - datetime.utcnow()).days
            if days_left < 0:
                risks.append({
                    'title': '任务已逾期',
                    'description': f'任务已逾期 {abs(days_left)} 天',
                    'probability': 5,
                    'impact': 5,
                    'mitigation_plan': '立即处理并更新截止日期'
                })
            elif days_left < 3:
                risks.append({
                    'title': '任务即将到期',
                    'description': f'任务将在 {days_left} 天内到期',
                    'probability': 4,
                    'impact': 4,
                    'mitigation_plan': '优先处理并确保按时完成'
                })
        
        # 检查进度风险
        if self.progress < 50 and self.end_date:
            days_passed = (datetime.utcnow() - self.start_date).days
            total_days = (self.end_date - self.start_date).days
            if days_passed > total_days * 0.5:
                risks.append({
                    'title': '进度滞后',
                    'description': f'任务已进行 {days_passed} 天，但进度仅为 {self.progress}%',
                    'probability': 4,
                    'impact': 4,
                    'mitigation_plan': '增加资源投入或调整任务计划'
                })
        
        # 检查依赖风险
        if hasattr(self, 'dependencies') and self.dependencies:
            blocked_deps = [dep for dep in self.dependencies if dep.status != 'completed']
            if blocked_deps:
                risks.append({
                    'title': '依赖任务未完成',
                    'description': f'有 {len(blocked_deps)} 个依赖任务未完成',
                    'probability': 3,
                    'impact': 4,
                    'mitigation_plan': '协调依赖任务负责人优先处理'
                })
        
        return risks

    def check_risk_thresholds(self):
        """检查风险阈值"""
        risks = self.analyze_risks()
        high_risks = [r for r in risks if r['probability'] * r['impact'] >= 16]
        return high_risks

class TaskDependency(db.Model):
    """Task dependency model"""
    __tablename__ = 'task_dependencies'
    __table_args__ = (
        db.UniqueConstraint('task_id', 'dependent_id', name='unique_dependency'),
        {'extend_existing': True}
    )
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    dependent_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    dependency_type = db.Column(db.String(20), nullable=False)  # finish-to-start, start-to-start, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    task = db.relationship('Task', foreign_keys=[task_id], back_populates='dependencies')
    dependent = db.relationship('Task', foreign_keys=[dependent_id], back_populates='dependents')
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'dependent_id': self.dependent_id,
            'dependency_type': self.dependency_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'task': self.task.to_dict() if self.task else None,
            'dependent': self.dependent.to_dict() if self.dependent else None
        }
    
    def __repr__(self):
        return f'<TaskDependency {self.task_id} -> {self.dependent_id}>'

class TaskLog(db.Model):
    """任务日志模型"""
    __tablename__ = 'task_logs'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # created, updated, deleted, etc.
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    task = db.relationship('Task', back_populates='logs')
    user = db.relationship('User', back_populates='task_logs')
    
    def __repr__(self):
        return f'<TaskLog {self.action}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'user_id': self.user_id,
            'action': self.action,
            'details': self.details,
            'created_at': self.created_at.isoformat()
        }

class TaskComment(db.Model):
    """任务评论模型"""
    __tablename__ = 'task_comments'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关系
    task = db.relationship('Task', back_populates='comments')
    user = db.relationship('User', back_populates='task_comments')
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'user_id': self.user_id,
            'content': self.content,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'user': self.user.to_dict() if self.user else None
        }

class TaskProgressHistory(db.Model):
    """任务进度历史记录"""
    __tablename__ = 'task_progress_history'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    progress = db.Column(db.Integer, nullable=False)  # 0-100
    previous_progress = db.Column(db.Integer)  # 之前的进度
    change_reason = db.Column(db.String(255))  # 进度变更原因
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关系
    task = db.relationship('Task', back_populates='progress_history')
    user = db.relationship('User', back_populates='task_progress_changes')
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'user_id': self.user_id,
            'progress': self.progress,
            'previous_progress': self.previous_progress,
            'change_reason': self.change_reason,
            'created_at': self.created_at.isoformat()
        }

class TaskProgressApproval(db.Model):
    """任务进度变更审批"""
    __tablename__ = 'task_progress_approvals'
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # 申请人
    approver_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # 审批人
    requested_progress = db.Column(db.Integer, nullable=False)  # 请求的进度
    current_progress = db.Column(db.Integer, nullable=False)  # 当前进度
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected
    change_reason = db.Column(db.String(255))  # 变更原因
    approval_comment = db.Column(db.String(255))  # 审批意见
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关系
    task = db.relationship('Task', back_populates='progress_approvals')
    user = db.relationship('User', foreign_keys=[user_id], back_populates='progress_requests')
    approver = db.relationship('User', foreign_keys=[approver_id], back_populates='progress_approvals')
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'user_id': self.user_id,
            'approver_id': self.approver_id,
            'requested_progress': self.requested_progress,
            'current_progress': self.current_progress,
            'status': self.status,
            'change_reason': self.change_reason,
            'approval_comment': self.approval_comment,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

@event.listens_for(Task, 'after_update')
def update_project_progress(mapper, connection, target):
    """更新项目进度"""
    try:
        # 使用已经建立的连接而不是session
        if target.project and hasattr(target.project, 'calculate_progress'):
            # 仅计算进度，不进行数据库操作
            progress = target.project.calculate_progress() 
            
            # 使用原始连接来更新项目进度
            if progress is not None:
                connection.execute(
                    'UPDATE projects SET progress = ? WHERE id = ?',
                    progress, target.project_id
                )
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"更新项目进度时出错: {str(e)}")
        # 不抛出异常，避免中断主流程 