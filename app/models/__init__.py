from flask_sqlalchemy import SQLAlchemy

# Create a proxy for db that will be initialized later
db = SQLAlchemy()

# Import models in dependency order
from app.models.auth import User, Role, Permission, TokenBlacklist
from app.models.project import Project, ProjectMember
from app.models.resource import Resource, ResourceAllocation, ResourceUtilization, ResourcePrediction, ResourceAlert, ResourceOptimization, ResourceReport, ResourceCostAnalysis, ResourceEfficiency, ResourceTrend, ResourceType, ResourceUsage
from app.models.task import Task, TaskDependency, TaskLog, TaskComment, TaskProgressHistory, TaskProgressApproval
from app.models.risk import Risk, RiskLog
from app.models.notification import Notification
from app.models.chat import Message, ChatRoom, ChatMessage
from app.models.system import SystemLog, SystemSetting
from app.models.team import Team, TeamMember, TeamMessage, TeamNotification
from app.models.attachment import TaskAttachment
from app.models.comment import Comment
from app.models.kanban import KanbanBoard, KanbanColumn, KanbanCard
from app.models.gantt import GanttTask, GanttDependency
from app.models.audit import AuditLog

__all__ = [
    'User', 'Role', 'Permission', 'TokenBlacklist',
    'Project', 'ProjectMember',
    'Resource', 'ResourceType', 'ResourceUsage',
    'ResourceAllocation', 'ResourceUtilization',
    'ResourcePrediction', 'ResourceAlert',
    'ResourceOptimization', 'ResourceReport',
    'ResourceCostAnalysis', 'ResourceEfficiency',
    'ResourceTrend',
    'Task', 'TaskDependency', 'TaskLog',
    'TaskComment', 'TaskProgressHistory',
    'TaskProgressApproval',
    'Risk', 'RiskLog',
    'Notification',
    'Message', 'ChatRoom', 'ChatMessage',
    'SystemLog', 'SystemSetting',
    'Team', 'TeamMember', 'TeamMessage',
    'TeamNotification',
    'TaskAttachment',
    'Comment',
    'KanbanBoard', 'KanbanColumn', 'KanbanCard',
    'GanttTask', 'GanttDependency',
    'AuditLog'
] 