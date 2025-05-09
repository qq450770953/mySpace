from app.extensions import db
from datetime import datetime
import os

class TaskAttachment(db.Model):
    __tablename__ = 'task_attachments'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)  # 文件大小（字节）
    description = db.Column(db.Text)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    version = db.Column(db.Integer, default=1)  # 版本号
    is_latest = db.Column(db.Boolean, default=True)  # 是否为最新版本
    parent_version_id = db.Column(db.Integer, db.ForeignKey('task_attachments.id'))  # 父版本ID
    
    # 关系
    task = db.relationship('Task', backref=db.backref('attachments', lazy=True))
    uploader = db.relationship('User', backref=db.backref('uploaded_attachments', lazy=True))
    parent_version = db.relationship('TaskAttachment', remote_side=[id], backref=db.backref('child_versions', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_type': self.file_type,
            'size': self.size,
            'description': self.description,
            'uploader': self.uploader.name,
            'uploaded_at': self.uploaded_at.strftime('%Y-%m-%d %H:%M'),
            'version': self.version,
            'is_latest': self.is_latest,
            'parent_version_id': self.parent_version_id
        } 