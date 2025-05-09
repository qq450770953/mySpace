from app.extensions import db
from datetime import datetime

class GanttTask(db.Model):
    __tablename__ = 'gantt_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    progress = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    dependencies = db.relationship('GanttDependency', 
                                 foreign_keys='GanttDependency.from_task_id',
                                 backref='from_task',
                                 lazy='dynamic')
    dependents = db.relationship('GanttDependency',
                               foreign_keys='GanttDependency.to_task_id',
                               backref='to_task',
                               lazy='dynamic')
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'progress': self.progress,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class GanttDependency(db.Model):
    __tablename__ = 'gantt_dependencies'
    
    id = db.Column(db.Integer, primary_key=True)
    from_task_id = db.Column(db.Integer, db.ForeignKey('gantt_tasks.id'), nullable=False)
    to_task_id = db.Column(db.Integer, db.ForeignKey('gantt_tasks.id'), nullable=False)
    type = db.Column(db.String(32), nullable=False)  # 'FS', 'SS', 'FF', 'SF'
    lag = db.Column(db.Integer, default=0)  # Lag time in days
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'from_task_id': self.from_task_id,
            'to_task_id': self.to_task_id,
            'type': self.type,
            'lag': self.lag,
            'created_at': self.created_at.isoformat() if self.created_at else None
        } 