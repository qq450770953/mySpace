from app.extensions import db
from datetime import datetime

class KanbanBoard(db.Model):
    __tablename__ = 'kanban_boards'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    columns = db.relationship('KanbanColumn', backref='board', lazy='dynamic', order_by='KanbanColumn.position')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'project_id': self.project_id,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class KanbanColumn(db.Model):
    __tablename__ = 'kanban_columns'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    board_id = db.Column(db.Integer, db.ForeignKey('kanban_boards.id'), nullable=False)
    position = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    cards = db.relationship('KanbanCard', backref='column', lazy='dynamic', order_by='KanbanCard.position')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'board_id': self.board_id,
            'position': self.position,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class KanbanCard(db.Model):
    __tablename__ = 'kanban_cards'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text)
    column_id = db.Column(db.Integer, db.ForeignKey('kanban_columns.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))
    position = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'column_id': self.column_id,
            'task_id': self.task_id,
            'position': self.position,
            'created_at': self.created_at.isoformat() if self.created_at else None
        } 