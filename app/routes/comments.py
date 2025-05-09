from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.task import Task, TaskComment
from app import db
from datetime import datetime
import logging

comments_bp = Blueprint('comments', __name__)
logger = logging.getLogger(__name__)

@comments_bp.route('/api/tasks/<int:task_id>/comments', methods=['GET'])
@jwt_required()
def get_task_comments(task_id):
    try:
        task = Task.query.get_or_404(task_id)
        comments = TaskComment.query.filter_by(task_id=task_id).order_by(TaskComment.created_at.desc()).all()
        return jsonify([comment.to_dict() for comment in comments])
    except Exception as e:
        logger.error(f"Error getting task comments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@comments_bp.route('/api/tasks/<int:task_id>/comments', methods=['POST'])
@jwt_required()
def create_comment(task_id):
    try:
        current_user = get_jwt_identity()
        task = Task.query.get_or_404(task_id)
        data = request.get_json()
        
        comment = TaskComment(
            task_id=task_id,
            user_id=current_user,
            content=data['content'],
            created_at=datetime.utcnow()
        )
        
        db.session.add(comment)
        db.session.commit()
        return jsonify(comment.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@comments_bp.route('/api/comments/<int:comment_id>', methods=['PUT'])
@jwt_required()
def update_comment(comment_id):
    try:
        current_user = get_jwt_identity()
        comment = TaskComment.query.get_or_404(comment_id)
        
        if comment.user_id != current_user:
            return jsonify({'error': '无权修改此评论'}), 403
            
        data = request.get_json()
        comment.content = data['content']
        comment.updated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify(comment.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating comment: {str(e)}")
        return jsonify({'error': str(e)}), 500

@comments_bp.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    try:
        current_user = get_jwt_identity()
        comment = TaskComment.query.get_or_404(comment_id)
        
        if comment.user_id != current_user:
            return jsonify({'error': '无权删除此评论'}), 403
            
        db.session.delete(comment)
        db.session.commit()
        return jsonify({'message': '评论已删除'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting comment: {str(e)}")
        return jsonify({'error': str(e)}), 500 