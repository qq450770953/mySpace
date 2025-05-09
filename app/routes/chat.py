from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models.chat import Message
from app import db
from datetime import datetime
import logging

chat_bp = Blueprint('chat', __name__)
logger = logging.getLogger(__name__)

@chat_bp.route('/api/chat/messages', methods=['GET'])
@jwt_required()
def get_messages():
    try:
        current_user = get_jwt_identity()
        messages = Message.query.filter(
            (Message.sender_id == current_user) | (Message.receiver_id == current_user)
        ).order_by(Message.created_at.desc()).all()
        return jsonify([message.to_dict() for message in messages])
    except Exception as e:
        logger.error(f"Error getting messages: {str(e)}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/chat/messages', methods=['POST'])
@jwt_required()
def send_message():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        message = Message(
            sender_id=current_user,
            receiver_id=data['receiver_id'],
            content=data['content'],
            created_at=datetime.utcnow()
        )
        
        db.session.add(message)
        db.session.commit()
        return jsonify(message.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending message: {str(e)}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/chat/messages/<int:message_id>', methods=['GET'])
@jwt_required()
def get_message(message_id):
    try:
        current_user = get_jwt_identity()
        message = Message.query.filter(
            Message.id == message_id,
            (Message.sender_id == current_user) | (Message.receiver_id == current_user)
        ).first_or_404()
        return jsonify(message.to_dict())
    except Exception as e:
        logger.error(f"Error getting message: {str(e)}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/chat/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_message(message_id):
    try:
        current_user = get_jwt_identity()
        message = Message.query.filter(
            Message.id == message_id,
            Message.sender_id == current_user
        ).first_or_404()
        
        db.session.delete(message)
        db.session.commit()
        return jsonify({'message': '消息已删除'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting message: {str(e)}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/chat/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    try:
        current_user = get_jwt_identity()
        conversations = Message.query.filter(
            (Message.sender_id == current_user) | (Message.receiver_id == current_user)
        ).order_by(Message.created_at.desc()).all()
        
        # Group messages by conversation
        conversation_dict = {}
        for message in conversations:
            other_user_id = message.receiver_id if message.sender_id == current_user else message.sender_id
            if other_user_id not in conversation_dict:
                conversation_dict[other_user_id] = {
                    'last_message': message.to_dict(),
                    'unread_count': 0
                }
            if not message.read and message.receiver_id == current_user:
                conversation_dict[other_user_id]['unread_count'] += 1
        
        return jsonify(list(conversation_dict.values()))
    except Exception as e:
        logger.error(f"Error getting conversations: {str(e)}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/api/chat/messages/<int:message_id>/read', methods=['PUT'])
@jwt_required()
def mark_message_read(message_id):
    try:
        current_user = get_jwt_identity()
        message = Message.query.filter(
            Message.id == message_id,
            Message.receiver_id == current_user
        ).first_or_404()
        
        message.read = True
        message.read_at = datetime.utcnow()
        db.session.commit()
        return jsonify(message.to_dict())
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marking message as read: {str(e)}")
        return jsonify({'error': str(e)}), 500 