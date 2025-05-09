from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import Notification, User
from app.extensions import db
from datetime import datetime

notification_bp = Blueprint('notification', __name__)

@notification_bp.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    """获取用户的通知列表"""
    try:
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        notifications = Notification.query.filter_by(user_id=current_user_id)\
            .order_by(Notification.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'notifications': [notification.to_dict() for notification in notifications.items],
            'total': notifications.total,
            'pages': notifications.pages,
            'current_page': notifications.page
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notification_bp.route('/notifications/<int:notification_id>', methods=['GET'])
@jwt_required()
def get_notification(notification_id):
    """获取单个通知详情"""
    try:
        current_user_id = get_jwt_identity()
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user_id
        ).first_or_404()
        
        return jsonify(notification.to_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notification_bp.route('/notifications/<int:notification_id>/read', methods=['PUT'])
@jwt_required()
def mark_notification_read(notification_id):
    """标记通知为已读"""
    try:
        current_user_id = get_jwt_identity()
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user_id
        ).first_or_404()
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify({'message': '通知已标记为已读'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@notification_bp.route('/notifications/read-all', methods=['PUT'])
@jwt_required()
def mark_all_notifications_read():
    """标记所有通知为已读"""
    try:
        current_user_id = get_jwt_identity()
        Notification.query.filter_by(
            user_id=current_user_id,
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        return jsonify({'message': '所有通知已标记为已读'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@notification_bp.route('/notifications/<int:notification_id>', methods=['DELETE'])
@jwt_required()
def delete_notification(notification_id):
    """删除通知"""
    try:
        current_user_id = get_jwt_identity()
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user_id
        ).first_or_404()
        
        db.session.delete(notification)
        db.session.commit()
        
        return jsonify({'message': '通知已删除'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@notification_bp.route('/messages', methods=['POST'])
@jwt_required()
def send_message():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    message = Message(
        sender_id=user_id,
        receiver_id=data['receiver_id'],
        content=data['content']
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify(message.to_dict()), 201

@notification_bp.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    user_id = get_jwt_identity()
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).order_by(Message.created_at.desc()).all()
    
    return jsonify([message.to_dict() for message in messages])

@notification_bp.route('/messages/<int:message_id>', methods=['PUT'])
@jwt_required()
def mark_message_read(message_id):
    message = Message.query.get_or_404(message_id)
    message.is_read = True
    db.session.commit()
    return jsonify(message.to_dict())

@notification_bp.route('/messages/conversation/<int:other_user_id>', methods=['GET'])
@jwt_required()
def get_conversation(other_user_id):
    user_id = get_jwt_identity()
    messages = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == user_id))
    ).order_by(Message.created_at.asc()).all()
    
    return jsonify([message.to_dict() for message in messages]) 