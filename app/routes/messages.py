from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import or_, and_
from datetime import datetime
from app import db, socketio
from app.models.notification import Message
from app.models.auth import User
from flask_socketio import emit, join_room, leave_room

bp = Blueprint('messages', __name__)

@bp.route('/api/contacts', methods=['GET'])
@jwt_required()
def get_contacts():
    """获取当前用户的联系人列表，包括未读消息数和最后一条消息"""
    current_user_id = get_jwt_identity()
    
    # 获取所有与当前用户有关的消息
    messages = Message.query.filter(
        or_(
            Message.sender_id == current_user_id,
            Message.receiver_id == current_user_id
        )
    ).order_by(Message.created_at.desc()).all()
    
    contacts = {}
    for msg in messages:
        other_id = msg.receiver_id if msg.sender_id == current_user_id else msg.sender_id
        if other_id not in contacts:
            other_user = User.query.get(other_id)
            contacts[other_id] = {
                'user_id': other_id,
                'username': other_user.username,
                'last_message': msg.content,
                'last_message_time': msg.created_at.isoformat(),
                'unread_count': 0
            }
        
        # 计算未读消息数
        if msg.receiver_id == current_user_id and not msg.is_read:
            contacts[other_id]['unread_count'] += 1
    
    return jsonify({'contacts': list(contacts.values())})

@bp.route('/api/messages', methods=['POST'])
@jwt_required()
def send_message():
    """发送消息"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'receiver_id' not in data or 'content' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    receiver = User.query.get(data['receiver_id'])
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    
    message = Message(
        sender_id=current_user_id,
        receiver_id=data['receiver_id'],
        content=data['content']
    )
    
    db.session.add(message)
    db.session.commit()
    
    # 通过WebSocket发送实时通知
    socketio.emit(
        'new_message',
        {
            'message_id': message.id,
            'sender_id': current_user_id,
            'content': message.content,
            'created_at': message.created_at.isoformat()
        },
        room=f'user_{data["receiver_id"]}'
    )
    
    return jsonify(message.to_dict()), 201

@bp.route('/api/messages/conversation/<int:other_user_id>', methods=['GET'])
@jwt_required()
def get_conversation(other_user_id):
    """获取与指定用户的对话历史"""
    current_user_id = get_jwt_identity()
    
    messages = Message.query.filter(
        or_(
            and_(Message.sender_id == current_user_id, Message.receiver_id == other_user_id),
            and_(Message.sender_id == other_user_id, Message.receiver_id == current_user_id)
        )
    ).order_by(Message.created_at.desc()).all()
    
    return jsonify({'messages': [msg.to_dict() for msg in messages]})

@bp.route('/api/messages/mark-read/<int:sender_id>', methods=['PUT'])
@jwt_required()
def mark_messages_read(sender_id):
    """将来自指定发送者的所有消息标记为已读"""
    current_user_id = get_jwt_identity()
    
    Message.query.filter_by(
        sender_id=sender_id,
        receiver_id=current_user_id,
        is_read=False
    ).update({'is_read': True})
    
    db.session.commit()
    return jsonify({'message': 'Messages marked as read'})

@bp.route('/api/messages/unread-count', methods=['GET'])
@jwt_required()
def get_unread_count():
    """获取当前用户的未读消息总数"""
    current_user_id = get_jwt_identity()
    
    count = Message.query.filter_by(
        receiver_id=current_user_id,
        is_read=False
    ).count()
    
    return jsonify({'unread_count': count})

# WebSocket事件处理器
@socketio.on('connect')
@jwt_required()
def handle_connect():
    """处理WebSocket连接"""
    current_user_id = get_jwt_identity()
    emit('connected', {'user_id': current_user_id})

@socketio.on('disconnect')
def handle_disconnect():
    """处理WebSocket断开连接"""
    pass

@socketio.on('join')
@jwt_required()
def on_join():
    """加入用户专属房间以接收消息"""
    current_user_id = get_jwt_identity()
    room = f'user_{current_user_id}'
    join_room(room)
    emit('joined', {'room': room})

@socketio.on('leave')
@jwt_required()
def on_leave():
    """离开用户专属房间"""
    current_user_id = get_jwt_identity()
    room = f'user_{current_user_id}'
    leave_room(room)
    emit('left', {'room': room}) 