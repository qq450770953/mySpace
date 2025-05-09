// 通知相关的全局变量
let currentContactId = null;
let unreadNotifications = 0;
let unreadMessages = 0;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    loadNotifications();
    loadContacts();
    initializeWebSocket();
});

// 加载通知列表
async function loadNotifications() {
    try {
        const response = await fetch('/api/notifications');
        if (!response.ok) throw new Error('Failed to load notifications');
        const notifications = await response.json();
        
        // 更新通知列表
        const list = document.querySelector('.notification-list');
        list.innerHTML = '';
        notifications.forEach(notification => {
            list.innerHTML += createNotificationHTML(notification);
        });
        
        // 更新未读通知数
        unreadNotifications = notifications.filter(n => !n.is_read).length;
        updateNotificationBadge();
    } catch (error) {
        console.error('Error loading notifications:', error);
        showAlert('error', '加载通知失败');
    }
}

// 加载联系人列表
async function loadContacts() {
    try {
        const response = await fetch('/api/contacts');
        if (!response.ok) throw new Error('Failed to load contacts');
        const contacts = await response.json();
        
        // 更新联系人列表
        const list = document.querySelector('.contact-list');
        list.innerHTML = '';
        contacts.forEach(contact => {
            list.innerHTML += createContactHTML(contact);
        });
        
        // 更新未读消息数
        unreadMessages = contacts.reduce((sum, contact) => sum + contact.unread_count, 0);
        updateMessageBadge();
    } catch (error) {
        console.error('Error loading contacts:', error);
        showAlert('error', '加载联系人失败');
    }
}

// 加载对话内容
async function loadConversation(contactId) {
    currentContactId = contactId;
    
    try {
        const response = await fetch(`/api/messages/conversation/${contactId}`);
        if (!response.ok) throw new Error('Failed to load conversation');
        const messages = await response.json();
        
        // 更新对话标题
        const contact = document.querySelector(`.contact-list [data-id="${contactId}"]`);
        document.getElementById('conversation-title').textContent = contact.querySelector('h6').textContent;
        
        // 显示消息表单
        document.getElementById('message-form').style.display = 'block';
        
        // 渲染消息
        const container = document.getElementById('conversation-messages');
        container.innerHTML = '';
        messages.forEach(message => {
            container.innerHTML += createMessageHTML(message);
        });
        
        // 滚动到底部
        container.scrollTop = container.scrollHeight;
        
        // 标记消息为已读
        if (messages.length > 0) {
            await markConversationAsRead(contactId);
        }
    } catch (error) {
        console.error('Error loading conversation:', error);
        showAlert('error', '加载对话失败');
    }
}

// 标记通知为已读
async function markAsRead(notificationId) {
    try {
        const response = await fetch(`/api/notifications/${notificationId}`, {
            method: 'PUT'
        });
        
        if (!response.ok) throw new Error('Failed to mark notification as read');
        
        const notification = document.getElementById(`notification-${notificationId}`);
        notification.classList.remove('unread');
        const button = notification.querySelector('button');
        if (button) button.remove();
        
        // 更新未读通知数
        unreadNotifications--;
        updateNotificationBadge();
    } catch (error) {
        console.error('Error marking notification as read:', error);
        showAlert('error', '标记通知失败');
    }
}

// 标记所有通知为已读
async function markAllRead() {
    try {
        const response = await fetch('/api/notifications/mark-all-read', {
            method: 'PUT'
        });
        
        if (!response.ok) throw new Error('Failed to mark all notifications as read');
        
        document.querySelectorAll('.notification-list .unread').forEach(notification => {
            notification.classList.remove('unread');
            const button = notification.querySelector('button');
            if (button) button.remove();
        });
        
        // 更新未读通知数
        unreadNotifications = 0;
        updateNotificationBadge();
        
        showAlert('success', '所有通知已标记为已读');
    } catch (error) {
        console.error('Error marking all notifications as read:', error);
        showAlert('error', '标记通知失败');
    }
}

// 清空所有通知
async function clearAll() {
    if (!confirm('确定要清空所有通知吗？')) return;
    
    try {
        const response = await fetch('/api/notifications', {
            method: 'DELETE'
        });
        
        if (!response.ok) throw new Error('Failed to clear notifications');
        
        document.querySelector('.notification-list').innerHTML = '';
        
        // 更新未读通知数
        unreadNotifications = 0;
        updateNotificationBadge();
        
        showAlert('success', '通知已清空');
    } catch (error) {
        console.error('Error clearing notifications:', error);
        showAlert('error', '清空通知失败');
    }
}

// 发送消息
async function sendMessage(event) {
    event.preventDefault();
    
    if (!currentContactId) return;
    
    const input = document.getElementById('message-input');
    const content = input.value.trim();
    if (!content) return;
    
    try {
        const response = await fetch('/api/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                receiver_id: currentContactId,
                content: content
            })
        });
        
        if (!response.ok) throw new Error('Failed to send message');
        
        // 清空输入框
        input.value = '';
        
        // 重新加载对话
        loadConversation(currentContactId);
    } catch (error) {
        console.error('Error sending message:', error);
        showAlert('error', '发送消息失败');
    }
}

// 标记对话为已读
async function markConversationAsRead(contactId) {
    try {
        const response = await fetch(`/api/messages/mark-read/${contactId}`, {
            method: 'PUT'
        });
        
        if (!response.ok) throw new Error('Failed to mark conversation as read');
        
        // 更新联系人列表中的未读消息数
        const contact = document.querySelector(`.contact-list [data-id="${contactId}"]`);
        const badge = contact.querySelector('.badge');
        if (badge) {
            unreadMessages -= parseInt(badge.textContent);
            updateMessageBadge();
            badge.remove();
        }
    } catch (error) {
        console.error('Error marking conversation as read:', error);
    }
}

// 更新通知徽章
function updateNotificationBadge() {
    const badge = document.querySelector('.notification-badge');
    if (unreadNotifications > 0) {
        badge.textContent = unreadNotifications;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }
}

// 更新消息徽章
function updateMessageBadge() {
    const badge = document.querySelector('.message-badge');
    if (unreadMessages > 0) {
        badge.textContent = unreadMessages;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }
}

// 创建通知HTML
function createNotificationHTML(notification) {
    return `
        <div class="list-group-item list-group-item-action ${notification.is_read ? '' : 'unread'}" id="notification-${notification.id}">
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1">${notification.title}</h6>
                <small>${formatDateTime(notification.created_at)}</small>
            </div>
            <p class="mb-1">${notification.content}</p>
            <div class="d-flex justify-content-between align-items-center">
                <small class="text-muted">${notification.type}</small>
                ${notification.is_read ? '' : `
                    <button class="btn btn-sm btn-outline-primary" onclick="markAsRead(${notification.id})">
                        <i class="fas fa-check"></i> 标记为已读
                    </button>
                `}
            </div>
        </div>
    `;
}

// 创建联系人HTML
function createContactHTML(contact) {
    return `
        <a href="#" class="list-group-item list-group-item-action" data-id="${contact.id}" onclick="loadConversation(${contact.id})">
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1">${contact.name}</h6>
                ${contact.unread_count > 0 ? `
                    <span class="badge bg-primary">${contact.unread_count}</span>
                ` : ''}
            </div>
            <small class="text-muted">${contact.last_message || '暂无消息'}</small>
        </a>
    `;
}

// 创建消息HTML
function createMessageHTML(message) {
    return `
        <div class="message ${message.sender_id === currentUserId ? 'sent' : 'received'}">
            <div class="content">${message.content}</div>
            <div class="time">${formatDateTime(message.created_at)}</div>
        </div>
    `;
}

// 格式化日期时间
function formatDateTime(dateString) {
    return new Date(dateString).toLocaleString();
}

// 初始化WebSocket连接
function initializeWebSocket() {
    const socket = io();
    
    // 监听新消息
    socket.on('new_message', function(data) {
        // 如果当前正在与发送者对话，则直接加载新消息
        if (currentContactId === data.sender_id) {
            loadConversation(currentContactId);
        }
        // 否则更新联系人列表中的未读消息数
        else {
            const contact = document.querySelector(`.contact-list [data-id="${data.sender_id}"]`);
            let badge = contact.querySelector('.badge');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'badge bg-primary';
                contact.querySelector('.d-flex').appendChild(badge);
                badge.textContent = '1';
            } else {
                badge.textContent = parseInt(badge.textContent) + 1;
            }
            unreadMessages++;
            updateMessageBadge();
        }
    });
    
    // 监听新通知
    socket.on('new_notification', function(data) {
        const list = document.querySelector('.notification-list');
        list.insertAdjacentHTML('afterbegin', createNotificationHTML(data));
        unreadNotifications++;
        updateNotificationBadge();
    });
}

// 绑定事件监听器
document.getElementById('message-form').addEventListener('submit', sendMessage); 