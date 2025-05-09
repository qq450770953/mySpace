/**
 * 加载任务列表
 */
function loadTasks() {
    console.log('加载任务列表...');
    
    // 显示加载指示器
    const tableBody = document.querySelector('table tbody');
    if (tableBody) {
        tableBody.innerHTML = '<tr><td colspan="6" class="text-center py-3"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">加载任务数据...</p></td></tr>';
    }
    
    // 发送请求获取任务列表
    fetch('/api/tasks')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('获取到任务数据:', data);
            renderTasks(data);
            
            // 任务列表加载完成后，检查按钮显示权限
            setupTaskUIBasedOnPermissions();
        })
        .catch(error => {
            console.error('获取任务列表失败:', error);
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-3">
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle-fill"></i> 
                        加载任务失败: ${error.message}
                    </div>
                </td></tr>`;
            }
        });
}

/**
 * 渲染任务列表
 */
function renderTasks(tasks) {
    const tableBody = document.querySelector('table tbody');
    if (!tableBody) return;
    
    if (!tasks || tasks.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-3">
            <div class="alert alert-info">
                <i class="bi bi-info-circle-fill"></i> 
                暂无任务数据
            </div>
        </td></tr>`;
        return;
    }
    
    // 生成任务列表HTML
    let html = '';
    for (const task of tasks) {
        html += `
        <tr class="task-status-${task.status.replace('_', '-') || 'todo'}">
            <td>${task.title}</td>
            <td>${task.assignee ? task.assignee.name : '未分配'}</td>
            <td>
                <span class="badge ${task.priority === 'high' ? 'bg-danger' : task.priority === 'medium' ? 'bg-warning' : 'bg-info'}">
                    ${task.priority || 'low'}
                </span>
            </td>
            <td>${task.due_date || '-'}</td>
            <td>
                <span class="badge ${getStatusClass(task.status)}">
                    ${getStatusText(task.status)}
                </span>
            </td>
            <td class="text-end">
                <div class="task-operations">
                    <button type="button" class="btn btn-sm btn-outline-primary" onclick="viewTask(${task.id})">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline-secondary edit-btn" onclick="editTask(${task.id})">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline-danger delete-btn" onclick="deleteTask(${task.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        </tr>`;
    }
    
    tableBody.innerHTML = html;
}

// 页面加载时执行的初始化函数
document.addEventListener('DOMContentLoaded', function() {
    console.log('初始化任务管理页面');
    
    // 根据用户权限设置任务界面元素
    setupTaskUIBasedOnPermissions();
});

// 根据用户权限设置任务界面元素
function setupTaskUIBasedOnPermissions() {
    // 检查用户是否有创建任务的权限
    const canCreateTask = hasPermission('create_task');
    // 检查用户是否有管理任务的权限
    const canManageTask = hasPermission('manage_task') || hasPermission('manage_all_tasks');
    
    console.log('任务权限检查:', { canCreateTask, canManageTask });
    
    // 设置"新建任务"按钮可见性
    const newTaskButtons = document.querySelectorAll('.new-task-btn, .create-task-btn, [data-action="new-task"]');
    newTaskButtons.forEach(button => {
        if (button) {
            button.style.display = canCreateTask ? 'inline-block' : 'none';
        }
    });
    
    // 设置任务编辑按钮可见性
    const taskEditButtons = document.querySelectorAll('.edit-btn, .task-edit-btn, [data-action="edit-task"]');
    taskEditButtons.forEach(button => {
        if (button) {
            button.style.display = canManageTask ? 'inline-block' : 'none';
        }
    });
    
    // 设置任务删除按钮可见性
    const taskDeleteButtons = document.querySelectorAll('.delete-btn, .task-delete-btn, [data-action="delete-task"]');
    taskDeleteButtons.forEach(button => {
        if (button) {
            button.style.display = canManageTask ? 'inline-block' : 'none';
        }
    });
    
    // 如果用户没有创建任务权限，隐藏新建任务模态框触发按钮
    const newTaskModalTriggers = document.querySelectorAll('[data-bs-toggle="modal"][data-bs-target="#newTaskModal"]');
    newTaskModalTriggers.forEach(trigger => {
        if (trigger) {
            trigger.style.display = canCreateTask ? 'inline-block' : 'none';
        }
    });
    
    // 任务操作按钮（分配、状态更改等）
    const taskActionButtons = document.querySelectorAll('.assign-task-btn, .change-status-btn');
    taskActionButtons.forEach(button => {
        if (button) {
            button.style.display = canManageTask ? 'inline-block' : 'none';
        }
    });
}

// 根据任务状态获取对应的类名
function getStatusClass(status) {
    switch (status) {
        case 'pending':
            return 'bg-secondary';
        case 'in_progress':
            return 'bg-primary';
        case 'completed':
            return 'bg-success';
        case 'on_hold':
            return 'bg-warning';
        case 'cancelled':
            return 'bg-danger';
        default:
            return 'bg-secondary';
    }
}

// 任务状态变更函数
function changeTaskStatus(taskId, newStatus) {
    if (!hasPermission('change_task_status') && !hasPermission('manage_task') && !hasPermission('manage_all_tasks')) {
        console.log('用户没有修改任务状态的权限');
        return;
    }
    
    fetch(`/api/auth/tasks/${taskId}/status`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: newStatus })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // 更新页面显示
            const taskCard = document.querySelector(`[data-task-id="${taskId}"]`);
            if (taskCard) {
                const statusBadge = taskCard.querySelector('.task-status');
                if (statusBadge) {
                    // 移除所有背景色类
                    statusBadge.classList.remove('bg-secondary', 'bg-primary', 'bg-success', 'bg-warning', 'bg-danger');
                    // 添加新的背景色类
                    statusBadge.classList.add(getStatusClass(newStatus));
                    // 更新文本
                    statusBadge.textContent = getStatusText(newStatus);
                }
            }
            
            // 显示成功消息
            showMessage('任务状态已更新', 'success');
        } else {
            throw new Error(data.message || '更新任务状态失败');
        }
    })
    .catch(error => {
        console.error('更新任务状态失败:', error);
        showMessage(`更新任务状态失败: ${error.message}`, 'danger');
    });
}

// 显示消息提示
function showMessage(message, type = 'info') {
    const alertBox = document.createElement('div');
    alertBox.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertBox.style.top = '20px';
    alertBox.style.right = '20px';
    alertBox.style.zIndex = '9999';
    
    alertBox.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    document.body.appendChild(alertBox);
    
    // 3秒后自动消失
    setTimeout(() => {
        alertBox.classList.remove('show');
        setTimeout(() => alertBox.remove(), 150);
    }, 3000);
}

// 获取任务状态的显示文本
function getStatusText(status) {
    switch (status) {
        case 'pending':
            return '待处理';
        case 'in_progress':
            return '进行中';
        case 'completed':
            return '已完成';
        case 'on_hold':
            return '已暂停';
        case 'cancelled':
            return '已取消';
        default:
            return '未知状态';
    }
} 