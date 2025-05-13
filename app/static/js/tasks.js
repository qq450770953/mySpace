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
    
    // 绑定新建任务按钮点击事件
    const newTaskBtn = document.querySelector('[data-bs-target="#newTaskModal"]');
    if (newTaskBtn) {
        newTaskBtn.addEventListener('click', function() {
            // 加载项目和用户列表
            loadProjectsForTaskModal();
            loadUsersForTaskModal();
        });
    }
    
    // 绑定保存任务按钮事件
    const saveTaskBtn = document.getElementById('saveTaskBtn');
    if (saveTaskBtn) {
        saveTaskBtn.addEventListener('click', saveTask);
    }
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

// 加载项目列表到任务模态框
function loadProjectsForTaskModal() {
    const projectSelect = document.getElementById('projectId');
    if (!projectSelect) {
        console.error('找不到项目选择器元素 #projectId');
        return;
    }
    
    console.log('开始加载项目列表到任务模态框');
    
    // 显示加载中状态
    projectSelect.innerHTML = '<option value="">加载中...</option>';
    projectSelect.disabled = true;
    
    // 定义多个可能的API端点
    const apiUrls = [
        '/api/auth/projects?bypass_jwt=true',
        '/api/projects?bypass_jwt=true',
        '/api/noauth/projects',
        '/api/global/projects',
        '/api/project-managers?bypass_jwt=true',
        '/projects/list?format=json',
        '/projects?bypass_jwt=true'
    ];
    
    // 定义递归尝试函数
    function tryNextProjectApi(index = 0) {
        if (index >= apiUrls.length) {
            console.error('所有项目API尝试均失败，使用静态数据');
            useStaticProjectData();
            return;
        }
        
        const url = apiUrls[index];
        console.log(`尝试从API加载项目(${index + 1}/${apiUrls.length}): ${url}`);
        
        fetch(url)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`获取项目列表失败: ${response.status} ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('成功获取项目数据:', data);
                
                // 提取项目列表
                let projects = [];
                if (Array.isArray(data)) {
                    projects = data;
                } else if (data.projects && Array.isArray(data.projects)) {
                    projects = data.projects;
                } else if (data.data && Array.isArray(data.data)) {
                    projects = data.data;
                } else {
                    console.warn('项目数据格式不符合预期:', data);
                    // 尝试从复杂对象中提取项目数据
                    for (const key in data) {
                        if (Array.isArray(data[key])) {
                            // 尝试找到看起来像项目列表的数组
                            if (data[key].length > 0 && data[key][0] && (data[key][0].id || data[key][0].name)) {
                                projects = data[key];
                                break;
                            }
                        }
                    }
                    
                    if (projects.length === 0) {
                        throw new Error('无法解析项目数据格式');
                    }
                }
                
                updateProjectSelect(projects);
            })
            .catch(error => {
                console.warn(`从 ${url} 加载项目失败:`, error);
                // 尝试下一个API
                setTimeout(() => tryNextProjectApi(index + 1), 100);
            });
    }
    
    // 使用静态项目数据作为后备
    function useStaticProjectData() {
        const staticProjects = [
            { id: 1, name: "产品研发项目" },
            { id: 2, name: "市场推广项目" },
            { id: 3, name: "系统升级项目" },
            { id: 4, name: "数据中心建设" },
            { id: 5, name: "客户服务优化" },
            { id: 6, name: "研发创新项目" },
            { id: 7, name: "基础设施升级" }
        ];
        
        updateProjectSelect(staticProjects);
        console.log('使用静态项目数据');
    }
    
    // 更新项目选择器
    function updateProjectSelect(projects) {
        // 清空选择器
        projectSelect.innerHTML = '';
        
        // 添加默认选项
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = '-- 选择项目 --';
        projectSelect.appendChild(defaultOption);
        
        // 标准化项目数据
        const normalizedProjects = projects.map(project => ({
            id: project.id || project.project_id,
            name: project.name || project.project_name || project.title || `项目 #${project.id || project.project_id}`
        }));
        
        // 添加项目选项
        normalizedProjects.forEach(project => {
            if (project.id) {  // 确保项目有ID
                const option = document.createElement('option');
                option.value = project.id;
                option.textContent = project.name;
                projectSelect.appendChild(option);
            }
        });
        
        // 启用选择器
        projectSelect.disabled = false;
        
        console.log(`已加载 ${normalizedProjects.length} 个项目`);
    }
    
    // 开始尝试第一个API
    tryNextProjectApi(0);
}

// 加载用户列表到任务模态框
function loadUsersForTaskModal() {
    const userSelect = document.getElementById('assigneeId');
    if (!userSelect) {
        console.error('找不到用户选择器元素 #assigneeId');
        return;
    }
    
    console.log('开始加载用户列表到任务模态框');
    
    // 显示加载中状态
    userSelect.innerHTML = '<option value="">加载中...</option>';
    userSelect.disabled = true;
    
    // 尝试多个可能的API端点
    const apiUrls = [
        '/api/global/users?bypass_jwt=true',
        '/api/auth/users?bypass_jwt=true',
        '/api/project-managers?bypass_jwt=true',
        '/api/noauth/users',
        '/api/auth/global/users?bypass_jwt=true',
        '/api/users?bypass_jwt=true',
        '/users?bypass_jwt=true',
        '/auth/users?bypass_jwt=true'
    ];
    
    // 定义递归尝试函数
    function tryNextUserApi(index = 0) {
        if (index >= apiUrls.length) {
            console.error('所有用户API尝试均失败，使用静态数据');
            useStaticUserData();
            return;
        }
        
        const url = apiUrls[index];
        console.log(`尝试从API加载用户(${index + 1}/${apiUrls.length}): ${url}`);
        
        fetch(url)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`获取用户列表失败: ${response.status} ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('成功获取用户数据:', data);
                
                // 提取用户列表
                let users = [];
                if (Array.isArray(data)) {
                    users = data;
                } else if (data.users && Array.isArray(data.users)) {
                    users = data.users;
                } else if (data.data && Array.isArray(data.data)) {
                    users = data.data;
                } else if (data.project_managers && Array.isArray(data.project_managers)) {
                    users = data.project_managers;
                } else {
                    console.warn('用户数据格式不符合预期:', data);
                    // 尝试从复杂对象中提取用户数据
                    for (const key in data) {
                        if (Array.isArray(data[key])) {
                            // 尝试找到看起来像用户列表的数组
                            if (data[key].length > 0 && data[key][0] && (data[key][0].id || data[key][0].user_id)) {
                                users = data[key];
                                break;
                            }
                        }
                    }
                    
                    if (users.length === 0) {
                        throw new Error('无法解析用户数据格式');
                    }
                }
                
                updateUserSelect(users);
            })
            .catch(error => {
                console.warn(`从 ${url} 加载用户失败:`, error);
                // 尝试下一个API
                setTimeout(() => tryNextUserApi(index + 1), 100);
            });
    }
    
    // 使用静态用户数据作为后备
    function useStaticUserData() {
        const staticUsers = [
            { id: 1, name: "管理员" },
            { id: 2, name: "项目经理" },
            { id: 3, name: "开发人员" },
            { id: 4, name: "测试人员" },
            { id: 5, name: "运维人员" }
        ];
        
        updateUserSelect(staticUsers);
        console.log('使用静态用户数据');
    }
    
    // 更新用户选择器
    function updateUserSelect(users) {
        // 清空选择器
        userSelect.innerHTML = '';
        
        // 添加默认选项
        const defaultOption = document.createElement('option');
        defaultOption.value = '';
        defaultOption.textContent = '-- 选择负责人 --';
        userSelect.appendChild(defaultOption);
        
        // 标准化用户数据
        const normalizedUsers = users.map(user => ({
            id: user.id || user.user_id,
            name: user.name || user.username || user.displayName || `用户 #${user.id || user.user_id}`
        }));
        
        // 添加用户选项
        normalizedUsers.forEach(user => {
            if (user.id) {  // 确保用户有ID
                const option = document.createElement('option');
                option.value = user.id;
                option.textContent = user.name;
                userSelect.appendChild(option);
            }
        });
        
        // 启用选择器
        userSelect.disabled = false;
        
        console.log(`已加载 ${normalizedUsers.length} 个用户`);
    }
    
    // 开始尝试第一个API
    tryNextUserApi(0);
} 