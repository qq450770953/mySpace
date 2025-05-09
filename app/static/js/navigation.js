// 确保函数在全局作用域中
window.navigateTo = async function(url) {
    try {
        // 从cookie中获取token
        const token = document.cookie.split('; ')
            .find(row => row.startsWith('access_token_cookie='))
            ?.split('=')[1];
            
        if (!token) {
            window.location.href = '/login';
            return;
        }

        // 确保URL以/api/auth开头
        const apiUrl = url.startsWith('/api/auth/') ? url : `/api/auth${url}`;

        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });

        if (response.status === 401) {
            // Token expired or invalid
            document.cookie = 'access_token_cookie=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
            window.location.href = '/login';
            return;
        }

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();
            // 更新页面内容
            updateContent(data);
        } else {
            // 处理非JSON响应
            const text = await response.text();
            document.getElementById('content').innerHTML = text;
        }
    } catch (error) {
        console.error('Navigation error:', error);
        showError('导航时发生错误');
    }
};

// 显示错误信息
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'alert alert-danger';
    errorDiv.textContent = message;
    document.getElementById('content').prepend(errorDiv);
    setTimeout(() => errorDiv.remove(), 5000);
}

// 更新页面内容
function updateContent(data) {
    if (data.user) {
        // 更新用户信息
        document.getElementById('userName').textContent = data.user.name || data.user.username;
    }
    
    if (data.tasks) {
        // 更新任务列表
        displayTasks(data.tasks);
    }
    
    if (data.projects) {
        // 更新项目列表
        updateProjectList(data.projects);
    }
}

// 检查token是否有效
async function checkToken(token) {
    try {
        const response = await fetch('/api/auth/check_token', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            },
            credentials: 'include'
        });
        
        return response.ok;
    } catch (error) {
        console.error('Token check error:', error);
        return false;
    }
}

// 更新任务列表显示
function updateTaskList(tasks) {
    const taskList = document.getElementById('taskList');
    if (!taskList) {
        console.error('Task list container not found');
        return;
    }
    
    taskList.innerHTML = '';
    
    if (!tasks || tasks.length === 0) {
        taskList.innerHTML = '<div class="alert alert-info">暂无任务</div>';
        return;
    }
    
    const table = document.createElement('table');
    table.className = 'table table-striped';
    table.innerHTML = `
        <thead>
            <tr>
                <th>标题</th>
                <th>状态</th>
                <th>优先级</th>
                <th>负责人</th>
                <th>创建者</th>
                <th>截止日期</th>
                <th>创建时间</th>
                <th>操作</th>
            </tr>
        </thead>
        <tbody>
        </tbody>
    `;
    
    const tbody = table.querySelector('tbody');
    tasks.forEach(task => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${task.title}</td>
            <td>
                <span class="badge ${getStatusBadgeClass(task.status)}">
                    ${getStatusText(task.status)}
                </span>
            </td>
            <td>
                <span class="badge ${getPriorityBadgeClass(task.priority)}">
                    ${getPriorityText(task.priority)}
                </span>
            </td>
            <td>${task.assignee ? task.assignee.name : '未分配'}</td>
            <td>${task.creator ? task.creator.name : '未知'}</td>
            <td>${task.due_date || '未设置'}</td>
            <td>${task.created_at}</td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="viewTask(${task.id})">查看</button>
                <button class="btn btn-sm btn-warning" onclick="editTask(${task.id})">编辑</button>
                <button class="btn btn-sm btn-danger" onclick="deleteTask(${task.id})">删除</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
    
    taskList.appendChild(table);
}

// 导航到仪表盘
window.loadDashboard = function() {
    // 从cookie中获取token
    const token = document.cookie.split('; ')
        .find(row => row.startsWith('access_token_cookie='))
        ?.split('=')[1];
        
    if (!token) {
        window.location.href = '/login';
        return;
    }
    
    fetch('/api/auth/dashboard', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        credentials: 'include'
    })
    .then(response => {
        if (!response.ok) {
            if (response.status === 401) {
                document.cookie = 'access_token_cookie=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
                window.location.href = '/login';
                return;
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // 更新仪表盘内容
        displayDashboard(data);
    })
    .catch(error => {
        console.error('Error loading dashboard:', error);
        showError(`加载仪表盘失败: ${error.message}`);
    });
}

// 导航到任务管理
window.loadTasks = function() {
    navigateTo('/auth/tasks');
}

// 导航到项目管理
window.loadProjects = async function() {
    try {
        // 从cookie中获取token
        const token = document.cookie.split('; ')
            .find(row => row.startsWith('access_token='))
            ?.split('=')[1];
            
        if (!token) {
            showError('未登录或登录已过期');
            window.location.href = '/login';
            return;
        }

        const response = await fetch('/auth/projects', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        updateProjectList(data.projects);
    } catch (error) {
        console.error('Error loading projects:', error);
        showError('加载项目列表失败');
    }
}

// 更新项目列表显示
function updateProjectList(projects) {
    const tableBody = document.getElementById('projectTableBody');
    if (!tableBody) {
        console.error('Project table body not found');
        return;
    }

    tableBody.innerHTML = '';
    
    if (!projects || projects.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" class="text-center">暂无项目</td></tr>';
        return;
    }

    projects.forEach(project => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${project.name}</td>
            <td><span class="badge ${getStatusClass(project.status)}">${getStatusText(project.status)}</span></td>
            <td>
                <div class="progress">
                    <div class="progress-bar" role="progressbar" style="width: ${project.progress || 0}%">
                        ${project.progress || 0}%
                    </div>
                </div>
            </td>
            <td>${project.start_date ? new Date(project.start_date).toLocaleDateString() : '-'}</td>
            <td>${project.end_date ? new Date(project.end_date).toLocaleDateString() : '-'}</td>
            <td>
                <button class="btn btn-sm btn-icon btn-outline-primary" onclick="viewProject(${project.id})">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="btn btn-sm btn-icon btn-outline-warning" onclick="editProject(${project.id})">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="btn btn-sm btn-icon btn-outline-danger" onclick="deleteProject(${project.id})">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

// 获取状态文本
function getStatusText(status) {
    const statusMap = {
        'planning': '规划中',
        'in_progress': '进行中',
        'completed': '已完成',
        'cancelled': '已取消'
    };
    return statusMap[status] || status;
}

// 获取状态样式类
function getStatusClass(status) {
    const classMap = {
        'planning': 'bg-secondary',
        'in_progress': 'bg-primary',
        'completed': 'bg-success',
        'cancelled': 'bg-danger'
    };
    return classMap[status] || 'bg-secondary';
}

// 导航到项目创建页面
window.showCreateProjectForm = function() {
    const token = localStorage.getItem('access_token');
    if (!token) {
        window.location.href = '/login';
        return;
    }
    window.location.href = '/projects/list#create';
}

// 导航到资源管理
window.loadResources = function() {
    navigateTo('/api/resources/list');
}

// 导航到风险管理
window.loadRisks = function() {
    navigateTo('/api/risks/list');
}

// 导航到通知页面
window.loadNotifications = function() {
    console.log('Loading notifications...');
    navigateTo('/api/notifications');
}

// 导航到消息页面
window.loadMessages = function() {
    console.log('Loading messages...');
    navigateTo('/api/chat/messages');
}

// 导航到个人资料页面
window.loadProfile = function() {
    console.log('Loading profile...');
    navigateTo('/api/auth/profile');
}

// 导航到修改密码页面
window.loadChangePassword = function() {
    console.log('Loading change password page...');
    navigateTo('/api/auth/change-password');
}

// 退出登录
window.logout = function() {
    const token = localStorage.getItem('access_token');
    if (token) {
        fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.ok) {
                localStorage.removeItem('access_token');
                window.location.href = '/login';
            } else {
                console.error('Logout failed:', response.status);
            }
        })
        .catch(error => {
            console.error('Logout error:', error);
        });
    } else {
        window.location.href = '/login';
    }
}

// 页面加载时初始化token和导航
document.addEventListener('DOMContentLoaded', function() {
    // 获取当前路径
    const currentPath = window.location.pathname;
    
    // 高亮当前活动的导航链接
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

// 处理浏览器前进/后退
window.addEventListener('popstate', function() {
    const currentPath = window.location.pathname;
    navigateTo(currentPath);
});

// 添加错误处理
window.onerror = function(message, source, lineno, colno, error) {
    console.error('Global error:', message, 'at', source, 'line', lineno, 'column', colno);
    console.error('Error object:', error);
    return false;
};

// 显示创建任务表单
window.showCreateTaskForm = function() {
    // 移除现有的模态框
    const existingModal = document.querySelector('.modal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // 创建模态框
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'createTaskModal';
    modal.setAttribute('tabindex', '-1');
    modal.setAttribute('aria-labelledby', 'createTaskModalLabel');
    modal.setAttribute('aria-hidden', 'true');
    
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="createTaskModalLabel">创建新任务</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="createTaskForm">
                        <div class="mb-3">
                            <label for="taskTitle" class="form-label">任务标题</label>
                            <input type="text" class="form-control" id="taskTitle" required>
                        </div>
                        <div class="mb-3">
                            <label for="taskDescription" class="form-label">任务描述</label>
                            <textarea class="form-control" id="taskDescription" rows="3"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="taskPriority" class="form-label">优先级</label>
                            <select class="form-select" id="taskPriority">
                                <option value="low">低</option>
                                <option value="medium" selected>中</option>
                                <option value="high">高</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label for="taskDueDate" class="form-label">截止日期</label>
                            <input type="date" class="form-control" id="taskDueDate">
                        </div>
                        <div class="mb-3">
                            <label for="taskProject" class="form-label">所属项目</label>
                            <select class="form-select" id="taskProject" required>
                                <option value="">请选择项目</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="submitCreateTask()">创建</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // 加载项目列表
    loadProjects();
    
    // 显示模态框
    const modalInstance = new bootstrap.Modal(modal);
    modalInstance.show();
}

// 提交创建任务表单
window.submitCreateTask = async function() {
    const token = localStorage.getItem('access_token');
    if (!token) {
        console.error('No token found');
        return;
    }
    
    const title = document.getElementById('taskTitle').value;
    const description = document.getElementById('taskDescription').value;
    const priority = document.getElementById('taskPriority').value;
    const dueDate = document.getElementById('taskDueDate').value;
    const projectId = document.getElementById('taskProject').value;
    
    if (!title || !projectId) {
        alert('请填写任务标题并选择项目');
        return;
    }
    
    try {
        const response = await fetch('/tasks', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                title: title,
                description: description,
                priority: priority,
                due_date: dueDate,
                project_id: projectId
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        // 关闭模态框
        const modal = bootstrap.Modal.getInstance(document.getElementById('createTaskModal'));
        modal.hide();

        // 刷新任务列表
        loadTasks();
    } catch (error) {
        console.error('Error creating task:', error);
        showError('创建任务失败');
    }
};

function displayTasks(tasks) {
    const mainContent = document.getElementById('main-content');
    if (!mainContent) return;

    const tasksHtml = tasks.map(task => `
        <div class="task-item">
            <h3>${task.title}</h3>
            <p>${task.description}</p>
            <p>Status: ${task.status}</p>
            <p>Due: ${task.due_date}</p>
        </div>
    `).join('');

    mainContent.innerHTML = `
        <div class="tasks-container">
            <h2>Tasks</h2>
            ${tasksHtml}
        </div>
    `;
}

function displayDashboard(data) {
    const mainContent = document.getElementById('main-content');
    if (!mainContent) return;

    let html = `
        <div class="container mt-4">
            <h2>Dashboard</h2>
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Welcome, ${data.username}!</h5>
                            <p class="card-text">Email: ${data.email}</p>
                            <p class="card-text">Role: ${data.role}</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Quick Stats</h5>
                            <p class="card-text">Tasks: ${data.task_count || 0}</p>
                            <p class="card-text">Completed: ${data.completed_tasks || 0}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    mainContent.innerHTML = html;
} 