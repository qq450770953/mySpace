// Main JavaScript file

import { init } from './utils/init';
import store from './store';
import router from './router';
import { showError, showSuccess } from './utils/notify';

// 全局变量
let currentUser = null;
let accessToken = localStorage.getItem('access_token');

// 初始化函数
function init() {
    // 检查认证状态
    checkAuth();
    
    // 初始化工具提示
    initTooltips();
    
    // 初始化弹出框
    initPopovers();
    
    // 初始化日期选择器
    initDatePickers();
    
    // 初始化表格排序
    initTableSorting();
    
    // 初始化文件上传
    initFileUpload();
}

// 检查认证状态
function checkAuth() {
    if (!accessToken && !window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {
        window.location.href = '/login';
        return;
    }
    
    if (accessToken) {
        // 获取当前用户信息
        fetch('/api/users/me', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            }
            throw new Error('获取用户信息失败');
        })
        .then(user => {
            currentUser = user;
            updateUserInfo();
        })
        .catch(error => {
            console.error('Error:', error);
            localStorage.removeItem('access_token');
            window.location.href = '/login';
        });
    }
}

// 更新用户信息显示
function updateUserInfo() {
    if (currentUser) {
        const userInfoElements = document.querySelectorAll('.user-info');
        userInfoElements.forEach(element => {
            if (element.dataset.field === 'name') {
                element.textContent = currentUser.name;
            } else if (element.dataset.field === 'role') {
                element.textContent = currentUser.role;
            }
        });
    }
}

// 初始化工具提示
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// 初始化弹出框
function initPopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// 初始化日期选择器
function initDatePickers() {
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        if (!input.value) {
            input.value = new Date().toISOString().split('T')[0];
        }
    });
}

// 初始化表格排序
function initTableSorting() {
    const tables = document.querySelectorAll('table[data-sortable="true"]');
    tables.forEach(table => {
        const headers = table.querySelectorAll('th[data-sortable="true"]');
        headers.forEach(header => {
            header.addEventListener('click', () => {
                const column = header.dataset.column;
                const direction = header.dataset.direction === 'asc' ? 'desc' : 'asc';
                
                // 更新排序方向
                headers.forEach(h => h.dataset.direction = '');
                header.dataset.direction = direction;
                
                // 排序表格
                sortTable(table, column, direction);
            });
        });
    });
}

// 表格排序函数
function sortTable(table, column, direction) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    rows.sort((a, b) => {
        const aValue = a.querySelector(`td[data-column="${column}"]`).textContent;
        const bValue = b.querySelector(`td[data-column="${column}"]`).textContent;
        
        if (direction === 'asc') {
            return aValue.localeCompare(bValue);
        } else {
            return bValue.localeCompare(aValue);
        }
    });
    
    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
}

// 初始化文件上传
function initFileUpload() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                const formData = new FormData();
                formData.append('file', file);
                
                // 显示上传进度
                const progressBar = document.createElement('div');
                progressBar.className = 'progress mt-2';
                progressBar.innerHTML = `
                    <div class="progress-bar" role="progressbar" style="width: 0%"></div>
                `;
                input.parentNode.appendChild(progressBar);
                
                // 上传文件
                fetch('/api/upload', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'Authorization': `Bearer ${accessToken}`
                    }
                })
                .then(response => {
                    if (response.ok) {
                        return response.json();
                    }
                    throw new Error('文件上传失败');
                })
                .then(data => {
                    progressBar.querySelector('.progress-bar').style.width = '100%';
                    setTimeout(() => progressBar.remove(), 1000);
                    // 处理上传成功后的逻辑
                })
                .catch(error => {
                    console.error('Error:', error);
                    progressBar.remove();
                    alert('文件上传失败');
                });
            }
        });
    });
}

// 显示加载动画
function showLoading() {
    const loadingElement = document.createElement('div');
    loadingElement.className = 'loading-overlay';
    loadingElement.innerHTML = `
        <div class="loading-spinner">
            <div class="loading"></div>
            <p>加载中...</p>
        </div>
    `;
    document.body.appendChild(loadingElement);
}

// 隐藏加载动画
function hideLoading() {
    const loadingElement = document.querySelector('.loading-overlay');
    if (loadingElement) {
        loadingElement.remove();
    }
}

// 显示成功消息
function showSuccess(message) {
    const toast = document.createElement('div');
    toast.className = 'toast align-items-center text-white bg-success border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    document.body.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// 显示错误消息
function showError(message) {
    const toast = document.createElement('div');
    toast.className = 'toast align-items-center text-white bg-danger border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    document.body.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// 确认对话框
function confirmDialog(message, callback) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.setAttribute('tabindex', '-1');
    modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">确认</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>${message}</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" id="confirmButton">确定</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    modal.querySelector('#confirmButton').addEventListener('click', () => {
        bsModal.hide();
        callback();
    });
    
    modal.addEventListener('hidden.bs.modal', () => {
        modal.remove();
    });
}

// 检查用户是否具有特定权限
function hasPermission(permissionName) {
    // 从浏览器本地存储中获取用户信息
    let userInfo = localStorage.getItem('user_info');
    if (!userInfo) {
        // 尝试从sessionStorage获取
        userInfo = sessionStorage.getItem('user_info');
    }
    
    if (userInfo) {
        try {
            const user = JSON.parse(userInfo);
            // 检查用户是否有指定权限
            if (user.permissions && Array.isArray(user.permissions)) {
                return user.permissions.includes(permissionName);
            }
            // 如果是管理员角色，默认拥有所有权限
            if (user.roles && Array.isArray(user.roles) && user.roles.includes('admin')) {
                return true;
            }
        } catch (e) {
            console.error('解析用户信息时出错:', e);
        }
    }
    
    // 如果找不到用户信息，检查全局变量
    if (window.userPermissions && Array.isArray(window.userPermissions)) {
        return window.userPermissions.includes(permissionName);
    }
    
    // 检查JWT令牌中的权限信息
    const token = localStorage.getItem('access_token');
    if (token) {
        try {
            // 尝试从JWT令牌中解析权限
            const payload = JSON.parse(atob(token.split('.')[1]));
            if (payload && payload.permissions && Array.isArray(payload.permissions)) {
                return payload.permissions.includes(permissionName);
            }
            // 如果令牌中有角色信息且用户是管理员，默认拥有所有权限
            if (payload && payload.roles && Array.isArray(payload.roles) && payload.roles.includes('admin')) {
                return true;
            }
        } catch (e) {
            console.warn('从JWT解析权限信息失败:', e);
        }
    }
    
    return false;
}

// 将hasPermission函数暴露到全局作用域
window.hasPermission = hasPermission;

// 根据用户权限设置编辑和删除按钮的可见性
function setupEditDeleteButtons() {
    // 检查用户是否有创建和管理项目/任务的权限
    const canManageProject = hasPermission('manage_project') || hasPermission('manage_all_projects');
    const canCreateProject = hasPermission('create_project');
    const canManageTask = hasPermission('manage_task') || hasPermission('manage_all_tasks');
    const canCreateTask = hasPermission('create_task');
    
    console.log('用户权限:', {
        canManageProject,
        canCreateProject,
        canManageTask,
        canCreateTask
    });
    
    // 设置项目相关按钮
    const projectEditButtons = document.querySelectorAll('.project-edit-btn, .edit-project-btn');
    const projectDeleteButtons = document.querySelectorAll('.project-delete-btn, .delete-project-btn');
    const createProjectButtons = document.querySelectorAll('.create-project-btn, .new-project-btn');
    
    projectEditButtons.forEach(button => {
        button.style.display = canManageProject ? 'inline-block' : 'none';
    });
    
    projectDeleteButtons.forEach(button => {
        button.style.display = canManageProject ? 'inline-block' : 'none';
    });
    
    createProjectButtons.forEach(button => {
        button.style.display = canCreateProject ? 'inline-block' : 'none';
    });
    
    // 设置任务相关按钮
    const taskEditButtons = document.querySelectorAll('.task-edit-btn, .edit-task-btn');
    const taskDeleteButtons = document.querySelectorAll('.task-delete-btn, .delete-task-btn');
    const createTaskButtons = document.querySelectorAll('.create-task-btn, .new-task-btn');
    
    taskEditButtons.forEach(button => {
        button.style.display = canManageTask ? 'inline-block' : 'none';
    });
    
    taskDeleteButtons.forEach(button => {
        button.style.display = canManageTask ? 'inline-block' : 'none';
    });
    
    createTaskButtons.forEach(button => {
        button.style.display = canCreateTask ? 'inline-block' : 'none';
    });
    
    // 通用编辑和删除按钮（可能同时适用于项目和任务）
    const editButtons = document.querySelectorAll('.edit-btn:not(.project-edit-btn):not(.task-edit-btn)');
    const deleteButtons = document.querySelectorAll('.delete-btn:not(.project-delete-btn):not(.task-delete-btn)');
    
    editButtons.forEach(button => {
        // 根据按钮的数据属性或其他特征判断它是项目按钮还是任务按钮
        const isProjectButton = button.closest('[data-type="project"]') || button.classList.contains('project-related');
        const isTaskButton = button.closest('[data-type="task"]') || button.classList.contains('task-related');
        
        if (isProjectButton) {
            button.style.display = canManageProject ? 'inline-block' : 'none';
        } else if (isTaskButton) {
            button.style.display = canManageTask ? 'inline-block' : 'none';
        } else {
            // 如果无法确定，则需要同时拥有管理项目和任务的权限
            button.style.display = (canManageProject || canManageTask) ? 'inline-block' : 'none';
        }
    });
    
    deleteButtons.forEach(button => {
        // 同样的逻辑应用于删除按钮
        const isProjectButton = button.closest('[data-type="project"]') || button.classList.contains('project-related');
        const isTaskButton = button.closest('[data-type="task"]') || button.classList.contains('task-related');
        
        if (isProjectButton) {
            button.style.display = canManageProject ? 'inline-block' : 'none';
        } else if (isTaskButton) {
            button.style.display = canManageTask ? 'inline-block' : 'none';
        } else {
            button.style.display = (canManageProject || canManageTask) ? 'inline-block' : 'none';
        }
    });
}

// 初始化应用
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // 初始化工具函数
        init();
        
        // 检查认证状态
        if (store.state.isAuthenticated) {
            try {
                await store.actions.getCurrentUser();
            } catch (error) {
                console.error('获取用户信息失败:', error);
                store.mutations.setToken(null);
                store.mutations.setUser(null);
            }
        }
        
        // 初始化路由
        router.beforeEach = (to, from, next) => {
            const requiresAuth = to.matched.some(record => record.meta.requiresAuth);
            const requiresAdmin = to.matched.some(record => record.meta.requiresAdmin);
            const isAuthenticated = store.getters.isAuthenticated;
            const isAdmin = store.getters.currentUser?.role === 'admin';
            
            if (requiresAuth && !isAuthenticated) {
                showError('请先登录');
                next('/login');
            } else if (requiresAdmin && !isAdmin) {
                showError('权限不足');
                next('/403');
            } else {
                next();
            }
        };
        
        // 全局错误处理
        window.addEventListener('error', (event) => {
            console.error('全局错误:', event.error);
            showError('发生了一个错误，请刷新页面重试');
        });
        
        window.addEventListener('unhandledrejection', (event) => {
            console.error('未处理的Promise错误:', event.reason);
            showError('发生了一个错误，请刷新页面重试');
        });
        
        // 显示欢迎消息
        if (store.state.isAuthenticated) {
            showSuccess(`欢迎回来，${store.state.user.name}`);
        }
        
        // 设置编辑和删除按钮
        setupEditDeleteButtons();
        
    } catch (error) {
        console.error('应用初始化失败:', error);
        showError('应用初始化失败，请刷新页面重试');
    }
});
