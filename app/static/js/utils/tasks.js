/**
 * Task Operations Utilities
 * 提供任务操作的统一功能实现
 */

import { getCsrfToken, refreshCsrfToken } from '../csrf.js';

/**
 * 查看任务详情
 * @param {number} taskId - 任务ID
 */
export function viewTask(taskId) {
    window.location.href = `/tasks/${taskId}/view?bypass_jwt=true`;
}

/**
 * 编辑任务
 * @param {number} taskId - 任务ID
 */
export function editTask(taskId) {
    window.location.href = `/tasks/${taskId}/edit?bypass_jwt=true`;
}

/**
 * 删除任务
 * @param {number} taskId - 任务ID
 * @returns {Promise<boolean>} - 是否删除成功
 */
export async function deleteTask(taskId) {
    if (!confirm('确定要删除这个任务吗？')) {
        return false;
    }
    
    try {
        // 获取CSRF令牌 - 尝试多个来源
        let csrfToken = getCsrfToken();
        
        if (!csrfToken) {
            console.warn('删除任务时未找到CSRF令牌，尝试刷新获取');
            csrfToken = await refreshCsrfToken();
        }
        
        // 尝试从meta标签获取
        if (!csrfToken) {
            const metaTag = document.querySelector('meta[name="csrf-token"]');
            if (metaTag) {
                csrfToken = metaTag.getAttribute('content');
                console.log('从meta标签获取到CSRF令牌');
            }
        }
        
        // 尝试从localStorage获取
        if (!csrfToken) {
            csrfToken = localStorage.getItem('csrf_token');
            console.log('从localStorage获取到CSRF令牌');
        }
        
        // 构建请求头，添加多种CSRF令牌头以增加兼容性
        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        };
        
        if (csrfToken) {
            headers['X-CSRF-TOKEN'] = csrfToken;
            headers['X-CSRFToken'] = csrfToken;  // 添加另一种常见格式
            headers['csrf-token'] = csrfToken;   // 添加小写格式
        }
        
        console.log(`删除任务 ${taskId}, CSRF令牌: ${csrfToken ? '已获取' : '未获取'}`);
        
        // 构建URL，可能需要在URL中附加令牌
        let url = `/tasks/${taskId}?bypass_jwt=true`;
        if (csrfToken && !url.includes('csrf_token=')) {
            url += `&csrf_token=${encodeURIComponent(csrfToken)}`;
        }
        
        const response = await fetch(url, {
            method: 'DELETE',
            headers: headers,
            credentials: 'include' // 确保发送cookie
        });

        if (response.ok) {
            console.log(`任务 ${taskId} 删除成功`);
            // 处理成功删除
            return true;
        } else {
            // 尝试解析响应
            let error;
            try {
                error = await response.json();
            } catch (e) {
                // 如果无法解析JSON，可能是非JSON响应
                error = { message: await response.text() || '删除任务失败' };
            }
            
            // 如果是CSRF错误，尝试重新获取令牌并重试一次
            if (response.status === 400 && error.message && error.message.includes('CSRF')) {
                console.log('CSRF验证失败，尝试重新获取令牌并重试...');
                
                // 强制刷新CSRF令牌
                csrfToken = await refreshCsrfToken();
                
                if (csrfToken) {
                    // 更新请求头
                    headers['X-CSRF-TOKEN'] = csrfToken;
                    headers['X-CSRFToken'] = csrfToken;
                    headers['csrf-token'] = csrfToken;
                    
                    // 重试请求
                    const retryResponse = await fetch(`/tasks/${taskId}?bypass_jwt=true&csrf_token=${encodeURIComponent(csrfToken)}`, {
                        method: 'DELETE',
                        headers: headers,
                        credentials: 'include'
                    });
                    
                    if (retryResponse.ok) {
                        console.log(`任务 ${taskId} 删除成功（重试后）`);
                        return true;
                    } else {
                        const retryError = await retryResponse.json().catch(() => ({ message: '删除任务失败' }));
                        alert(retryError.message || '删除任务失败');
                        return false;
                    }
                }
            }
            
            alert(error.message || '删除任务失败');
            return false;
        }
    } catch (error) {
        console.error('删除任务时出错:', error);
        alert('删除任务时发生错误: ' + error.message);
        return false;
    }
}

/**
 * 更新任务状态
 * @param {number} taskId - 任务ID
 * @param {string} status - 新状态
 * @returns {Promise<boolean>} - 是否更新成功
 */
export async function updateTaskStatus(taskId, status) {
    try {
        // 获取CSRF令牌
        let csrfToken = getCsrfToken();
        
        if (!csrfToken) {
            console.warn('更新任务状态时未找到CSRF令牌，尝试刷新获取');
            csrfToken = await refreshCsrfToken();
        }
        
        const response = await fetch(`/tasks/${taskId}/status?bypass_jwt=true`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-TOKEN': csrfToken || ''
            },
            body: JSON.stringify({ status }),
            credentials: 'include'
        });

        if (response.ok) {
            return true;
        } else {
            const error = await response.json();
            alert(error.message || '更新任务状态失败');
            return false;
        }
    } catch (error) {
        console.error('Error:', error);
        alert('更新任务状态时发生错误');
        return false;
    }
}

// 初始化任务操作按钮
export function initTaskOperations() {
    // 为所有任务操作按钮添加事件监听
    document.addEventListener('click', function(event) {
        const target = event.target.closest('[data-action]');
        if (!target) return;
        
        const action = target.dataset.action;
        const taskId = target.dataset.taskId;
        
        if (!taskId) return;
        
        switch (action) {
            case 'view':
                viewTask(taskId);
                break;
            case 'edit':
                editTask(taskId);
                break;
            case 'delete':
                deleteTask(taskId).then(success => {
                    if (success) {
                        // 重新加载页面或从DOM中移除任务行
                        const taskRow = document.querySelector(`tr[data-task-id="${taskId}"]`);
                        if (taskRow) {
                            taskRow.remove();
                        } else {
                            window.location.reload();
                        }
                    }
                });
                break;
            default:
                console.warn(`未知的任务操作: ${action}`);
        }
    });
    
    // 初始化任务模态框
    initTaskModal();
}

/**
 * 初始化任务模态框，包括加载项目列表和负责人列表
 */
export function initTaskModal() {
    // 找到添加任务按钮和模态框
    const addTaskBtn = document.getElementById('addTaskBtn');
    const taskModal = document.getElementById('taskModal');
    
    if (!addTaskBtn || !taskModal) {
        console.log('未找到添加任务按钮或模态框元素');
        return;
    }
    
    // 监听添加任务按钮点击事件
    addTaskBtn.addEventListener('click', function() {
        console.log('打开任务模态框，初始化表单');
        
        // 重置表单
        const taskForm = document.getElementById('taskForm');
        if (taskForm) taskForm.reset();
        
        // 设置模态框标题为新建任务
        const modalTitle = document.getElementById('taskModalTitle');
        if (modalTitle) modalTitle.textContent = '新建任务';
        
        // 清空任务ID
        const taskIdInput = document.getElementById('taskId');
        if (taskIdInput) taskIdInput.value = '';
        
        // 加载项目列表（如果需要）
        loadProjectsForTaskModal();
        
        // 加载负责人列表
        loadAssigneesForTaskModal();
    });
    
    // 监听模态框显示事件
    taskModal.addEventListener('show.bs.modal', function() {
        // 确保每次打开模态框时都加载最新的项目和负责人列表
        loadProjectsForTaskModal();
        loadAssigneesForTaskModal();
    });
}

/**
 * 加载项目列表到任务模态框
 */
function loadProjectsForTaskModal() {
    const projectSelect = document.getElementById('taskProject');
    // 检查是否在项目详情页面，此时不需要加载项目列表
    if (!projectSelect) {
        console.log('未找到项目选择器，可能是在项目详情页面');
        return;
    }
    
    console.log('加载项目列表到任务模态框');
    
    // 显示加载中状态
    projectSelect.innerHTML = '<option value="">加载中...</option>';
    projectSelect.disabled = true;
    
    // 发送请求获取项目列表
    fetch('/api/projects?bypass_jwt=true')
        .then(response => {
            if (!response.ok) {
                throw new Error(`获取项目列表失败: ${response.status}`);
            }
            return response.json();
        })
        .then(projects => {
            console.log('成功加载项目列表:', projects);
            
            // 清空现有选项
            projectSelect.innerHTML = '';
            
            // 添加默认选项
            const defaultOption = document.createElement('option');
            defaultOption.value = '';
            defaultOption.textContent = '-- 选择项目 --';
            projectSelect.appendChild(defaultOption);
            
            // 添加项目选项
            if (Array.isArray(projects)) {
                projects.forEach(project => {
                    const option = document.createElement('option');
                    option.value = project.id;
                    option.textContent = project.name;
                    projectSelect.appendChild(option);
                });
            }
            
            // 启用选择器
            projectSelect.disabled = false;
        })
        .catch(error => {
            console.error('加载项目列表失败:', error);
            
            // 恢复正常状态
            projectSelect.innerHTML = '<option value="">-- 加载失败 --</option>';
            projectSelect.disabled = false;
        });
}

/**
 * 加载负责人列表到任务模态框
 */
function loadAssigneesForTaskModal() {
    const assigneeSelect = document.getElementById('taskAssignee');
    if (!assigneeSelect) {
        console.log('未找到负责人选择器');
        return;
    }
    
    console.log('加载负责人列表到任务模态框');
    
    // 显示加载中状态
    assigneeSelect.innerHTML = '<option value="">加载中...</option>';
    assigneeSelect.disabled = true;
    
    // 检查是否在项目详情页
    const projectIdInput = document.querySelector('input[name="project_id"]');
    const isProjectDetail = !!projectIdInput;
    
    // 如果在项目详情页，获取项目成员
    if (isProjectDetail) {
        const projectId = projectIdInput.value;
        console.log(`在项目详情页，获取项目 ${projectId} 的成员`);
        
        fetch(`/api/projects/${projectId}/members?bypass_jwt=true`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`获取项目成员失败: ${response.status}`);
                }
                return response.json();
            })
            .then(members => {
                console.log('成功加载项目成员:', members);
                populateAssigneeSelect(assigneeSelect, members);
            })
            .catch(error => {
                console.error('加载项目成员失败:', error);
                // 尝试加载所有用户作为备选
                loadAllUsers(assigneeSelect);
            });
    } else {
        // 如果不在项目详情页，加载所有用户
        loadAllUsers(assigneeSelect);
    }
}

/**
 * 加载所有用户到负责人选择器
 */
function loadAllUsers(assigneeSelect) {
    fetch('/api/users?bypass_jwt=true')
        .then(response => {
            if (!response.ok) {
                throw new Error(`获取用户列表失败: ${response.status}`);
            }
            return response.json();
        })
        .then(users => {
            console.log('成功加载所有用户:', users);
            populateAssigneeSelect(assigneeSelect, users);
        })
        .catch(error => {
            console.error('加载所有用户失败:', error);
            
            // 恢复正常状态
            assigneeSelect.innerHTML = '<option value="">-- 加载失败 --</option>';
            assigneeSelect.disabled = false;
        });
}

/**
 * 填充负责人选择器
 */
function populateAssigneeSelect(assigneeSelect, users) {
    // 清空现有选项
    assigneeSelect.innerHTML = '';
    
    // 添加默认选项
    const defaultOption = document.createElement('option');
    defaultOption.value = '';
    defaultOption.textContent = '-- 选择负责人 --';
    assigneeSelect.appendChild(defaultOption);
    
    // 添加用户选项
    if (Array.isArray(users)) {
        users.forEach(user => {
            const option = document.createElement('option');
            option.value = user.id;
            option.textContent = user.name || user.username || `用户 #${user.id}`;
            assigneeSelect.appendChild(option);
        });
    }
    
    // 启用选择器
    assigneeSelect.disabled = false;
}

// 导出函数到全局作用域，确保在未使用import时也能使用这些函数
window.viewTask = viewTask;
window.editTask = editTask;
window.deleteTask = deleteTask;
window.updateTaskStatus = updateTaskStatus;
window.initTaskOperations = initTaskOperations;
window.initTaskModal = initTaskModal; 