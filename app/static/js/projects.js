/**
 * 加载项目列表
 */
function loadProjects() {
    console.log('加载项目列表...');
    
    // 显示加载指示器
    const tableBody = document.querySelector('table tbody');
    if (tableBody) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center py-3"><div class="spinner-border text-primary" role="status"></div><p class="mt-2">加载项目数据...</p></td></tr>';
    }
    
    // 发送请求获取项目列表
    fetch('/api/projects')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('获取到项目数据:', data);
            renderProjects(data);
            
            // 项目列表加载完成后，确保检查按钮显示权限
            setupProjectUIBasedOnPermissions();
        })
        .catch(error => {
            console.error('获取项目列表失败:', error);
            if (tableBody) {
                tableBody.innerHTML = `<tr><td colspan="7" class="text-center py-3">
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle-fill"></i> 
                        加载项目失败: ${error.message}
                    </div>
                </td></tr>`;
            }
        });
}

/**
 * 渲染项目列表
 */
function renderProjects(projects) {
    const tableBody = document.querySelector('table tbody');
    if (!tableBody) return;
    
    if (!projects || projects.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" class="text-center py-3">
            <div class="alert alert-info">
                <i class="bi bi-info-circle-fill"></i> 
                暂无项目数据
            </div>
        </td></tr>`;
        return;
    }
    
    // 生成项目列表HTML
    let html = '';
    for (const project of projects) {
        html += `
        <tr data-project-id="${project.id}">
            <td>${project.name}</td>
            <td>${project.manager || '未分配'}</td>
            <td>${project.start_date || '未设置'}</td>
            <td>${project.end_date || '未设置'}</td>
            <td>
                <div class="progress">
                    <div class="progress-bar" role="progressbar" style="width: ${project.progress || 0}%">
                        ${project.progress || 0}%
                    </div>
                </div>
            </td>
            <td>
                <span class="badge bg-${getStatusColor(project.status)}">
                    ${project.status || '未设置'}
                </span>
            </td>
            <td>
                <div class="project-operations">
                    <a href="/projects/${project.id}" class="btn btn-sm btn-outline-primary">
                        <i class="bi bi-eye"></i>
                    </a>
                    <button type="button" class="btn btn-sm btn-outline-secondary edit-btn" onclick="editProject(${project.id})">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button type="button" class="btn btn-sm btn-outline-danger delete-btn" onclick="deleteProject(${project.id})">
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
    console.log('初始化项目管理页面');
    
    // 检查用户权限，控制界面元素显示
    setupProjectUIBasedOnPermissions();
    
    // 确保项目加载后的其他初始化
    if (typeof loadManagersForNewProject === 'function') {
        console.log('正在检查项目负责人选择框...');
        setTimeout(() => {
            const managerSelect = document.getElementById('projectManager');
            if (managerSelect && managerSelect.options.length <= 1) {
                console.log('项目负责人选择框为空，正在加载数据...');
                loadManagersForNewProject();
            }
        }, 500);
    }
    
    // 加载甘特图
    setTimeout(() => {
        loadGanttChart();
    }, 1000);
});

// 根据用户权限设置项目界面元素
function setupProjectUIBasedOnPermissions() {
    // 检查用户是否有创建项目的权限
    const canCreateProject = hasPermission('create_project');
    // 检查用户是否有管理项目的权限
    const canManageProject = hasPermission('manage_project') || hasPermission('manage_all_projects');
    
    console.log('项目权限检查:', { canCreateProject, canManageProject });
    
    // 设置"新建项目"按钮可见性
    const newProjectButtons = document.querySelectorAll('.new-project-btn, .create-project-btn, [data-action="new-project"]');
    newProjectButtons.forEach(button => {
        if (button) {
            button.style.display = canCreateProject ? 'inline-block' : 'none';
        }
    });
    
    // 设置项目编辑按钮可见性
    const projectEditButtons = document.querySelectorAll('.edit-btn, .project-edit-btn, [data-action="edit-project"]');
    projectEditButtons.forEach(button => {
        if (button) {
            button.style.display = canManageProject ? 'inline-block' : 'none';
        }
    });
    
    // 设置项目删除按钮可见性
    const projectDeleteButtons = document.querySelectorAll('.delete-btn, .project-delete-btn, [data-action="delete-project"]');
    projectDeleteButtons.forEach(button => {
        if (button) {
            button.style.display = canManageProject ? 'inline-block' : 'none';
        }
    });
    
    // 如果用户没有创建项目权限，隐藏新建项目模态框触发按钮
    const newProjectModalTriggers = document.querySelectorAll('[data-bs-toggle="modal"][data-bs-target="#newProjectModal"]');
    newProjectModalTriggers.forEach(trigger => {
        if (trigger) {
            trigger.style.display = canCreateProject ? 'inline-block' : 'none';
        }
    });
}

// 在编辑项目时获取和显示管理员列表
function loadProjectManagers() {
    fetch('/api/project-managers?bypass_jwt=true')
        .then(response => {
            if (!response.ok) {
                throw new Error(`获取项目经理列表失败: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.project_managers) {
                throw new Error('项目经理数据格式错误');
            }
            
            const managerSelect = document.getElementById('projectManager');
            if (managerSelect) {
                // 清空现有选项
                managerSelect.innerHTML = '';
                
                // 添加默认选项
                const defaultOption = document.createElement('option');
                defaultOption.value = '';
                defaultOption.textContent = '-- 选择负责人 --';
                managerSelect.appendChild(defaultOption);
                
                // 添加所有管理员
                data.project_managers.forEach(manager => {
                    const option = document.createElement('option');
                    option.value = manager.id;
                    option.textContent = manager.name;
                    managerSelect.appendChild(option);
                });
                
                console.log(`已加载 ${data.project_managers.length} 个项目经理选项`);
            }
        })
        .catch(error => {
            console.error('加载项目经理失败:', error);
        });
}

// 保存项目
async function saveProject() {
    try {
        const form = document.getElementById('projectForm');
        if (!form.checkValidity()) {
            console.log('表单验证失败');
            form.reportValidity();
            return;
        }
        
        // 获取表单数据
        const formData = {
            name: document.getElementById('projectName').value.trim(),
            manager_id: document.getElementById('projectManager').value || null,
            start_date: document.getElementById('startDate').value,
            end_date: document.getElementById('endDate').value,
            description: document.getElementById('projectDescription').value.trim() || '',
            status: 'planning'  // 新项目默认状态为规划中
        };
        
        // 日志记录表单数据
        console.log('准备创建新项目:', formData);
        
        // 验证必填字段
        if (!formData.name) {
            console.log('项目名称为空');
            alert('项目名称不能为空');
            return;
        }
        
        if (!formData.start_date) {
            console.log('开始日期为空');
            alert('开始日期不能为空');
            return;
        }
        
        if (formData.end_date && formData.end_date < formData.start_date) {
            console.log('日期验证失败:', formData.start_date, formData.end_date);
            alert('结束日期不能早于开始日期');
            return;
        }
        
        // 获取CSRF令牌
        const csrfToken = getCsrfToken();
        
        // 构建请求头
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        
        // 如果有CSRF令牌，添加到请求头
        if (csrfToken) {
            headers['X-CSRF-TOKEN'] = csrfToken;
            headers['X-CSRFToken'] = csrfToken;
        }
        
        // 项目API的URL
        const apiUrl = '/api/auth/projects?bypass_jwt=true';
        console.log('发送创建项目请求到:', apiUrl);
        console.log('请求头:', headers);
        console.log('请求体:', JSON.stringify(formData));
        
        // 发送创建项目的请求
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(formData),
            credentials: 'include'
        });
        
        console.log('创建项目响应状态:', response.status);
        
        // 尝试解析响应，即使状态码不是200也尝试获取错误信息
        let responseData;
        try {
            const responseText = await response.text();
            console.log('服务器原始响应:', responseText);
            responseData = JSON.parse(responseText);
        } catch (e) {
            console.warn('无法解析服务器响应JSON:', e);
            responseData = { error: '无法解析服务器响应' };
        }
        
        if (response.ok) {
            console.log('创建项目成功:', responseData);
            
            // 关闭模态框
            const modal = document.getElementById('newProjectModal');
            if (modal) {
                const modalInstance = bootstrap.Modal.getInstance(modal);
                if (modalInstance) {
                    modalInstance.hide();
                } else {
                    // 备用关闭方法
                    modal.classList.remove('show');
                    modal.style.display = 'none';
                    document.body.classList.remove('modal-open');
                    
                    // 移除背景遮罩
                    const backdrop = document.querySelector('.modal-backdrop');
                    if (backdrop) {
                        backdrop.remove();
                    }
                }
            }
            
            // 显示成功消息
            showSuccessMessage('项目创建成功！');
            
            // 刷新页面
            setTimeout(() => {
                window.location.reload();
            }, 800);
        } else {
            console.error('创建项目失败:', responseData);
            showErrorMessage('项目创建失败: ' + responseData.error);
        }
    } catch (error) {
        console.error('保存项目时发生错误:', error);
        showErrorMessage('保存项目时发生错误: ' + error.message);
    }
}

// 编辑项目
function editProject(projectId) {
    console.log('编辑项目:', projectId);
    
    // 获取项目详情
    fetch(`/api/auth/projects/${projectId}?bypass_jwt=true`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`获取项目详情失败: ${response.status} ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('获取到项目数据:', data);
            
            // 检查编辑模态框是否存在
            const editModal = document.getElementById('editProjectModal');
            if (!editModal) {
                console.error('找不到编辑模态框 #editProjectModal');
                alert('无法加载编辑界面：找不到编辑模态框');
                return;
            }
            
            // 在设置任何表单值之前检查所有必需的表单元素
            const requiredElements = [
                { id: 'editProjectId', name: '项目ID' },
                { id: 'editProjectName', name: '项目名称' },
                { id: 'editProjectDescription', name: '项目描述' },
                { id: 'editProjectStatus', name: '项目状态' }
            ];
            
            let missingElements = [];
            for (const elem of requiredElements) {
                if (!document.getElementById(elem.id)) {
                    missingElements.push(elem.name);
                }
            }
            
            if (missingElements.length > 0) {
                console.error('编辑表单缺少必要元素:', missingElements.join(', '));
                alert(`无法加载编辑界面：表单缺少必要元素 (${missingElements.join(', ')})`);
                return;
            }
            
            // 填充编辑表单
            document.getElementById('editProjectId').value = projectId;
            document.getElementById('editProjectName').value = data.name || '';
            document.getElementById('editProjectDescription').value = data.description || '';
            document.getElementById('editProjectStatus').value = data.status || 'planning';
            
            // 如果有编辑器中的其他字段，也填充它们 - 添加存在性检查
            const editStartDateField = document.getElementById('editStartDate');
            if (editStartDateField && data.start_date) {
                editStartDateField.value = data.start_date;
            }
            
            const editEndDateField = document.getElementById('editEndDate');
            if (editEndDateField && data.end_date) {
                editEndDateField.value = data.end_date;
            }
            
            const editManagerField = document.getElementById('editProjectManager');
            if (editManagerField && data.manager_id) {
                editManagerField.value = data.manager_id;
            }
            
            // 显示编辑模态框
            try {
                const bsModal = new bootstrap.Modal(editModal);
                bsModal.show();
            } catch (error) {
                console.error('无法显示编辑模态框:', error);
                // 使用备用方法显示模态框
                editModal.classList.add('show');
                editModal.style.display = 'block';
                document.body.classList.add('modal-open');
                
                // 添加背景遮罩
                const backdrop = document.createElement('div');
                backdrop.className = 'modal-backdrop fade show';
                document.body.appendChild(backdrop);
            }
            
            // 加载负责人列表
            if (typeof loadProjectManagers === 'function') {
                loadProjectManagers();
            }
        })
        .catch(error => {
            console.error('获取项目详情失败:', error);
            alert('无法加载项目详情: ' + error.message);
        });
}

// 加载甘特图
function loadGanttChart() {
    console.log('正在加载甘特图...');
    
    // 显示加载中状态
    const ganttLoadingElement = document.getElementById('ganttLoading');
    const ganttChartElement = document.getElementById('ganttChart');
    const ganttErrorElement = document.getElementById('ganttError');
    
    if (!ganttChartElement) {
        console.error('找不到甘特图容器元素 #ganttChart');
        return;
    }
    
    if (ganttLoadingElement) {
        ganttLoadingElement.classList.remove('d-none');
    }
    
    if (ganttErrorElement) {
        ganttErrorElement.classList.add('d-none');
    }
    
    // 尝试从服务器获取甘特图数据
    fetch('/tasks/project/all/gantt/data?bypass_jwt=true')
        .then(response => {
            if (!response.ok) {
                throw new Error(`获取甘特图数据失败: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('获取到甘特图数据:', data);
            
            if (!data || !data.data || data.data.length === 0) {
                console.warn('甘特图数据为空');
                showGanttError('没有可用的任务数据');
                return;
            }
            
            // 准备甘特图任务
            const tasks = data.data.map(task => ({
                id: task.id,
                name: task.text || `任务 #${task.id}`,
                start: task.start_date,
                end: task.end_date,
                progress: task.progress || 0,
                dependencies: []
            }));
            
            // 添加依赖关系
            if (data.links && Array.isArray(data.links)) {
                data.links.forEach(link => {
                    const task = tasks.find(t => t.id == link.target);
                    if (task) {
                        task.dependencies.push(link.source.toString());
                    }
                });
            }
            
            // 初始化甘特图
            try {
                // 清空容器
                ganttChartElement.innerHTML = '';
                
                // 创建甘特图实例
                window.gantt = new Gantt(ganttChartElement, tasks, {
                    header_height: 50,
                    column_width: 30,
                    step: 24,
                    view_modes: ['Quarter Day', 'Half Day', 'Day', 'Week', 'Month'],
                    bar_height: 20,
                    bar_corner_radius: 3,
                    arrow_curve: 5,
                    padding: 18,
                    view_mode: 'Month',
                    date_format: 'YYYY-MM-DD',
                    custom_popup_html: null
                });
                
                // 隐藏加载中状态
                if (ganttLoadingElement) {
                    ganttLoadingElement.classList.add('d-none');
                }
                
                console.log('甘特图加载完成');
            } catch (error) {
                console.error('初始化甘特图失败:', error);
                showGanttError(`初始化甘特图失败: ${error.message}`);
            }
        })
        .catch(error => {
            console.error('获取甘特图数据失败:', error);
            showGanttError(`获取甘特图数据失败: ${error.message}`);
        });
}

// 显示甘特图错误
function showGanttError(message) {
    const ganttLoadingElement = document.getElementById('ganttLoading');
    const ganttErrorElement = document.getElementById('ganttError');
    const errorMessageElement = document.getElementById('errorMessage');
    
    if (ganttLoadingElement) {
        ganttLoadingElement.classList.add('d-none');
    }
    
    if (ganttErrorElement) {
        ganttErrorElement.classList.remove('d-none');
        
        if (errorMessageElement) {
            errorMessageElement.textContent = message;
        }
    }
    
    console.error('甘特图错误:', message);
} 