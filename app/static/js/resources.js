// 资源管理相关的全局变量
let resourcesTable;
let utilizationChart;
let allocationChart;
let resourceStatusChart;
let utilizationTrendChart;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeDataTables();
    loadResources();
    loadAllocations();
    startMonitoring();
    console.log('资源管理页面加载完成');
    
    // 加载资源类型列表到下拉菜单
    loadResourceTypes();
    
    // 初始化新建资源模态框事件
    const newResourceModal = document.getElementById('newResourceModal');
    if (newResourceModal) {
        newResourceModal.addEventListener('show.bs.modal', function() {
            document.getElementById('resourceForm').reset();
        });
    }

    // 根据用户权限设置资源界面元素
    setupResourceUIBasedOnPermissions();
});

// 初始化图表
function initializeCharts() {
    // 资源利用率图表
    const utilizationCtx = document.getElementById('utilizationChart').getContext('2d');
    utilizationChart = new Chart(utilizationCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '资源利用率',
                data: [],
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });

    // 资源分配图表
    const allocationCtx = document.getElementById('allocationChart').getContext('2d');
    allocationChart = new Chart(allocationCtx, {
        type: 'pie',
        data: {
            labels: ['已分配', '可用'],
            datasets: [{
                data: [0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(75, 192, 192, 0.2)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        }
    });

    // 资源状态图表
    const statusCtx = document.getElementById('resourceStatusChart').getContext('2d');
    resourceStatusChart = new Chart(statusCtx, {
        type: 'doughnut',
        data: {
            labels: ['正常', '警告', '超载'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.2)',
                    'rgba(255, 206, 86, 0.2)',
                    'rgba(255, 99, 132, 0.2)'
                ],
                borderColor: [
                    'rgba(75, 192, 192, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(255, 99, 132, 1)'
                ],
                borderWidth: 1
            }]
        }
    });

    // 利用率趋势图表
    const trendCtx = document.getElementById('utilizationTrendChart').getContext('2d');
    utilizationTrendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '利用率趋势',
                data: [],
                fill: false,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

// 初始化数据表格
function initializeDataTables() {
    resourcesTable = $('#resourcesTable').DataTable({
        pageLength: 10,
        order: [[0, 'asc']],
        language: {
            url: '/static/js/dataTables.chinese.json'
        }
    });
}

// 加载资源列表
function loadResources() {
    console.log('加载资源列表...');
    
    // 显示加载指示器
    const resourceList = document.getElementById('resourceList');
    if (resourceList) {
        resourceList.innerHTML = `
            <div class="text-center py-3">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2">加载资源数据...</p>
            </div>
        `;
    }
    
    // 发送请求获取资源列表
    fetch('/api/resources')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('获取到资源数据:', data);
            
            // 提取资源列表
            const resources = data.resources || [];
            renderResources(resources);
            
            // 资源列表加载完成后，检查按钮显示权限
            setupEditDeleteButtons();
        })
        .catch(error => {
            console.error('获取资源列表失败:', error);
            if (resourceList) {
                resourceList.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle-fill"></i> 
                        加载资源失败: ${error.message}
                    </div>
                `;
            }
        });
}

// 渲染资源列表
function renderResources(resources) {
    const resourceList = document.getElementById('resourceList');
    if (!resourceList) return;
    
    if (!resources || resources.length === 0) {
        resourceList.innerHTML = `
            <div class="alert alert-info">
                <i class="bi bi-info-circle-fill"></i> 
                暂无资源数据
            </div>
        `;
        return;
    }
    
    // 创建表格显示资源
    let html = `
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>资源名称</th>
                        <th>类型</th>
                        <th>容量</th>
                        <th>单位</th>
                        <th>单位成本</th>
                        <th>利用率</th>
                        <th>状态</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    for (const resource of resources) {
        html += `
            <tr data-resource-id="${resource.id}">
                <td>${resource.name}</td>
                <td>${resource.type || '未分类'}</td>
                <td>${resource.quantity || resource.capacity || 0}</td>
                <td>${resource.unit || '个'}</td>
                <td>${resource.cost_per_unit || 0}</td>
                <td>
                    <div class="progress">
                        <div class="progress-bar" role="progressbar" style="width: ${resource.utilization_rate || 0}%">
                            ${resource.utilization_rate || 0}%
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${getStatusColor(resource.status)}">
                        ${resource.status || '可用'}
                    </span>
                </td>
                <td>
                    <div class="resource-operations">
                        <button type="button" class="btn btn-sm btn-outline-primary" onclick="viewResource(${resource.id})">
                            <i class="bi bi-eye"></i>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary edit-btn" onclick="editResource(${resource.id})">
                            <i class="bi bi-pencil"></i>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-danger delete-btn" onclick="deleteResource(${resource.id})">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    resourceList.innerHTML = html;
}

// 获取资源状态对应的颜色
function getStatusColor(status) {
    switch (status) {
        case 'available':
            return 'success';
        case 'allocated':
            return 'primary';
        case 'unavailable':
            return 'danger';
        case 'maintenance':
            return 'warning';
        default:
            return 'secondary';
    }
}

// 加载资源类型列表
function loadResourceTypes() {
    fetch('/resources/resource-types')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(types => {
            const typeSelect = document.getElementById('resourceType');
            if (typeSelect) {
                typeSelect.innerHTML = '';
                
                types.forEach(type => {
                    const option = document.createElement('option');
                    option.value = type.id;
                    option.textContent = type.name;
                    typeSelect.appendChild(option);
                });
            }
        })
        .catch(error => {
            console.error('加载资源类型失败:', error);
        });
}

// 保存资源
function saveResource() {
    const resourceForm = document.getElementById('resourceForm');
    
    // 简单表单验证
    const name = document.getElementById('resourceName').value;
    if (!name) {
        alert('请输入资源名称');
        return;
    }
    
    // 创建请求数据
    const resourceData = {
        name: name,
        type_id: document.getElementById('resourceType').value,
        capacity: document.getElementById('capacity').value,
        unit: document.getElementById('unit').value,
        cost_per_unit: document.getElementById('cost').value,
        description: document.getElementById('resourceDescription').value,
        status: 'available'
    };
    
    // 发送创建资源请求
    fetch('/api/resources', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': getCsrfToken()
        },
        body: JSON.stringify(resourceData)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('资源创建成功:', data);
        
        // 关闭模态框
        const modal = bootstrap.Modal.getInstance(document.getElementById('newResourceModal'));
        modal.hide();
        
        // 重新加载资源列表
        loadResources();
        
        // 显示成功消息
        alert('资源创建成功');
    })
    .catch(error => {
        console.error('创建资源失败:', error);
        alert('创建资源失败: ' + error.message);
    });
}

// 查看资源详情
function viewResource(id) {
    alert('查看资源详情: ' + id);
    // TODO: 实现资源详情查看功能
}

// 编辑资源
function editResource(id) {
    alert('编辑资源: ' + id);
    // TODO: 实现资源编辑功能
}

// 删除资源
function deleteResource(id) {
    if (confirm('确定要删除此资源吗？此操作不可撤销。')) {
        fetch(`/api/resources/${id}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-TOKEN': getCsrfToken()
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('资源删除成功:', data);
            
            // 从页面上移除资源
            const resourceElement = document.querySelector(`tr[data-resource-id="${id}"]`);
            if (resourceElement) {
                resourceElement.remove();
            }
            
            // 如果列表为空，显示提示信息
            const resourceList = document.querySelector('tbody');
            if (resourceList && resourceList.children.length === 0) {
                document.getElementById('resourceList').innerHTML = `
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle-fill"></i> 
                        暂无资源数据
                    </div>
                `;
            }
            
            // 显示成功消息
            alert('资源删除成功');
        })
        .catch(error => {
            console.error('删除资源失败:', error);
            alert('删除资源失败: ' + error.message);
        });
    }
}

// 导出资源列表
function exportResources() {
    alert('导出资源列表功能待实现');
    // TODO: 实现资源列表导出功能
}

// 加载资源分配
async function loadAllocations() {
    try {
        const response = await fetch('/api/resources/allocations');
        if (!response.ok) throw new Error('Failed to load allocations');
        const allocations = await response.json();
        
        // 更新分配表格
        const tbody = document.querySelector('#allocationsTable tbody');
        tbody.innerHTML = '';
        allocations.forEach(allocation => {
            tbody.innerHTML += `
                <tr>
                    <td>${allocation.resource_name}</td>
                    <td>${allocation.task_name}</td>
                    <td>${allocation.quantity}</td>
                    <td>${formatDate(allocation.start_date)}</td>
                    <td>${formatDate(allocation.end_date)}</td>
                    <td>
                        <span class="badge bg-${getAllocationStatusColor(allocation.status)}">
                            ${allocation.status}
                        </span>
                    </td>
                    <td>
                        <div class="btn-group">
                            ${allocation.status === 'pending' ? `
                                <button class="btn btn-sm btn-info" onclick="approveAllocation(${allocation.id})">
                                    <i class="fas fa-check"></i>
                                </button>
                            ` : ''}
                            <button class="btn btn-sm btn-warning" onclick="editAllocation(${allocation.id})">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="deleteAllocation(${allocation.id})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });
    } catch (error) {
        console.error('Error loading allocations:', error);
        showAlert('error', '加载资源分配失败');
    }
}

// 开始资源监控
function startMonitoring() {
    loadMonitoringData();
    setInterval(loadMonitoringData, 60000); // 每分钟更新一次
}

// 加载监控数据
async function loadMonitoringData() {
    try {
        // 加载资源使用情况
        const usageResponse = await fetch('/api/resources/usage');
        if (!usageResponse.ok) throw new Error('Failed to load resource usage');
        const usage = await usageResponse.json();
        
        // 加载告警信息
        const alertsResponse = await fetch('/api/resources/alerts');
        if (!alertsResponse.ok) throw new Error('Failed to load alerts');
        const alerts = await alertsResponse.json();
        
        // 更新监控表格
        updateMonitoringTable(usage);
        
        // 更新告警列表
        updateAlerts(alerts);
        
        // 更新监控图表
        updateMonitoringCharts(usage);
    } catch (error) {
        console.error('Error loading monitoring data:', error);
        showAlert('error', '加载监控数据失败');
    }
}

// 更新图表数据
function updateCharts(resources) {
    // 更新利用率图表
    utilizationChart.data.labels = resources.map(r => r.name);
    utilizationChart.data.datasets[0].data = resources.map(r => r.utilization_rate);
    utilizationChart.update();
    
    // 更新分配图表
    const totalAllocated = resources.reduce((sum, r) => sum + (r.quantity - r.available_quantity), 0);
    const totalAvailable = resources.reduce((sum, r) => sum + r.available_quantity, 0);
    allocationChart.data.datasets[0].data = [totalAllocated, totalAvailable];
    allocationChart.update();
}

// 更新监控表格
function updateMonitoringTable(usage) {
    const tbody = document.querySelector('#monitoringTable tbody');
    tbody.innerHTML = '';
    usage.forEach(item => {
        tbody.innerHTML += `
            <tr>
                <td>${item.resource_name}</td>
                <td>${item.total_quantity}</td>
                <td>${item.allocated_quantity}</td>
                <td>${item.available_quantity}</td>
                <td>
                    <div class="progress">
                        <div class="progress-bar" role="progressbar" style="width: ${item.utilization_rate}%">
                            ${item.utilization_rate}%
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${getStatusColor(item.status)}">
                        ${item.status}
                    </span>
                </td>
                <td>${formatDateTime(item.updated_at)}</td>
            </tr>
        `;
    });
}

// 更新告警列表
function updateAlerts(alerts) {
    const alertsContainer = document.getElementById('alerts');
    alertsContainer.innerHTML = '';
    alerts.forEach(alert => {
        alertsContainer.innerHTML += `
            <div class="list-group-item list-group-item-${getAlertSeverityClass(alert.severity)}">
                <div class="d-flex w-100 justify-content-between">
                    <h5 class="mb-1">${alert.title}</h5>
                    <small>${formatDateTime(alert.created_at)}</small>
                </div>
                <p class="mb-1">${alert.message}</p>
            </div>
        `;
    });
}

// 更新监控图表
function updateMonitoringCharts(usage) {
    // 更新状态图表
    const statusCounts = {
        normal: 0,
        warning: 0,
        overload: 0
    };
    usage.forEach(item => {
        if (item.utilization_rate < 70) statusCounts.normal++;
        else if (item.utilization_rate < 90) statusCounts.warning++;
        else statusCounts.overload++;
    });
    resourceStatusChart.data.datasets[0].data = [
        statusCounts.normal,
        statusCounts.warning,
        statusCounts.overload
    ];
    resourceStatusChart.update();
    
    // 更新趋势图表
    const now = new Date();
    utilizationTrendChart.data.labels.push(formatTime(now));
    utilizationTrendChart.data.datasets[0].data.push(
        usage.reduce((sum, item) => sum + item.utilization_rate, 0) / usage.length
    );
    if (utilizationTrendChart.data.labels.length > 60) {
        utilizationTrendChart.data.labels.shift();
        utilizationTrendChart.data.datasets[0].data.shift();
    }
    utilizationTrendChart.update();
}

// 工具函数
function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString();
}

function formatDateTime(dateString) {
    return new Date(dateString).toLocaleString();
}

function formatTime(date) {
    return date.toLocaleTimeString();
}

function getAllocationStatusColor(status) {
    switch (status.toLowerCase()) {
        case 'approved': return 'success';
        case 'pending': return 'warning';
        case 'rejected': return 'danger';
        default: return 'secondary';
    }
}

function getAlertSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'low': return 'info';
        case 'medium': return 'warning';
        case 'high': return 'danger';
        case 'critical': return 'dark';
        default: return 'secondary';
    }
}

// 显示提示信息
function showAlert(type, message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.alert-container').appendChild(alertDiv);
    setTimeout(() => alertDiv.remove(), 5000);
}

// 分配操作函数
async function approveAllocation(id) {
    try {
        const response = await fetch(`/api/resources/allocations/${id}/approve`, {
            method: 'POST'
        });
        
        if (!response.ok) throw new Error('Failed to approve allocation');
        
        loadAllocations();
        showAlert('success', '分配已批准');
    } catch (error) {
        console.error('Error approving allocation:', error);
        showAlert('error', '批准分配失败');
    }
}

async function editAllocation(id) {
    try {
        const response = await fetch(`/api/resources/allocations/${id}`);
        if (!response.ok) throw new Error('Failed to load allocation');
        const allocation = await response.json();
        
        // 显示编辑模态框
        const modal = new bootstrap.Modal(document.getElementById('allocationEditModal'));
        document.getElementById('editAllocationId').value = allocation.id;
        document.getElementById('editAllocationQuantity').value = allocation.quantity;
        document.getElementById('editAllocationStartDate').value = allocation.start_date.split('T')[0];
        document.getElementById('editAllocationEndDate').value = allocation.end_date.split('T')[0];
        modal.show();
    } catch (error) {
        console.error('Error editing allocation:', error);
        showAlert('error', '加载分配信息失败');
    }
}

async function saveAllocation() {
    const id = document.getElementById('editAllocationId').value;
    const data = {
        quantity: parseFloat(document.getElementById('editAllocationQuantity').value),
        start_date: document.getElementById('editAllocationStartDate').value,
        end_date: document.getElementById('editAllocationEndDate').value
    };
    
    try {
        const response = await fetch(`/api/resources/allocations/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) throw new Error('Failed to save allocation');
        
        // 关闭模态框并刷新数据
        bootstrap.Modal.getInstance(document.getElementById('allocationEditModal')).hide();
        loadAllocations();
        showAlert('success', '分配更新成功');
    } catch (error) {
        console.error('Error saving allocation:', error);
        showAlert('error', '保存分配失败');
    }
}

async function deleteAllocation(id) {
    if (!confirm('确定要删除这个分配吗？')) return;
    
    try {
        const response = await fetch(`/api/resources/allocations/${id}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) throw new Error('Failed to delete allocation');
        
        loadAllocations();
        showAlert('success', '分配删除成功');
    } catch (error) {
        console.error('Error deleting allocation:', error);
        showAlert('error', '删除分配失败');
    }
}

// 监控相关函数
function refreshMonitoring() {
    loadMonitoringData();
    showAlert('info', '监控数据已刷新');
}

// 导出相关函数
async function exportResourceReport() {
    try {
        const response = await fetch('/api/resources/reports', {
            method: 'POST'
        });
        
        if (!response.ok) throw new Error('Failed to generate report');
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `resource-report-${new Date().toISOString().split('T')[0]}.xlsx`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showAlert('success', '报告导出成功');
    } catch (error) {
        console.error('Error exporting report:', error);
        showAlert('error', '导出报告失败');
    }
}

// 根据用户权限设置资源界面元素
function setupResourceUIBasedOnPermissions() {
    // 检查用户是否有管理资源的权限
    const canManageResources = hasPermission('manage_resources');
    
    console.log('资源权限检查:', { canManageResources });
    
    // 设置"新建资源"按钮可见性
    const newResourceButtons = document.querySelectorAll('.new-resource-btn, .create-resource-btn, [data-action="new-resource"]');
    newResourceButtons.forEach(button => {
        if (button) {
            button.style.display = canManageResources ? 'inline-block' : 'none';
        }
    });
    
    // 设置资源编辑按钮可见性
    const resourceEditButtons = document.querySelectorAll('.edit-btn, .resource-edit-btn, [data-action="edit-resource"]');
    resourceEditButtons.forEach(button => {
        if (button) {
            button.style.display = canManageResources ? 'inline-block' : 'none';
        }
    });
    
    // 设置资源删除按钮可见性
    const resourceDeleteButtons = document.querySelectorAll('.delete-btn, .resource-delete-btn, [data-action="delete-resource"]');
    resourceDeleteButtons.forEach(button => {
        if (button) {
            button.style.display = canManageResources ? 'inline-block' : 'none';
        }
    });
    
    // 资源分配按钮
    const resourceAllocationButtons = document.querySelectorAll('.allocate-resource-btn, [data-action="allocate-resource"]');
    resourceAllocationButtons.forEach(button => {
        if (button) {
            button.style.display = canManageResources ? 'inline-block' : 'none';
        }
    });
    
    // 如果用户没有管理资源权限，隐藏相关模态框触发按钮
    const resourceModalTriggers = document.querySelectorAll('[data-bs-toggle="modal"][data-bs-target="#newResourceModal"], [data-bs-toggle="modal"][data-bs-target="#editResourceModal"]');
    resourceModalTriggers.forEach(trigger => {
        if (trigger) {
            trigger.style.display = canManageResources ? 'inline-block' : 'none';
        }
    });
} 