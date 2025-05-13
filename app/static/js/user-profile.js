/**
 * 用户信息展示组件
 * 使用getUserInfo API获取并显示用户信息
 */
document.addEventListener('DOMContentLoaded', function() {
    // 查找用户信息容器
    const userInfoContainer = document.getElementById('user-info-container');
    if (!userInfoContainer) {
        console.log("未找到用户信息容器，跳过初始化");
        return;
    }
    
    console.log("初始化用户信息展示组件");
    
    // 载入用户信息
    loadUserInfo();
    
    // 添加刷新按钮事件监听
    const refreshButton = document.getElementById('refresh-user-info');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            loadUserInfo(true);
        });
    }
    
    /**
     * 加载并显示用户信息
     * @param {boolean} forceRefresh 是否强制从服务器刷新
     */
    async function loadUserInfo(forceRefresh = false) {
        try {
            // 显示加载状态
            userInfoContainer.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';
            
            let userData;
            
            if (forceRefresh) {
                // 从服务器获取最新数据
                userData = await getUserInfo();
                console.log("已从服务器刷新用户数据:", userData);
            } else {
                // 先尝试从localStorage获取
                const storedData = localStorage.getItem('user_info');
                if (storedData) {
                    try {
                        userData = JSON.parse(storedData);
                        console.log("从localStorage获取用户数据:", userData);
                    } catch (e) {
                        console.error("解析localStorage数据出错:", e);
                    }
                }
                
                // 如果没有本地数据或数据不完整，从服务器获取
                if (!userData || !userData.username) {
                    userData = await getUserInfo();
                    console.log("从服务器获取用户数据:", userData);
                }
            }
            
            // 如果获取数据失败
            if (!userData) {
                userInfoContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle-fill"></i> 
                        获取用户信息失败
                    </div>
                    <button class="btn btn-sm btn-outline-primary" id="retry-load-user">重试</button>
                `;
                
                // 添加重试按钮事件
                document.getElementById('retry-load-user')?.addEventListener('click', () => loadUserInfo(true));
                return;
            }
            
            // 显示用户信息
            userInfoContainer.innerHTML = `
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>用户信息</h5>
                        <button class="btn btn-sm btn-outline-primary" id="refresh-user-info">
                            <i class="bi bi-arrow-clockwise"></i> 刷新
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <strong>当前登录用户:</strong> ${userData.username}
                        </div>
                        <div class="mb-3">
                            <strong>角色:</strong> ${userData.roles ? userData.roles.join(', ') : '无'}
                        </div>
                        <div class="mb-3">
                            <strong>管理员权限:</strong> 
                            <span class="badge ${userData.is_admin ? 'bg-success' : 'bg-secondary'}">
                                ${userData.is_admin ? '是' : '否'}
                            </span>
                        </div>
                        <div class="mb-3">
                            <strong>上次登录:</strong> ${userData.last_login ? new Date(userData.last_login).toLocaleString() : '未知'}
                        </div>
                        <div class="mb-3">
                            <strong>邮箱:</strong> ${userData.email || '未设置'}
                        </div>
                        ${userData.permissions && userData.permissions.length > 0 ? `
                            <div class="mb-3">
                                <strong>权限:</strong>
                                <ul class="list-group list-group-flush">
                                    ${userData.permissions.map(perm => `
                                        <li class="list-group-item">${perm}</li>
                                    `).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                    <div class="card-footer text-muted">
                        用户ID: ${userData.id}
                    </div>
                </div>
            `;
            
            // 重新添加刷新按钮事件
            document.getElementById('refresh-user-info')?.addEventListener('click', () => loadUserInfo(true));
            
        } catch (error) {
            console.error("加载用户信息出错:", error);
            userInfoContainer.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-triangle-fill"></i> 
                    加载用户信息时发生错误: ${error.message}
                </div>
                <button class="btn btn-sm btn-outline-primary" id="retry-load-user">重试</button>
            `;
            
            // 添加重试按钮事件
            document.getElementById('retry-load-user')?.addEventListener('click', () => loadUserInfo(true));
        }
    }
}); 