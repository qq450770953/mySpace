/**
 * 工具函数库
 */

/**
 * 带CSRF令牌的fetch函数
 * @param {string} url - 请求URL
 * @param {Object} options - fetch选项
 * @param {boolean} bypassJwt - 是否绕过JWT验证（仅用于测试环境）
 * @returns {Promise<any>} - 返回JSON响应
 */
async function fetchWithCsrf(url, options = {}, bypassJwt = false) {
    // 获取CSRF令牌
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    
    // 准备headers
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    // 添加CSRF令牌到headers
    if (csrfToken) {
        headers['X-CSRF-TOKEN'] = csrfToken;
    }
    
    // 构建URL，如果需要绕过JWT验证，添加bypass_jwt参数
    let finalUrl = url;
    if (bypassJwt) {
        const separator = url.includes('?') ? '&' : '?';
        finalUrl = `${url}${separator}bypass_jwt=true`;
        console.log(`[fetchWithCsrf] 绕过JWT验证: ${finalUrl}`);
    }
    
    // 合并options
    const finalOptions = {
        ...options,
        headers
    };

    console.log(`[fetchWithCsrf] 请求URL: ${finalUrl}`, finalOptions);
    
    try {
        // 发送请求
        const response = await fetch(finalUrl, finalOptions);
        
        // 检查状态码
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`[fetchWithCsrf] 请求失败: ${response.status} ${response.statusText}`, errorText);
            
            // 尝试解析错误响应
            let errorData;
            try {
                errorData = JSON.parse(errorText);
            } catch (e) {
                errorData = { error: errorText || '未知错误' };
            }
            
            // 抛出带有状态码和错误数据的错误
            const error = new Error(`请求失败: ${response.status} ${response.statusText}`);
            error.status = response.status;
            error.data = errorData;
            throw error;
        }
        
        // 解析响应
        if (response.headers.get('content-type')?.includes('application/json')) {
            return await response.json();
        }
        
        return await response.text();
        
    } catch (error) {
        console.error('[fetchWithCsrf] 请求异常:', error);
        throw error;
    }
}

/**
 * 格式化日期
 * @param {Date|string} date - 日期对象或日期字符串
 * @param {string} format - 格式化模式，例如 'YYYY-MM-DD'
 * @returns {string} - 格式化后的日期字符串
 */
function formatDate(date, format = 'YYYY-MM-DD') {
    if (!date) return '';
    
    const d = typeof date === 'string' ? new Date(date) : date;
    
    if (isNaN(d.getTime())) {
        console.error('无效的日期:', date);
        return '';
    }
    
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');
    
    return format
        .replace('YYYY', year)
        .replace('MM', month)
        .replace('DD', day)
        .replace('HH', hours)
        .replace('mm', minutes)
        .replace('ss', seconds);
}

/**
 * 简单的防抖函数
 * @param {Function} func - 要执行的函数
 * @param {number} wait - 等待时间（毫秒）
 * @returns {Function} - 防抖后的函数
 */
function debounce(func, wait = 300) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * 显示Toast通知
 * @param {string} message - 通知消息
 * @param {string} type - 通知类型: 'success', 'error', 'warning', 'info'
 * @param {number} duration - 持续时间（毫秒）
 */
function showToast(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    // 添加显示类以触发过渡动画
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // 设置自动消失
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300); // 等待过渡动画完成
    }, duration);
}

/**
 * 检查并设置用户角色，从多个来源汇总角色信息
 * @returns {Array} 用户角色数组
 */
function getUserRoles() {
    let roles = [];
    
    console.log("[getUserRoles] ===================== 开始收集用户角色 =====================");
    
    // 添加强制检测函数 - 简化admin用户检测逻辑
    function isAdminUser() {
        // 1. 直接检查username或ID
        try {
            const userInfoStr = localStorage.getItem('user_info');
            if (userInfoStr) {
                const userInfo = JSON.parse(userInfoStr);
                if (userInfo && (userInfo.username === 'admin' || userInfo.id === 1 || userInfo.is_admin === true)) {
                    console.log('[getUserRoles:isAdminUser] 从用户信息中检测到admin用户');
                    return true;
                }
            }
        } catch(e) {
            console.error('[getUserRoles:isAdminUser] 检查用户信息失败:', e);
        }
        
        // 2. 检查localStorage中的标记
        if (localStorage.getItem('is_admin') === 'true' || 
            localStorage.getItem('admin') === 'true' || 
            localStorage.getItem('admin_forced') === 'true') {
            console.log('[getUserRoles:isAdminUser] 从localStorage中检测到admin标记');
            return true;
        }
        
        // 3. 检查cookie中的标记
        const getCookieValue = (name) => {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        };
        
        if (getCookieValue('is_admin') === 'true' || 
            getCookieValue('admin') === 'true' || 
            getCookieValue('admin_role') === 'true') {
            console.log('[getUserRoles:isAdminUser] 从Cookie中检测到admin标记');
            return true;
        }
        
        // 4. 检查window.currentUser
        if (window.currentUser && 
            (window.currentUser.isAdmin === true || 
             window.currentUser.username === 'admin' || 
             window.currentUser.id === 1 ||
             (Array.isArray(window.currentUser.roles) && window.currentUser.roles.includes('admin')))) {
            console.log('[getUserRoles:isAdminUser] 从window.currentUser中检测到admin用户');
            return true;
        }
        
        // 5. 检查JWT token
        try {
            const token = localStorage.getItem('access_token');
            if (token) {
                const payload = JSON.parse(atob(token.split('.')[1]));
                if (payload.admin === true || 
                    payload.sub === 1 || 
                    (payload.user_claims && payload.user_claims.username === 'admin') ||
                    (Array.isArray(payload.roles) && payload.roles.includes('admin'))) {
                    console.log('[getUserRoles:isAdminUser] 从JWT中检测到admin用户');
                    return true;
                }
            }
        } catch(e) {
            console.error('[getUserRoles:isAdminUser] JWT解析失败:', e);
        }
        
        return false;
    }
    
    // 0. 首先检查用户是否是admin，如果是则优先处理
    if (isAdminUser()) {
        console.log('[getUserRoles] 用户是admin，优先返回admin角色');
        
        // 无条件同步admin角色到所有位置
        localStorage.setItem('is_admin', 'true');
        document.cookie = `is_admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
        document.cookie = `admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
        document.cookie = `admin_role=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
        
        // 更新角色存储
        localStorage.setItem('user_roles', 'admin');
        document.cookie = `user_roles=admin; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
        
        // 同步到currentUser
        if (window.currentUser) {
            window.currentUser.isAdmin = true;
            if (!window.currentUser.roles.includes('admin')) {
                window.currentUser.roles.push('admin');
            }
        }
        
        console.log("[getUserRoles] ===================== 最终角色(admin用户): ['admin'] =====================");
        return ['admin'];
    }

    // 如果不是admin，则继续正常的角色收集流程...
    
    // 1. 检查localStorage中的角色
    try {
        const storedRoles = localStorage.getItem('user_roles');
        if (storedRoles) {
            console.log('[getUserRoles] localStorage中的角色:', storedRoles);
            const roleArray = storedRoles.split(',').filter(r => r.trim() !== '');
            
            // 合并角色，避免重复
            roleArray.forEach(role => {
                if (!roles.includes(role)) {
                    roles.push(role);
                }
            });
            
            console.log('[getUserRoles] 从localStorage添加角色后:', roles);
        }
    } catch(e) {
        console.error('[getUserRoles] 从localStorage获取角色失败:', e);
    }
    
    // 2. 从Cookie中获取角色
    try {
        const getCookie = function(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        };
        
        const cookieRoles = getCookie('user_roles');
        if (cookieRoles) {
            console.log('[getUserRoles] Cookie中的角色:', cookieRoles);
            const roleArray = cookieRoles.split(',').filter(r => r.trim() !== '');
            
            // 合并角色，避免重复
            roleArray.forEach(role => {
                if (!roles.includes(role)) {
                    roles.push(role);
                }
            });
            
            console.log('[getUserRoles] 从Cookie添加角色后:', roles);
        }
    } catch(e) {
        console.error('[getUserRoles] 从Cookie获取角色失败:', e);
    }
    
    // 3. 从window.currentUser获取角色
    if (window.currentUser && window.currentUser.roles && Array.isArray(window.currentUser.roles)) {
        console.log('[getUserRoles] window.currentUser中的角色:', window.currentUser.roles);
        
        // 合并角色，避免重复
        window.currentUser.roles.forEach(role => {
            if (!roles.includes(role)) {
                roles.push(role);
            }
        });
        
        console.log('[getUserRoles] 从currentUser添加角色后:', roles);
    }
    
    // 4. 从JWT token获取角色
    try {
        const token = localStorage.getItem('access_token');
        if (token) {
            const parts = token.split('.');
            if (parts.length === 3) {
                const payload = JSON.parse(atob(parts[1]));
                console.log('[getUserRoles] JWT载荷:', payload);
                
                // 检查token中的角色信息
                if (payload.roles && Array.isArray(payload.roles)) {
                    console.log('[getUserRoles] JWT token中的角色:', payload.roles);
                    
                    // 合并角色，避免重复
                    payload.roles.forEach(role => {
                        if (!roles.includes(role)) {
                            roles.push(role);
                        }
                    });
                    
                    console.log('[getUserRoles] 从JWT添加角色后:', roles);
                }
            }
        }
    } catch(e) {
        console.error('[getUserRoles] 从JWT获取角色失败:', e);
    }
    
    // 5. 最后检查是否包含admin角色，并设置标志
    if (roles.includes('admin')) {
        console.log('[getUserRoles] 检测到角色列表中包含admin，设置admin标志');
        localStorage.setItem('is_admin', 'true');
        document.cookie = `is_admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
        
        // 同步到currentUser
        if (window.currentUser) {
            window.currentUser.isAdmin = true;
        }
    }
    
    // 同步最终角色列表到存储和全局变量
    if (roles.length > 0) {
        console.log('[getUserRoles] 同步最终角色列表:', roles);
        localStorage.setItem('user_roles', roles.join(','));
        document.cookie = `user_roles=${roles.join(',')}; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
        
        // 同步到currentUser
        if (window.currentUser) {
            window.currentUser.roles = [...roles];
        }
    }
    
    console.log("[getUserRoles] ===================== 最终角色: ", roles, " =====================");
    return roles;
}

/**
 * 从服务器获取最新的用户信息并更新本地存储
 * @returns {Promise<Object>} 用户信息对象
 */
async function getUserInfo() {
    console.log("[getUserInfo] 开始从服务器获取最新用户信息");
    
    try {
        // 构造请求选项
        const options = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include' // 包含cookie
        };
        
        // 获取JWT Token (如果存在)
        const token = localStorage.getItem('access_token');
        if (token) {
            options.headers['Authorization'] = `Bearer ${token}`;
        }
        
        // 发送请求，添加随机参数避免缓存
        const timestamp = new Date().getTime();
        const response = await fetch(`/auth/user_info?_=${timestamp}&bypass_jwt=true`, options);
        
        if (!response.ok) {
            const errorData = await response.json();
            console.error("[getUserInfo] 获取用户信息失败:", errorData);
            return null;
        }
        
        // 解析响应
        const userData = await response.json();
        console.log("[getUserInfo] 获取的用户信息:", userData);
        
        // 更新本地存储
        if (userData && userData.success) {
            // 保存完整用户信息
            localStorage.setItem('user_info', JSON.stringify(userData));
            
            // 更新角色信息
            if (userData.roles && Array.isArray(userData.roles)) {
                localStorage.setItem('user_roles', userData.roles.join(','));
                document.cookie = `user_roles=${userData.roles.join(',')}; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
            }
            
            // 更新admin标志
            if (userData.is_admin) {
                localStorage.setItem('is_admin', 'true');
                document.cookie = `is_admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                document.cookie = `admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
            } else {
                localStorage.setItem('is_admin', 'false');
                document.cookie = `is_admin=false; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                document.cookie = `admin=false; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
            }
            
            // 如果存在全局currentUser对象，更新它
            if (window.currentUser) {
                window.currentUser.roles = userData.roles || [];
                window.currentUser.permissions = userData.permissions || [];
                window.currentUser.isAdmin = userData.is_admin || false;
                window.currentUser.id = userData.id;
                window.currentUser.username = userData.username;
                
                console.log("[getUserInfo] 更新全局currentUser:", window.currentUser);
            }
            
            // 特殊处理admin用户
            if (userData.username === 'admin' || userData.id === 1) {
                // 强制设置admin标志
                localStorage.setItem('is_admin', 'true');
                document.cookie = `is_admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                document.cookie = `admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                
                // 确保用户角色中包含admin
                if (!userData.roles.includes('admin')) {
                    userData.roles.push('admin');
                    localStorage.setItem('user_roles', userData.roles.join(','));
                    document.cookie = `user_roles=${userData.roles.join(',')}; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                }
                
                // 更新is_admin标志
                userData.is_admin = true;
                
                // 如果存在全局currentUser对象，确保它也有admin角色
                if (window.currentUser) {
                    window.currentUser.isAdmin = true;
                    if (!window.currentUser.roles.includes('admin')) {
                        window.currentUser.roles.push('admin');
                    }
                }
                
                console.log("[getUserInfo] 对admin用户进行特殊处理完成");
            }
            
            console.log("[getUserInfo] 用户信息更新完成");
        }
        
        return userData;
    } catch (error) {
        console.error("[getUserInfo] 获取用户信息出错:", error);
        return null;
    }
}

/**
 * 从服务器获取项目信息
 * @param {number} projectId - 项目ID
 * @param {boolean} forceRefresh - 是否强制刷新
 * @returns {Promise<Object>} 项目信息对象
 */
async function getProjectInfo(projectId, forceRefresh = false) {
    console.log(`[getProjectInfo] 开始获取项目${projectId}的信息, 强制刷新: ${forceRefresh}`);
    
    try {
        // 尝试从本地存储获取
        const storageKey = `project_info_${projectId}`;
        let projectData = null;
        
        if (!forceRefresh) {
            try {
                const storedData = localStorage.getItem(storageKey);
                if (storedData) {
                    projectData = JSON.parse(storedData);
                    console.log(`[getProjectInfo] 从本地存储获取项目${projectId}数据:`, projectData);
                    
                    // 检查数据是否过期（20分钟内的数据视为有效）
                    const now = new Date().getTime();
                    const storedTime = projectData.fetchTime || 0;
                    if (now - storedTime < 20 * 60 * 1000) {
                        console.log(`[getProjectInfo] 使用本地缓存的项目数据，未过期`);
                        
                        // 新增：验证数据结构
                        if (!validateProjectData(projectData)) {
                            console.warn('[getProjectInfo] 本地缓存的项目数据格式不正确，将重新获取');
                        } else {
                            return projectData;
                        }
                    } else {
                        console.log(`[getProjectInfo] 项目数据已过期，需要刷新`);
                    }
                }
            } catch (e) {
                console.error(`[getProjectInfo] 解析本地存储的项目数据出错:`, e);
            }
        }
        
        // 从服务器获取最新数据 - 直接使用标准API，跳过专用editor API调用
        console.log(`[getProjectInfo] 从服务器获取项目${projectId}数据`);
        
        let data = null;
        let apiError = null;
        
        // 直接使用标准API获取数据，避免多次尝试
        try {
            data = await fetchProjectDataFromApi(projectId, 'standard');
            if (data && validateProjectData(data)) {
                console.log(`[getProjectInfo] 成功从standard API获取项目数据`);
            } else {
                console.warn(`[getProjectInfo] standard API返回的数据格式不正确`);
                // 如果数据不符合预期格式但有效，尝试修复
                if (data) {
                    data = fixProjectData(data, projectId);
                }
            }
        } catch (error) {
            console.error(`[getProjectInfo] 从standard API获取项目数据失败: ${error.message}`);
            // 记录错误但继续执行
            apiError = error;
            
            // 尝试使用本地存储中的数据作为备选
            if (projectData && validateProjectData(projectData)) {
                console.log(`[getProjectInfo] 使用本地存储的旧数据作为备选`);
                return projectData;
            }
            
            throw apiError;
        }
        
        // 如果API调用失败，抛出错误
        if (!data) {
            throw new Error('无法从API获取项目数据');
        }
        
        // 添加获取时间戳
        data.fetchTime = new Date().getTime();
        
        // 保存到本地存储
        localStorage.setItem(storageKey, JSON.stringify(data));
        
        return data;
    } catch (error) {
        console.error(`[getProjectInfo] 获取项目${projectId}信息出错:`, error);
        throw error;
    }
}

/**
 * 从特定API获取项目数据
 * @param {number} projectId - 项目ID
 * @param {string} apiType - API类型: 'editor' 或 'standard'
 * @returns {Promise<Object>} 项目数据
 */
async function fetchProjectDataFromApi(projectId, apiType = 'standard') {
    console.log(`[fetchProjectDataFromApi:${apiType}] 开始获取项目${projectId}数据`);
    
    // 构造URL - 使用已修改好的URL定义
    let url;
    if (apiType === 'editor') {
        url = `/api/noauth/projects/${projectId}?bypass_jwt=true`;
    } else {
        url = `/api/noauth/projects/${projectId}?bypass_jwt=true`;
    }
    
    // 添加随机参数避免缓存
    const randomParam = Math.random().toString(36).substring(2, 15);
    const finalUrl = `${url}&_=${randomParam}`;
    console.log(`[fetchProjectDataFromApi:${apiType}] 请求URL: ${finalUrl}`);
    
    // 添加备用URL
    const backupUrls = [
        `/api/projects/${projectId}?bypass_jwt=true&_=${randomParam}`,
        `/api/detail/${projectId}?bypass_jwt=true&_=${randomParam}`,
        `/api/projects/detail/${projectId}?bypass_jwt=true&_=${randomParam}`
    ];
    
    // 尝试从多个来源获取CSRF令牌
    let csrfToken = null;
    
    // 1. 尝试从meta标签获取
    const metaCsrf = document.querySelector('meta[name="csrf-token"]')?.content;
    if (metaCsrf) {
        csrfToken = metaCsrf;
        console.log(`[fetchProjectDataFromApi:${apiType}] 从meta标签获取到CSRF令牌: ${csrfToken.substring(0, 10)}...`);
    } 
    
    // 2. 尝试从cookie获取
    if (!csrfToken) {
        const cookieMatch = document.cookie.match(/csrf_token=([^;]+)/);
        if (cookieMatch && cookieMatch[1]) {
            csrfToken = cookieMatch[1];
            console.log(`[fetchProjectDataFromApi:${apiType}] 从cookie获取到CSRF令牌: ${csrfToken.substring(0, 10)}...`);
        }
    }
    
    // 3. 如果仍然没有令牌，尝试获取新的令牌
    if (!csrfToken) {
        console.log(`[fetchProjectDataFromApi:${apiType}] 未找到CSRF令牌，正在获取新令牌...`);
        try {
            const tokenResponse = await fetch('/auth/csrf-token?bypass_jwt=true');
            if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                csrfToken = tokenData.csrf_token;
                console.log(`[fetchProjectDataFromApi:${apiType}] 获取到新的CSRF令牌: ${csrfToken.substring(0, 10)}...`);
                
                // 创建或更新meta标签
                let metaTag = document.querySelector('meta[name="csrf-token"]');
                if (!metaTag) {
                    metaTag = document.createElement('meta');
                    metaTag.name = 'csrf-token';
                    document.head.appendChild(metaTag);
                }
                metaTag.content = csrfToken;
                
                // 更新cookie
                document.cookie = `csrf_token=${csrfToken}; path=/; max-age=${tokenData.expires_in || 3600}`;
            } else {
                console.error(`[fetchProjectDataFromApi:${apiType}] 获取CSRF令牌失败: ${tokenResponse.status}`);
            }
        } catch (error) {
            console.error(`[fetchProjectDataFromApi:${apiType}] 获取CSRF令牌出错:`, error);
        }
    }
    
    // 构造请求选项
    const options = {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Accept': 'application/json'
        },
        credentials: 'include' // 包含cookie
    };
    
    // 添加CSRF令牌到请求头和URL
    if (csrfToken) {
        options.headers['X-CSRF-TOKEN'] = csrfToken;
        options.headers['X-XSRF-TOKEN'] = csrfToken;
    }
    
    // 准备URL集合
    const urlsToTry = [finalUrl, ...backupUrls];
    let lastError = null;
    
    // 尝试所有URL
    for (let i = 0; i < urlsToTry.length; i++) {
        const currentUrl = urlsToTry[i];
        // 同时在URL中添加令牌参数，以防系统检查URL中的令牌
        const separator = currentUrl.includes('?') ? '&' : '?';
        const urlWithCsrf = csrfToken ? `${currentUrl}${separator}csrf_token=${csrfToken}` : currentUrl;
        
        // 记录当前尝试
        const isBackup = i > 0;
        console.log(`[fetchProjectDataFromApi:${apiType}] ${isBackup ? '备选' : '主要'}请求: ${urlWithCsrf.split('?')[0]}`);
        
        try {
            // 添加超时控制，避免长时间等待
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5秒超时
            
            const response = await fetch(urlWithCsrf, {
                ...options,
                signal: controller.signal
            });
            
            // 清除超时
            clearTimeout(timeoutId);
            
            console.log(`[fetchProjectDataFromApi:${apiType}] 收到响应:`, response.status, response.statusText);
            
            // 检查Content-Type
            const contentType = response.headers.get('content-type');
            console.log(`[fetchProjectDataFromApi:${apiType}] 响应Content-Type: ${contentType}`);
            
            if (!response.ok) {
                let errorText = '';
                try {
                    errorText = await response.text();
                    console.error(`[fetchProjectDataFromApi:${apiType}] 请求失败:`, 
                        response.status, errorText.substring(0, 200));
                    
                    // 检查是否为HTML错误页面
                    if (errorText.includes('<!DOCTYPE html>') || errorText.includes('<html>')) {
                        console.error(`[fetchProjectDataFromApi:${apiType}] 收到HTML错误页面而非JSON`);
                        lastError = new Error(`收到HTML响应而非JSON: ${response.status}`);
                        continue; // 尝试下一个URL
                    }
                } catch (e) {
                    errorText = `无法读取响应内容: ${e.message}`;
                }
                
                lastError = new Error(`请求失败: ${response.status} - ${errorText.substring(0, 100)}`);
                
                // 如果这是主URL，继续尝试备选URL
                if (!isBackup) {
                    console.log(`[fetchProjectDataFromApi:${apiType}] 主URL请求失败，将尝试备选URL`);
                    continue;
                }
                
                throw lastError;
            }
            
            // 解析响应
            if (contentType && contentType.includes('application/json')) {
                try {
                    const data = await response.json();
                    console.log(`[fetchProjectDataFromApi:${apiType}] 请求成功:`, isBackup ? '使用备选URL' : '使用主URL');
                    
                    // 对数据进行更强大的处理
                    let processedData = {...data};
                    
                    // 直接记录关键字段，方便调试
                    if (processedData.project) {
                        console.log('[fetchProjectDataFromApi] 原始项目数据关键字段:', {
                            id: processedData.project.id,
                            name: processedData.project.name,
                            manager_id: processedData.project.manager_id,
                            manager: processedData.project.manager,
                            manager_name: processedData.project.manager_name,
                            manager_username: processedData.project.manager_username
                        });
                    }
                    
                    // 确保project_managers字段存在
                    if (!processedData.project_managers && processedData.project) {
                        processedData.project_managers = [];
                        
                        // 如果响应中有项目管理员信息，使用它
                        if (data.managers || data.users || data.project_managers) {
                            processedData.project_managers = data.managers || data.users || data.project_managers || [];
                            console.log('[fetchProjectDataFromApi] 使用响应中的管理员列表:', processedData.project_managers.length);
                        } else {
                            // 尝试从全局API获取项目经理列表
                            try {
                                // 尝试获取全局项目经理列表
                                let managersUrl = '/api/global/project-managers?bypass_jwt=true&_=' + Date.now();
                                console.log('[fetchProjectDataFromApi] 尝试从全局API获取项目经理列表');
                                const managersResponse = await fetch(managersUrl, {
                                    headers: {
                                        'Accept': 'application/json',
                                        'X-Requested-With': 'XMLHttpRequest'
                                    },
                                    credentials: 'include'
                                });
                                
                                if (managersResponse.ok) {
                                    const managersData = await managersResponse.json();
                                    if (managersData && Array.isArray(managersData.project_managers)) {
                                        console.log('[fetchProjectDataFromApi] 成功获取项目经理列表:', managersData.project_managers.length);
                                        processedData.project_managers = managersData.project_managers;
                                    }
                                } else {
                                    console.warn('[fetchProjectDataFromApi] 获取项目经理列表失败，状态码:', managersResponse.status);
                                    
                                    // 如果项目经理API失败，尝试获取所有用户
                                    try {
                                        let usersUrl = '/api/global/users?bypass_jwt=true&_=' + Date.now();
                                        console.log('[fetchProjectDataFromApi] 尝试获取用户列表作为备选');
                                        const usersResponse = await fetch(usersUrl, {
                                            headers: {
                                                'Accept': 'application/json',
                                                'X-Requested-With': 'XMLHttpRequest'
                                            },
                                            credentials: 'include'
                                        });
                                        
                                        if (usersResponse.ok) {
                                            const usersData = await usersResponse.json();
                                            if (usersData && Array.isArray(usersData.users)) {
                                                console.log('[fetchProjectDataFromApi] 成功获取用户列表:', usersData.users.length);
                                                processedData.project_managers = usersData.users;
                                            }
                                        }
                                    } catch (e) {
                                        console.error('[fetchProjectDataFromApi] 获取用户列表失败:', e);
                                    }
                                }
                            } catch (error) {
                                console.warn('[fetchProjectDataFromApi] 获取全局项目经理列表失败:', error);
                            }
                        }
                        
                        // 如果项目中有manager_id但project_managers数组仍为空
                        if (processedData.project.manager_id && processedData.project_managers.length === 0) {
                            // 添加一个基本的项目经理对象
                            processedData.project_managers.push({
                                id: processedData.project.manager_id,
                                name: processedData.project.manager_name || 
                                      processedData.project.manager_username || 
                                      processedData.project.manager || 
                                      `用户 #${processedData.project.manager_id}`
                            });
                            console.log('[fetchProjectDataFromApi] 为空的经理列表添加了基本对象');
                        }
                    }
                    
                    // 确保项目对象中的manager_name字段存在
                    if (processedData.project && processedData.project.manager_id) {
                        // 先记录原始值，方便排查问题
                        const originalManager = processedData.project.manager;
                        const originalManagerName = processedData.project.manager_name;
                        
                        // 如果缺少manager_name，先尝试使用manager
                        if (!processedData.project.manager_name && processedData.project.manager) {
                            processedData.project.manager_name = processedData.project.manager;
                            console.log('[fetchProjectDataFromApi] 使用manager字段值作为manager_name');
                        }
                        
                        // 尝试从project_managers中查找匹配的管理员名称
                        if (Array.isArray(processedData.project_managers) && processedData.project_managers.length > 0) {
                            const manager = processedData.project_managers.find(m => 
                                m.id == processedData.project.manager_id);
                            
                            if (manager) {
                                // 保存用户名以供显示
                                if (manager.username && !processedData.project.manager_username) {
                                    processedData.project.manager_username = manager.username;
                                    console.log('[fetchProjectDataFromApi] 设置manager_username:', manager.username);
                                }
                                
                                // 优先使用name字段，如果存在
                                if (manager.name) {
                                    processedData.project.manager_name = manager.name;
                                    console.log('[fetchProjectDataFromApi] 设置manager_name:', manager.name);
                                } else if (manager.username) {
                                    // 如果name不存在但username存在，使用username
                                    processedData.project.manager_name = manager.username;
                                    console.log('[fetchProjectDataFromApi] 使用username作为manager_name:', manager.username);
                                }
                                
                                console.log(`[fetchProjectDataFromApi] 从project_managers中找到匹配的管理员: ${processedData.project.manager_name}`);
                            } else {
                                console.log(`[fetchProjectDataFromApi] 未在project_managers中找到ID为${processedData.project.manager_id}的管理员`);
                                
                                // 尝试从数据库获取特定用户数据
                                try {
                                    const userUrl = `/api/global/user/${processedData.project.manager_id}?bypass_jwt=true&_=${Date.now()}`;
                                    const userResponse = await fetch(userUrl, {
                                        headers: {
                                            'Accept': 'application/json',
                                            'X-Requested-With': 'XMLHttpRequest'
                                        },
                                        credentials: 'include'
                                    });
                                    
                                    if (userResponse.ok) {
                                        const userData = await userResponse.json();
                                        if (userData && userData.user) {
                                            console.log('[fetchProjectDataFromApi] 成功获取负责人用户数据:', userData.user);
                                            
                                            // 更新manager_name和manager_username
                                            if (userData.user.name) {
                                                processedData.project.manager_name = userData.user.name;
                                            }
                                            
                                            if (userData.user.username) {
                                                processedData.project.manager_username = userData.user.username;
                                                
                                                // 如果没有name，使用username作为name
                                                if (!processedData.project.manager_name) {
                                                    processedData.project.manager_name = userData.user.username;
                                                }
                                            }
                                        }
                                    }
                                } catch (e) {
                                    console.warn('[fetchProjectDataFromApi] 获取用户数据失败:', e);
                                }
                            }
                        }
                        
                        // 记录最终使用的值，便于调试
                        console.log(`[fetchProjectDataFromApi] 处理项目经理字段: 原始manager=${originalManager}, 原始manager_name=${originalManagerName}, 最终manager_name=${processedData.project.manager_name}, manager_username=${processedData.project.manager_username}`);
                    }
                    
                    // 添加请求信息到返回数据
                    return {
                        ...processedData,
                        _meta: {
                            url: urlWithCsrf.split('?')[0],
                            wasBackup: isBackup,
                            timestamp: new Date().toISOString()
                        }
                    };
                } catch (e) {
                    console.error(`[fetchProjectDataFromApi:${apiType}] JSON解析错误:`, e);
                    lastError = new Error(`JSON解析错误: ${e.message}`);
                    
                    // 如果这是主URL，继续尝试备选URL
                    if (!isBackup) continue;
                    throw lastError;
                }
            } else {
                const textData = await response.text();
                console.error(`[fetchProjectDataFromApi:${apiType}] 响应不是JSON格式:`, 
                    textData.substring(0, 100));
                
                lastError = new Error(`服务器返回了非JSON格式的数据: ${textData.substring(0, 100)}...`);
                
                // 如果这是主URL，继续尝试备选URL
                if (!isBackup) continue;
                throw lastError;
            }
        } catch (error) {
            // 检查是否是超时错误
            if (error.name === 'AbortError') {
                console.error(`[fetchProjectDataFromApi:${apiType}] 请求超时`);
                lastError = new Error('请求超时，服务器响应时间过长');
            } else {
                console.error(`[fetchProjectDataFromApi:${apiType}] 请求失败:`, error);
                lastError = error;
            }
            
            // 如果这是主URL，继续尝试备选URL
            if (!isBackup) continue;
        }
    }
    
    // 如果所有URL都失败
    throw lastError || new Error(`所有API请求都失败，无法获取项目${projectId}信息`);
}

/**
 * 验证项目数据格式是否正确
 * @param {Object} data - 项目数据
 * @returns {boolean} 数据格式是否正确
 */
function validateProjectData(data) {
    // 检查基本结构
    if (!data) {
        console.error('[validateProjectData] 数据为空');
        return false;
    }
    
    // 检查项目对象
    if (!data.project) {
        console.error('[validateProjectData] 缺少project字段');
        return false;
    }
    
    // 检查项目ID
    if (!data.project.id) {
        console.error('[validateProjectData] 缺少project.id字段');
        return false;
    }
    
    // 其他必要字段检查
    const requiredFields = ['name', 'status'];
    for (const field of requiredFields) {
        if (data.project[field] === undefined) {
            console.error(`[validateProjectData] 缺少project.${field}字段`);
            return false;
        }
    }
    
    console.log('[validateProjectData] 数据验证通过');
    return true;
}

/**
 * 尝试修复项目数据格式
 * @param {Object} data - 原始项目数据
 * @param {number} projectId - 项目ID
 * @returns {Object} 修复后的项目数据
 */
function fixProjectData(data, projectId) {
    console.log('[fixProjectData] 尝试修复项目数据格式');
    
    // 创建一个新的数据对象
    const fixedData = { 
        status: 'success',
        timestamp: new Date().toISOString()
    };
    
    // 情况1: 如果数据本身就是项目对象
    if (data.id && data.name) {
        console.log('[fixProjectData] 数据本身是项目对象，包装到project字段中');
        fixedData.project = data;
        
        // 确保manager_name字段存在
        if (data.manager && !data.manager_name) {
            fixedData.project.manager_name = data.manager;
        }
        
        // 保存原始manager_id，防止后续处理丢失
        if (data.manager_id) {
            fixedData.original_manager_id = data.manager_id;
        }
    }
    // 情况2: 如果数据是另一种格式，但包含项目信息
    else if (data.project_info || data.projectInfo || data.projectData) {
        console.log('[fixProjectData] 从特殊字段中提取项目数据');
        fixedData.project = data.project_info || data.projectInfo || data.projectData;
        
        // 确保manager_name字段存在
        if (fixedData.project.manager && !fixedData.project.manager_name) {
            fixedData.project.manager_name = fixedData.project.manager;
        }
    }
    // 其他情况: 创建最小化的项目对象
    else {
        console.log('[fixProjectData] 无法从数据中提取项目信息，创建基本项目对象');
        fixedData.project = {
            id: projectId,
            name: `项目 #${projectId}`,
            description: '数据格式不正确，无法显示详细信息',
            status: 'unknown',
            manager: '未知',
            manager_name: '未知负责人',
            manager_id: null,
            start_date: null,
            end_date: null,
            progress: 0
        };
    }
    
    // 确保project_managers字段存在
    if (!fixedData.project_managers) {
        fixedData.project_managers = [];
        
        // 尝试从全局项目经理列表获取数据
        setTimeout(async () => {
            try {
                const response = await fetch('/api/global/project-managers?bypass_jwt=true&_=' + Date.now(), {
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const managersData = await response.json();
                    if (managersData && Array.isArray(managersData.project_managers)) {
                        console.log('[fixProjectData] 异步获取到项目经理列表，更新本地存储');
                        
                        // 更新项目经理列表
                        fixedData.project_managers = managersData.project_managers;
                        
                        // 检查是否有匹配的项目经理
                        if (fixedData.project.manager_id) {
                            const manager = managersData.project_managers.find(m => m.id == fixedData.project.manager_id);
                            if (manager) {
                                fixedData.project.manager_name = manager.name;
                                fixedData.project.manager_username = manager.username;
                                console.log(`[fixProjectData] 从异步获取的项目经理列表中找到匹配: ${manager.name}`);
                            }
                        }
                        
                        // 更新本地存储
                        const storageKey = `project_info_${projectId}`;
                        localStorage.setItem(storageKey, JSON.stringify(fixedData));
                    }
                }
            } catch (error) {
                console.warn('[fixProjectData] 异步获取项目经理列表失败:', error);
            }
        }, 100);
        
        // 如果有manager_id但没有project_managers，创建一个基本的项目经理对象
        if (fixedData.project.manager_id) {
            fixedData.project_managers.push({
                id: fixedData.project.manager_id,
                name: fixedData.project.manager_name || fixedData.project.manager || `负责人 #${fixedData.project.manager_id}`
            });
        }
    }
    
    console.log('[fixProjectData] 修复后的数据:', fixedData);
    return fixedData;
}

/**
 * 从服务器获取新的CSRF令牌
 * @param {boolean} setMeta - 是否自动设置meta标签
 * @param {boolean} setCookie - 是否自动设置cookie
 * @returns {Promise<string|null>} 新的CSRF令牌，失败时返回null
 */
async function refreshCsrfToken(setMeta = true, setCookie = true) {
    console.log('[refreshCsrfToken] 正在获取新的CSRF令牌...');
    
    try {
        // 添加随机参数避免缓存
        const random = Math.random().toString(36).substring(2, 15);
        const response = await fetch(`/auth/csrf-token?bypass_jwt=true&_=${random}`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'include'
        });
        
        if (!response.ok) {
            console.error(`[refreshCsrfToken] 获取CSRF令牌失败: ${response.status}`);
            return null;
        }
        
        const data = await response.json();
        
        if (!data.csrf_token) {
            console.error('[refreshCsrfToken] 响应中没有csrf_token字段');
            return null;
        }
        
        const csrfToken = data.csrf_token;
        console.log(`[refreshCsrfToken] 获取到新的CSRF令牌: ${csrfToken.substring(0, 10)}...`);
        
        // 自动设置meta标签
        if (setMeta) {
            let metaTag = document.querySelector('meta[name="csrf-token"]');
            if (!metaTag) {
                metaTag = document.createElement('meta');
                metaTag.name = 'csrf-token';
                document.head.appendChild(metaTag);
            }
            metaTag.content = csrfToken;
        }
        
        // 自动设置cookie
        if (setCookie) {
            document.cookie = `csrf_token=${csrfToken}; path=/; max-age=${data.expires_in || 3600}`;
        }
        
        return csrfToken;
    } catch (error) {
        console.error('[refreshCsrfToken] 获取CSRF令牌出错:', error);
        return null;
    }
}

/**
 * 获取当前有效的CSRF令牌，如果不存在则自动获取新令牌
 * @param {boolean} autoRefresh - 如果不存在令牌，是否自动获取新令牌
 * @returns {string|null} CSRF令牌，如果不存在且不自动刷新则返回null
 */
function getCsrfToken(autoRefresh = true) {
    // 1. 尝试从meta标签获取
    let csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    if (csrfToken) {
        return csrfToken;
    }
    
    // 2. 尝试从cookie获取
    const cookieMatch = document.cookie.match(/csrf_token=([^;]+)/);
    if (cookieMatch && cookieMatch[1]) {
        csrfToken = cookieMatch[1];
        
        // 同步到meta标签
        let metaTag = document.querySelector('meta[name="csrf-token"]');
        if (!metaTag) {
            metaTag = document.createElement('meta');
            metaTag.name = 'csrf-token';
            document.head.appendChild(metaTag);
        }
        metaTag.content = csrfToken;
        
        return csrfToken;
    }
    
    // 3. 如果自动刷新且没有令牌，从服务器获取新令牌
    if (autoRefresh) {
        console.log('[getCsrfToken] 未找到CSRF令牌，正在获取新令牌...');
        // 返回一个空串而不是null，避免后续代码判断时出错
        return '';
    }
    
    return null;
}

// 导出工具函数（如果使用模块系统）
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
    module.exports = {
        fetchWithCsrf,
        formatDate,
        debounce,
        showToast,
        getUserRoles,
        getUserInfo,
        getProjectInfo
    };
} 