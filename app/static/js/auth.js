/**
 * 认证相关工具函数
 */

// 当文档加载完成时初始化认证拦截器
document.addEventListener('DOMContentLoaded', function() {
    // 检查是否已经登录
    const token = localStorage.getItem('access_token');
    if (token) {
        // 如果有token，添加拦截器并设置cookie
        addAuthInterceptor();
        setCookieToken(token);
    }
});

/**
 * 设置cookie中的令牌
 */
function setCookieToken(token) {
    if (!token) return;
    
    // 设置cookie，24小时有效
    document.cookie = `access_token_cookie=${token}; path=/; max-age=${60*60*24}; SameSite=Lax`;
    console.log('已设置令牌cookie');
}

/**
 * 添加全局认证拦截器
 * 确保所有fetch请求都带有认证头
 */
function addAuthInterceptor() {
    // 使用fetch的拦截器模式，通过覆盖fetch方法实现
    const originalFetch = window.fetch;
    window.fetch = async function(url, options = {}) {
        // 默认初始化options对象
        options = options || {};
        options.headers = options.headers || {};
        
        // 从localStorage获取token
        const token = localStorage.getItem('access_token');
        
        // 如果有token，添加到Authorization头和其他位置
        if (token) {
            // 添加到请求头
            options.headers['Authorization'] = `Bearer ${token}`;
            
            // 同时确保cookie存在
            setCookieToken(token);
            
            // 添加token作为URL参数，除非URL已包含该参数或明确不需要添加
            const skipTokenInUrl = url.includes('/static/') || 
                                  url.includes('/favicon.ico');
            
            if (!skipTokenInUrl) {
                // 检查现有的URL参数
                const urlObj = new URL(url, window.location.origin);
                
                // 如果没有jwt或token参数，添加jwt参数
                if (!urlObj.searchParams.has('jwt') && !urlObj.searchParams.has('token')) {
                    urlObj.searchParams.set('jwt', token);
                    url = urlObj.toString();
                }
                
                console.log('请求URL (含令牌): ', url);
            }
        }
        
        // 记录请求
        console.log(`发送${token ? '认证' : '未认证'}请求: ${url}`);
        
        try {
            // 调用原始fetch并返回结果
            const response = await originalFetch(url, options);
            
            // 处理401未授权响应
            if (response.status === 401) {
                console.log('检测到未授权访问，尝试刷新令牌');
                // 尝试刷新令牌
                const refreshed = await refreshToken();
                if (refreshed) {
                    // 如果刷新成功，使用新令牌重试请求
                    const newToken = localStorage.getItem('access_token');
                    options.headers['Authorization'] = `Bearer ${newToken}`;
                    setCookieToken(newToken);
                    
                    // 更新URL中的令牌
                    if (!url.includes('/static/') && !url.includes('/favicon.ico')) {
                        const urlObj = new URL(url, window.location.origin);
                        if (urlObj.searchParams.has('jwt')) {
                            urlObj.searchParams.set('jwt', newToken);
                        } else if (urlObj.searchParams.has('token')) {
                            urlObj.searchParams.set('token', newToken);
                        } else {
                            urlObj.searchParams.set('jwt', newToken);
                        }
                        url = urlObj.toString();
                    }
                    
                    return originalFetch(url, options);
                } else {
                    // 如果刷新失败，重定向到登录页面
                    console.log('令牌刷新失败，重定向到登录页面');
                    redirectToLogin();
                }
            }
            
            return response;
        } catch (error) {
            console.error('请求错误:', error);
            throw error;
        }
    };
    
    console.log('已添加全局认证拦截器');
}

/**
 * 刷新令牌
 * @returns {Promise<boolean>} 刷新是否成功
 */
async function refreshToken() {
    try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) {
            console.log('没有刷新令牌可用');
            return false;
        }
        
        const response = await fetch('/auth/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${refreshToken}`
            },
            body: JSON.stringify({
                refresh_token: refreshToken
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.access_token) {
                localStorage.setItem('access_token', data.access_token);
                setCookieToken(data.access_token);
                return true;
            }
        }
        
        return false;
    } catch (error) {
        console.error('刷新令牌失败:', error);
        return false;
    }
}

/**
 * 重定向到登录页面
 */
function redirectToLogin() {
    // 清除所有认证相关的本地存储
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    
    // 清除cookie
    document.cookie = 'access_token_cookie=; path=/; max-age=0; SameSite=Lax';
    
    // 保存当前URL，以便登录后可以返回
    const currentUrl = window.location.href;
    localStorage.setItem('login_redirect', currentUrl);
    
    // 重定向到登录页面
    window.location.href = '/auth/login';
}

/**
 * 检查用户是否已登录
 * @returns {boolean} 用户是否已登录
 */
function isLoggedIn() {
    return !!localStorage.getItem('access_token');
}

/**
 * 获取当前令牌
 * @returns {string|null} 访问令牌
 */
function getToken() {
    return localStorage.getItem('access_token');
}

/**
 * 退出登录
 */
async function logout() {
    try {
        const token = localStorage.getItem('access_token');
        if (token) {
            await fetch('/auth/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            });
        }
    } catch (error) {
        console.error('退出登录失败:', error);
    } finally {
        // 无论如何都清除本地存储和cookie
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        document.cookie = 'access_token_cookie=; path=/; max-age=0; SameSite=Lax';
        window.location.href = '/auth/login';
    }
} 