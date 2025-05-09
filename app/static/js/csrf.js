/**
 * CSRF令牌工具函数
 */

// 使用自执行函数创建闭包，避免全局变量命名冲突
(function() {
    // CSRF令牌处理 - 放在模块作用域内防止冲突
    let _csrfToken = null;
    let _tokenRefreshPromise = null;

    /**
     * 从Cookie中获取CSRF令牌
     * @returns {string|null} CSRF令牌
     */
    function getCsrfToken() {
        if (_csrfToken) {
            return _csrfToken;
        }
        
        const name = 'csrf_token=';
        const decodedCookie = decodeURIComponent(document.cookie);
        const cookieArray = decodedCookie.split(';');
        
        for (let cookie of cookieArray) {
            cookie = cookie.trim();
            if (cookie.indexOf(name) === 0) {
                _csrfToken = cookie.substring(name.length);
                return _csrfToken;
            }
        }
        return null;
    }

    /**
     * 刷新CSRF令牌 - 从服务器获取新的令牌
     * @returns {Promise<string|null>} 新的CSRF令牌
     */
    async function refreshCsrfToken() {
        // 如果已经有一个刷新请求在进行中，返回该Promise
        if (_tokenRefreshPromise) {
            return _tokenRefreshPromise;
        }

        _tokenRefreshPromise = (async () => {
            try {
                const response = await fetch('/auth/csrf-token?bypass_jwt=true', {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Accept': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`Failed to refresh CSRF token: ${response.status}`);
                }
                
                const data = await response.json();
                if (!data.csrf_token) {
                    throw new Error('No CSRF token in response');
                }
                
                _csrfToken = data.csrf_token;
                return _csrfToken;
            } catch (error) {
                console.error('Error refreshing CSRF token:', error);
                return null;
            } finally {
                _tokenRefreshPromise = null;
            }
        })();

        return _tokenRefreshPromise;
    }

    /**
     * 将CSRF令牌添加到请求头中
     * @param {object} headers - 请求头对象
     * @returns {object} 包含CSRF令牌的请求头对象
     */
    function addCsrfToken(headers = {}) {
        const token = getCsrfToken();
        if (token) {
            headers['X-CSRF-TOKEN'] = token;
        }
        return headers;
    }

    /**
     * 为fetch请求添加CSRF令牌
     * @param {string} url - 请求URL
     * @param {object} options - fetch选项
     * @returns {Promise<Response>} fetch响应
     */
    async function fetchWithCsrf(url, options = {}) {
        // 确保options.headers存在
        options.headers = options.headers || {};
        
        // 获取CSRF令牌
        let token = getCsrfToken();
        
        // 如果没有找到CSRF令牌，尝试刷新获取
        if (!token) {
            console.log('CSRF token not found, attempting to refresh');
            token = await refreshCsrfToken();
            if (!token) {
                throw new Error('Unable to obtain CSRF token');
            }
        }
        
        // 添加CSRF令牌到请求头
        options.headers['X-CSRF-TOKEN'] = token;
        
        // 确保包含credentials以发送cookie
        options.credentials = 'include';
        
        // 发送请求
        try {
            const response = await fetch(url, options);
            
            // 如果收到CSRF错误，尝试刷新令牌并重试一次
            if (response.status === 401 && 
                (response.headers.get('X-CSRF-TOKEN-INVALID') || 
                 await response.text().includes('CSRF token'))) {
                console.log('CSRF token invalid, refreshing and retrying');
                
                // 清除当前token
                _csrfToken = null;
                
                // 获取新token
                token = await refreshCsrfToken();
                if (!token) {
                    throw new Error('Failed to refresh CSRF token');
                }
                
                // 使用新token重试请求
                options.headers['X-CSRF-TOKEN'] = token;
                return fetch(url, options);
            }
            
            return response;
        } catch (error) {
            console.error('Error in fetchWithCsrf:', error);
            throw error;
        }
    }

    /**
     * 获取用户专用的CSRF令牌
     * @returns {Promise<string>} 新的CSRF令牌
     */
    async function getUserCsrfToken() {
        try {
            console.log('获取用户专用CSRF令牌...');
            const response = await fetch('/auth/user-csrf-token', {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`获取用户CSRF令牌失败: ${response.status} ${response.statusText}`);
            }
            
            const data = await response.json();
            if (!data.csrf_token) {
                throw new Error('响应中没有CSRF令牌');
            }
            
            // 更新全局CSRF令牌
            _csrfToken = data.csrf_token;
            
            // 更新页面上的CSRF令牌meta标签
            const metaElement = document.querySelector('meta[name="csrf-token"]');
            if (metaElement) {
                metaElement.setAttribute('content', _csrfToken);
            }
            
            return _csrfToken;
        } catch (error) {
            console.error('获取用户CSRF令牌时出错:', error);
            throw error;
        }
    }

    /**
     * 用户更新专用的fetch函数，确保使用正确的CSRF令牌
     * @param {string} url - 请求URL
     * @param {object} options - fetch选项
     * @returns {Promise<Response>} fetch响应
     */
    async function fetchUserUpdate(url, options = {}) {
        try {
            // 首先获取一个新的用户专用CSRF令牌
            const token = await getUserCsrfToken();
            
            // 确保options.headers存在
            options.headers = options.headers || {};
            
            // 添加CSRF令牌到请求头
            options.headers['X-CSRF-TOKEN'] = token;
            options.headers['X-CSRFToken'] = token;
            
            // 确保URL中包含CSRF令牌参数
            if (!url.includes('csrf_token=')) {
                const separator = url.includes('?') ? '&' : '?';
                url = `${url}${separator}csrf_token=${encodeURIComponent(token)}`;
            }
            
            // 确保包含credentials以发送cookie
            options.credentials = 'include';
            
            // 发送请求
            console.log(`发送${options.method || 'GET'}请求到: ${url}`);
            const response = await fetch(url, options);
            console.log(`请求响应状态: ${response.status} ${response.statusText}`);
            
            return response;
        } catch (error) {
            console.error('用户更新请求失败:', error);
            throw error;
        }
    }

    // 导出函数到全局作用域
    window.getCsrfToken = getCsrfToken;
    window.refreshCsrfToken = refreshCsrfToken;
    window.fetchWithCsrf = fetchWithCsrf;
    window.getUserCsrfToken = getUserCsrfToken;
    window.fetchUserUpdate = fetchUserUpdate;
})(); 