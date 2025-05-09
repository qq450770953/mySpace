document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const errorMessage = document.getElementById('error-message');
    const submitButton = document.querySelector('button[type="submit"]');
    const csrfTokenField = document.getElementById('csrf_token');

    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // 清除之前的错误信息
        errorMessage.style.display = 'none';
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember') ? document.getElementById('remember').checked : false;
        const formCsrfToken = csrfTokenField ? csrfTokenField.value : '';

        // 表单验证
        if (!username || !password) {
            errorMessage.textContent = '请填写用户名和密码';
            errorMessage.style.display = 'block';
            return;
        }
        
        // 禁用提交按钮，防止重复提交
        submitButton.disabled = true;
        submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 登录中...';
        
        try {
            // 获取CSRF令牌（先尝试从表单获取，如果没有再尝试其他方式）
            let tokenToUse = formCsrfToken;
            if (!tokenToUse && typeof window.getCsrfToken === 'function') {
                tokenToUse = window.getCsrfToken();
            }
            
            // 构建FormData，使用传统表单提交方式
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            if (remember !== undefined) {
                formData.append('remember', remember ? '1' : '0');
            }
            if (tokenToUse) {
                formData.append('csrf_token', tokenToUse);
            }
            
            // 发送登录请求 - 试用两种方式：JSON格式和表单格式
            let response;
            
            try {
                // 首先尝试使用表单格式
                response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        // 不设置Content-Type，让浏览器自动设置正确的表单Content-Type
                        'X-CSRF-TOKEN': tokenToUse
                    },
                    credentials: 'include', // 包含cookie
                    body: formData
                });
                
                // 如果表单格式失败，尝试JSON格式
                if (!response.ok && response.status === 400) {
                    console.log('表单格式提交失败，尝试JSON格式');
                    response = await fetch('/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                            'X-CSRF-TOKEN': tokenToUse
                        },
                        credentials: 'include', // 包含cookie
                        body: JSON.stringify({
                            username,
                            password,
                            remember,
                            csrf_token: tokenToUse
                        })
                    });
                }
            } catch (fetchError) {
                console.error('登录请求发送失败:', fetchError);
                throw new Error('登录请求发送失败');
            }
            
            // 处理响应
            if (response.ok) {
                let data;
                try {
                    // 尝试解析JSON响应
                    data = await response.json();
                } catch (jsonError) {
                    console.log('响应不是JSON格式，可能是重定向');
                    // 处理重定向
                    window.location.href = '/main/dashboard';
                    return;
                }
                
                // 保存CSRF令牌到localStorage，用于后续请求
                if (data.csrf_token) {
                    localStorage.setItem('csrf_token', data.csrf_token);
                }
                
                if (data.access_token) {
                    localStorage.setItem('access_token', data.access_token);
                }
                
                // 保存用户信息到localStorage
                if (data.user) {
                    // 保存完整的用户信息
                    localStorage.setItem('user_info', JSON.stringify(data.user));
                    
                    // 保存用户角色信息
                    if (data.user.roles) {
                        console.log("保存用户角色信息:", data.user.roles);
                        localStorage.setItem('user_roles', data.user.roles.join(','));
                    }
                    
                    // 保存用户权限信息
                    if (data.user.permissions) {
                        console.log("保存用户权限信息:", data.user.permissions);
                        localStorage.setItem('user_permissions', data.user.permissions.join(','));
                    }
                }
                
                // 跳转到仪表板
                window.location.href = '/main/dashboard';
            } else {
                // 登录失败，显示错误消息
                try {
                    const data = await response.json();
                    errorMessage.textContent = data.error || '登录失败，请检查用户名和密码';
                } catch (e) {
                    // 如果响应不是JSON格式
                    errorMessage.textContent = '登录失败，请检查用户名和密码';
                }
                errorMessage.style.display = 'block';
                
                // 恢复提交按钮
                submitButton.disabled = false;
                submitButton.innerHTML = '登录';
            }
        } catch (error) {
            console.error('登录过程出错:', error);
            errorMessage.textContent = '登录请求出错，请稍后再试';
            errorMessage.style.display = 'block';
            
            // 恢复提交按钮
            submitButton.disabled = false;
            submitButton.innerHTML = '登录';
        }
    });
    
    // 获取CSRF令牌的函数 - 重命名以避免冲突
    function getPageCsrfToken() {
        // 首先尝试从meta标签获取
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) {
            const token = metaTag.getAttribute('content');
            if (token && token.trim() !== '') {
                console.log('从meta标签获取到CSRF令牌');
                return token;
            }
        }
        
        // 尝试从表单隐藏字段获取
        const csrfInput = document.getElementById('csrf_token');
        if (csrfInput && csrfInput.value && csrfInput.value.trim() !== '') {
            console.log('从表单字段获取到CSRF令牌');
            return csrfInput.value;
        }
        
        // 如果meta标签中没有，尝试从localStorage获取
        const storedToken = localStorage.getItem('csrf_token');
        if (storedToken && storedToken.trim() !== '') {
            console.log('从localStorage获取到CSRF令牌');
            return storedToken;
        }
        
        // 尝试从cookie获取
        const csrfCookie = document.cookie.split('; ').find(cookie => cookie.startsWith('csrf_token='));
        if (csrfCookie) {
            const token = csrfCookie.split('=')[1];
            if (token && token.trim() !== '') {
                console.log('从cookie获取到CSRF令牌');
                return token;
            }
        }
        
        console.warn('无法获取CSRF令牌');
        return '';
    }
    
    // 添加全局拦截器，确保所有请求包含认证信息
    function addAuthInterceptor() {
        // 使用fetch的拦截器模式，通过覆盖fetch方法实现
        const originalFetch = window.fetch;
        window.fetch = async function(url, options = {}) {
            // 默认初始化options对象
            options = options || {};
            options.headers = options.headers || {};
            
            // 从localStorage获取token
            const token = localStorage.getItem('access_token');
            
            // 如果有token，添加到Authorization头
            if (token) {
                options.headers['Authorization'] = `Bearer ${token}`;
            }
            
            // 添加CSRF令牌(如果存在)
            const pageCsrfToken = getPageCsrfToken();
            if (pageCsrfToken) {
                options.headers['X-CSRF-TOKEN'] = pageCsrfToken;
            }
            
            // 确保包含cookies
            options.credentials = options.credentials || 'include';
            
            // 调用原始fetch并返回结果
            return originalFetch(url, options);
        };
        
        console.log('已添加全局认证拦截器');
    }
    
    // 检查是否已登录（页面加载时）
    const token = localStorage.getItem('access_token');
    if (token) {
        addAuthInterceptor();
    }
}); 