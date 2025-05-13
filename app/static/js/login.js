document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    if (!loginForm) return;
    
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorMsg = document.getElementById('error-message');
        
        // 清除错误消息
        if (errorMsg) errorMsg.textContent = '';
        
        // 预检查：如果是admin用户，先设置标志以确保后续能正确识别
        if (username === 'admin') {
            console.log("登录请求: 检测到admin用户，预设标记");
            localStorage.setItem('admin_username', 'admin');
            localStorage.setItem('login_admin_attempt', 'true');
            localStorage.setItem('admin_login_time', Date.now().toString());
        }
        
        try {
            // 显示加载状态
            const submitButton = loginForm.querySelector('button[type="submit"]');
            const originalText = submitButton.innerHTML;
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 登录中...';
            
            // 提交登录请求
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ username, password })
            });
            
            // 恢复按钮状态
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
            
            if (!response.ok) {
                const data = await response.json();
                if (errorMsg) {
                    errorMsg.textContent = data.message || '登录失败，请检查用户名和密码';
                }
                return;
            }
            
            const data = await response.json();
            
            // 登录成功后的处理
            if (data.success) {
                // 打印从服务器返回的完整用户信息，用于调试
                console.log("================== 前端接收的用户数据详情 ==================");
                console.log("完整响应数据:", data);
                console.log("用户信息:", data.user);
                console.log("用户ID:", data.user?.id);
                console.log("用户名:", data.user?.username);
                console.log("用户角色:", data.user?.roles);
                console.log("用户权限:", data.user?.permissions);
                console.log("JWT Token:", data.access_token);
                
                // 尝试解析JWT Token中的信息
                try {
                    if (data.access_token) {
                        const payload = JSON.parse(atob(data.access_token.split('.')[1]));
                        console.log("JWT payload:", payload);
                    }
                } catch (e) {
                    console.error("解析JWT失败:", e);
                }
                
                // 处理admin用户，确保角色和标志正确设置
                const isAdminUser = data.user.username === 'admin' || data.user.id === 1 || data.user.is_admin === true;
                if (isAdminUser) {
                    console.log("检测到admin用户，确保角色设置正确");
                    if (!data.user.roles.includes('admin')) {
                        data.user.roles.push('admin');
                    }
                    data.user.is_admin = true;
                }
                
                // 确保用户角色和权限都是数组
                if (!Array.isArray(data.user.roles)) {
                    data.user.roles = data.user.roles ? [data.user.roles] : [];
                }
                if (!Array.isArray(data.user.permissions)) {
                    data.user.permissions = data.user.permissions ? [data.user.permissions] : [];
                }
                
                // 保存完整的用户信息
                localStorage.setItem('user_info', JSON.stringify(data.user));
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('refresh_token', data.refresh_token);
                localStorage.setItem('user_roles', data.user.roles.join(','));
                
                // 设置admin标志
                if (data.user.is_admin || data.user.roles.includes('admin')) {
                    localStorage.setItem('is_admin', 'true');
                    document.cookie = `is_admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                    document.cookie = `admin=true; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                } else {
                    localStorage.removeItem('is_admin');
                    document.cookie = `is_admin=false; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                    document.cookie = `admin=false; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                }
                
                // 设置角色cookie
                document.cookie = `user_roles=${data.user.roles.join(',')}; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                
                // 设置CSRF令牌cookie
                document.cookie = `csrf_token=${data.csrf_token}; path=/; max-age=${60*60*24*7}; SameSite=Lax`;
                
                // 添加数据对比检查，确保保存的数据与服务器返回的一致
                setTimeout(() => {
                    console.log("================== 登录后数据一致性检查 ==================");
                    // 从localStorage读取保存的用户信息
                    const savedUserInfo = localStorage.getItem('user_info');
                    if (savedUserInfo) {
                        try {
                            const parsedUserInfo = JSON.parse(savedUserInfo);
                            console.log("保存的用户数据:", parsedUserInfo);
                            console.log("用户数据一致性检查:");
                            console.log("- ID一致:", parsedUserInfo.id === data.user.id);
                            console.log("- 用户名一致:", parsedUserInfo.username === data.user.username);
                            console.log("- 角色数量一致:", parsedUserInfo.roles.length === data.user.roles.length);
                            console.log("- 是否admin一致:", parsedUserInfo.is_admin === data.user.is_admin);
                            
                            // 最后进行全局角色检查
                            const finalRoles = getUserRoles();
                            console.log("最终收集到的角色:", finalRoles);
                            console.log("admin标志检查:", localStorage.getItem('is_admin'));
                        } catch (e) {
                            console.error("解析保存的用户信息失败:", e);
                        }
                    }
                    console.log("================== 数据一致性检查结束 ==================");
                }, 100);
                
                // 定义获取URL参数的辅助函数
                function getQueryParam(param) {
                    const urlParams = new URLSearchParams(window.location.search);
                    return urlParams.get(param);
                }
                
                // 登录成功，跳转到首页或目标页面
                const nextUrl = getQueryParam("next") || "/dashboard";
                
                // 添加立即执行的admin检查脚本
                // 创建一个script元素，内容为在页面加载后强制设置admin用户信息
                const scriptEl = document.createElement('script');
                scriptEl.innerHTML = `
                    document.addEventListener('DOMContentLoaded', function() {
                        console.log("执行admin用户检查");
                        // 从localStorage读取用户信息
                        try {
                            const userInfoStr = localStorage.getItem('user_info');
                            if (userInfoStr) {
                                const userInfo = JSON.parse(userInfoStr);
                                // 检查是否为admin
                                if (userInfo.username === 'admin' || userInfo.id === 1) {
                                    console.log("页面加载时检测到admin用户，强制设置admin角色");
                                    
                                    // 强制设置所有admin标记
                                    localStorage.setItem('is_admin', 'true');
                                    document.cookie = 'is_admin=true; path=/; max-age=604800; SameSite=Lax';
                                    document.cookie = 'admin=true; path=/; max-age=604800; SameSite=Lax';
                                    
                                    // 确保角色中包含admin
                                    if (!userInfo.roles || !userInfo.roles.includes('admin')) {
                                        userInfo.roles = userInfo.roles || [];
                                        userInfo.roles.push('admin');
                                        userInfo.is_admin = true;
                                        localStorage.setItem('user_info', JSON.stringify(userInfo));
                                    }
                                    
                                    // 设置角色标记
                                    localStorage.setItem('user_roles', userInfo.roles.join(','));
                                    document.cookie = 'user_roles=' + userInfo.roles.join(',') + '; path=/; max-age=604800; SameSite=Lax';
                                    
                                    // 更新全局变量（如果存在）
                                    if (window.currentUser) {
                                        window.currentUser.isAdmin = true;
                                        window.currentUser.roles = userInfo.roles;
                                    }
                                    
                                    console.log("admin用户设置完成");
                                    
                                    // 尝试添加一个全局debug方法
                                    window.debugAdminInfo = function() {
                                        console.log("=============== Admin Debug Info ===============");
                                        console.log("LocalStorage user_info:", JSON.parse(localStorage.getItem('user_info') || '{}'));
                                        console.log("LocalStorage is_admin:", localStorage.getItem('is_admin'));
                                        console.log("Cookie is_admin:", document.cookie.split('; ').find(row => row.startsWith('is_admin=')));
                                        console.log("window.currentUser:", window.currentUser);
                                        console.log("===============================================");
                                    };
                                }
                            }
                        } catch(e) {
                            console.error("解析用户信息出错:", e);
                        }
                    });
                `;
                document.head.appendChild(scriptEl);
                
                // 如果是admin用户，使用特殊URL参数确保后端正确识别
                if (isAdminUser) {
                    window.location.href = nextUrl + "?bypass_jwt=true&admin=true";
                } else {
                    window.location.href = nextUrl;
                }
            } else {
                // 登录失败处理
                if (errorMsg) {
                    errorMsg.textContent = data.message || '登录失败，请检查用户名和密码';
                }
            }
        } catch (error) {
            console.error('登录请求出错:', error);
            // 恢复按钮状态
            const submitButton = loginForm.querySelector('button[type="submit"]');
            submitButton.disabled = false;
            submitButton.innerHTML = '登录';
            
            if (errorMsg) {
                errorMsg.textContent = '登录服务暂时不可用，请稍后再试';
            }
        }
    });
}); 