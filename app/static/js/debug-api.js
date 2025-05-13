/**
 * 调试工具脚本 - 用于测试项目相关API
 */

// 封装fetch请求，自动处理常见错误情况
async function debugFetch(url, options = {}) {
    console.log(`[DEBUG] 发送请求到: ${url}`);
    console.log('[DEBUG] 请求选项:', options);
    
    try {
        const response = await fetch(url, options);
        console.log(`[DEBUG] 响应状态: ${response.status}`);
        
        // 获取响应头信息
        const headers = {};
        response.headers.forEach((value, key) => {
            headers[key] = value;
        });
        console.log('[DEBUG] 响应头:', headers);
        
        // 尝试作为JSON解析
        let data;
        const contentType = response.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            try {
                data = await response.json();
                console.log('[DEBUG] 响应JSON数据:', data);
                return { ok: response.ok, status: response.status, data };
            } catch (e) {
                console.error('[DEBUG] 解析JSON失败:', e);
                const text = await response.text();
                console.log('[DEBUG] 响应文本数据:', text);
                return { ok: false, status: response.status, error: '解析JSON失败', text };
            }
        } else {
            // 如果不是JSON，则作为文本处理
            const text = await response.text();
            console.log('[DEBUG] 响应文本数据:', text.substring(0, 500) + (text.length > 500 ? '...' : ''));
            
            // 检查是否是HTML
            if (text.includes('<!DOCTYPE') || text.includes('<html>')) {
                console.warn('[DEBUG] 收到HTML响应而不是预期的JSON');
                return { ok: false, status: response.status, error: '收到HTML响应而不是预期的JSON', html: text };
            }
            
            // 尝试解析为JSON
            try {
                data = JSON.parse(text);
                console.log('[DEBUG] 从文本中解析出JSON数据:', data);
                return { ok: response.ok, status: response.status, data };
            } catch (e) {
                console.warn('[DEBUG] 文本不是有效的JSON');
                return { ok: response.ok, status: response.status, text };
            }
        }
    } catch (error) {
        console.error('[DEBUG] 请求失败:', error);
        return { ok: false, error: error.message };
    }
}

// 获取CSRF令牌
async function debugGetCsrfToken() {
    console.log('[DEBUG] 获取CSRF令牌...');
    
    const timestamp = new Date().getTime();
    const result = await debugFetch(`/auth/csrf-token?bypass_jwt=true&_=${timestamp}`);
    
    if (result.ok && result.data && result.data.csrf_token) {
        console.log('[DEBUG] 成功获取CSRF令牌:', result.data.csrf_token);
        return result.data.csrf_token;
    } else {
        console.error('[DEBUG] 获取CSRF令牌失败:', result);
        return null;
    }
}

// 测试项目编辑器API
async function debugProjectEditorApi(projectId) {
    console.log(`[DEBUG] 测试项目编辑器API, 项目ID: ${projectId}`);
    
    // 获取CSRF令牌
    const csrfToken = await debugGetCsrfToken();
    if (!csrfToken) {
        console.error('[DEBUG] 无法获取CSRF令牌，测试终止');
        return;
    }
    
    // 构建请求头
    const headers = {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-TOKEN': csrfToken
    };
    
    // 测试项目编辑器API
    const timestamp = new Date().getTime();
    const result = await debugFetch(`/api/noauth/project-editor/${projectId}?bypass_jwt=true&csrf_token=${encodeURIComponent(csrfToken)}&_=${timestamp}`, {
        headers: headers
    });
    
    console.log('[DEBUG] 项目编辑器API测试结果:', result);
    return result;
}

// 测试标准项目API
async function debugStandardProjectApi(projectId) {
    console.log(`[DEBUG] 测试标准项目API, 项目ID: ${projectId}`);
    
    // 获取CSRF令牌
    const csrfToken = await debugGetCsrfToken();
    if (!csrfToken) {
        console.error('[DEBUG] 无法获取CSRF令牌，测试终止');
        return;
    }
    
    // 构建请求头
    const headers = {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-TOKEN': csrfToken
    };
    
    // 测试标准项目API
    const timestamp = new Date().getTime();
    const result = await debugFetch(`/api/projects/${projectId}?bypass_jwt=true&csrf_token=${encodeURIComponent(csrfToken)}&_=${timestamp}`, {
        headers: headers
    });
    
    console.log('[DEBUG] 标准项目API测试结果:', result);
    return result;
}

// 测试项目无认证API
async function debugNoauthProjectApi(projectId) {
    console.log(`[DEBUG] 测试项目无认证API, 项目ID: ${projectId}`);
    
    // 获取CSRF令牌
    const csrfToken = await debugGetCsrfToken();
    if (!csrfToken) {
        console.error('[DEBUG] 无法获取CSRF令牌，测试终止');
        return;
    }
    
    // 构建请求头
    const headers = {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-TOKEN': csrfToken
    };
    
    // 测试项目无认证API
    const timestamp = new Date().getTime();
    const result = await debugFetch(`/api/noauth/projects/${projectId}?bypass_jwt=true&csrf_token=${encodeURIComponent(csrfToken)}&_=${timestamp}`, {
        headers: headers
    });
    
    console.log('[DEBUG] 项目无认证API测试结果:', result);
    return result;
}

// 测试更新项目API
async function debugUpdateProjectApi(projectId, projectData) {
    console.log(`[DEBUG] 测试更新项目API, 项目ID: ${projectId}`);
    
    // 获取CSRF令牌
    const csrfToken = await debugGetCsrfToken();
    if (!csrfToken) {
        console.error('[DEBUG] 无法获取CSRF令牌，测试终止');
        return;
    }
    
    // 构建请求头
    const headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRF-TOKEN': csrfToken
    };
    
    // 测试更新项目API
    const timestamp = new Date().getTime();
    const result = await debugFetch(`/api/projects/${projectId}?bypass_jwt=true&csrf_token=${encodeURIComponent(csrfToken)}&_=${timestamp}`, {
        method: 'PUT',
        headers: headers,
        body: JSON.stringify(projectData || {
            name: '测试更新项目',
            description: '这是一个测试更新',
            status: 'active',
            start_date: new Date().toISOString().split('T')[0],
            end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
        })
    });
    
    console.log('[DEBUG] 更新项目API测试结果:', result);
    return result;
}

// 综合测试项目API并修复问题
async function testAndFixProject(projectId) {
    console.log(`[DEBUG] 开始综合测试和修复项目API, 项目ID: ${projectId}`);
    const results = {
        csrfToken: null,
        tests: {},
        recommendations: []
    };
    
    // 第1步: 获取CSRF令牌
    try {
        results.csrfToken = await debugGetCsrfToken();
        if (!results.csrfToken) {
            results.recommendations.push('CSRF令牌获取失败，需要检查/auth/csrf-token API');
        } else {
            console.log(`[DEBUG] 成功获取CSRF令牌: ${results.csrfToken.substring(0, 10)}...`);
        }
    } catch (e) {
        results.recommendations.push(`CSRF令牌获取异常: ${e.message}`);
    }
    
    // 第2步: 测试项目编辑器API
    try {
        results.tests.editor = await debugProjectEditorApi(projectId);
        if (results.tests.editor.ok) {
            console.log('[DEBUG] 项目编辑器API测试成功');
        } else {
            results.recommendations.push('项目编辑器API失败，可能需要检查/api/noauth/project-editor/{projectId}路由');
        }
    } catch (e) {
        results.recommendations.push(`项目编辑器API异常: ${e.message}`);
    }
    
    // 第3步: 测试标准项目API
    try {
        results.tests.standard = await debugStandardProjectApi(projectId);
        if (results.tests.standard.ok) {
            console.log('[DEBUG] 标准项目API测试成功');
        } else {
            results.recommendations.push('标准项目API失败，可能需要检查/api/projects/{projectId}路由');
        }
    } catch (e) {
        results.recommendations.push(`标准项目API异常: ${e.message}`);
    }
    
    // 第4步: 测试无认证项目API
    try {
        results.tests.noauth = await debugNoauthProjectApi(projectId);
        if (results.tests.noauth.ok) {
            console.log('[DEBUG] 无认证项目API测试成功');
        } else {
            results.recommendations.push('无认证项目API失败，可能需要检查/api/noauth/projects/{projectId}路由');
        }
    } catch (e) {
        results.recommendations.push(`无认证项目API异常: ${e.message}`);
    }
    
    // 第5步: 尝试简单更新项目
    try {
        const simpleUpdate = {
            name: `测试项目 #${projectId} (${new Date().toISOString().slice(0, 16)})`,
            description: '这是一个API调试测试'
        };
        
        results.tests.update = await debugUpdateProjectApi(projectId, simpleUpdate);
        if (results.tests.update.ok) {
            console.log('[DEBUG] 更新项目API测试成功');
        } else {
            results.recommendations.push('更新项目API失败，可能需要检查PUT /api/projects/{projectId}路由');
        }
    } catch (e) {
        results.recommendations.push(`更新项目API异常: ${e.message}`);
    }
    
    // 分析结果，生成建议
    console.log(`[DEBUG] 完成综合测试，成功测试: ${Object.values(results.tests).filter(r => r && r.ok).length}/${Object.keys(results.tests).length}`);
    
    if (results.recommendations.length === 0) {
        results.recommendations.push('所有API测试通过，不需要修复');
    } else {
        console.log('[DEBUG] 存在需要修复的问题:', results.recommendations);
    }
    
    // 返回测试结果
    return results;
}

// 导出调试函数
window.debugApi = {
    getProject: debugStandardProjectApi,
    getProjectEditor: debugProjectEditorApi,
    getNoauthProject: debugNoauthProjectApi,
    updateProject: debugUpdateProjectApi,
    getCsrfToken: debugGetCsrfToken,
    fetch: debugFetch,
    testAndFix: testAndFixProject
}; 