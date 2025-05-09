// 默认配置
const defaultConfig = {
    baseURL: '/api',
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json'
    }
};

// 请求拦截器
function requestInterceptor(config) {
    const token = localStorage.getItem('access_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
}

// 响应拦截器
function responseInterceptor(response) {
    if (response.status === 401) {
        localStorage.removeItem('access_token');
        window.location.href = '/login';
        return Promise.reject('未授权');
    }
    return response;
}

// 错误处理
function handleError(error) {
    if (error.response) {
        switch (error.response.status) {
            case 400:
                showError('请求参数错误');
                break;
            case 401:
                showError('未授权，请重新登录');
                localStorage.removeItem('access_token');
                window.location.href = '/login';
                break;
            case 403:
                showError('拒绝访问');
                break;
            case 404:
                showError('请求的资源不存在');
                break;
            case 500:
                showError('服务器错误');
                break;
            default:
                showError('网络错误');
        }
    } else if (error.request) {
        showError('网络请求超时');
    } else {
        showError('请求配置错误');
    }
    return Promise.reject(error);
}

// GET请求
async function get(url, params = {}, config = {}) {
    try {
        const queryString = new URLSearchParams(params).toString();
        const fullUrl = queryString ? `${url}?${queryString}` : url;
        const response = await fetch(defaultConfig.baseURL + fullUrl, {
            ...defaultConfig,
            ...config,
            method: 'GET'
        });
        return await responseInterceptor(response);
    } catch (error) {
        return handleError(error);
    }
}

// POST请求
async function post(url, data = {}, config = {}) {
    try {
        const response = await fetch(defaultConfig.baseURL + url, {
            ...defaultConfig,
            ...config,
            method: 'POST',
            body: JSON.stringify(data)
        });
        return await responseInterceptor(response);
    } catch (error) {
        return handleError(error);
    }
}

// PUT请求
async function put(url, data = {}, config = {}) {
    try {
        const response = await fetch(defaultConfig.baseURL + url, {
            ...defaultConfig,
            ...config,
            method: 'PUT',
            body: JSON.stringify(data)
        });
        return await responseInterceptor(response);
    } catch (error) {
        return handleError(error);
    }
}

// DELETE请求
async function del(url, config = {}) {
    try {
        const response = await fetch(defaultConfig.baseURL + url, {
            ...defaultConfig,
            ...config,
            method: 'DELETE'
        });
        return await responseInterceptor(response);
    } catch (error) {
        return handleError(error);
    }
}

// 上传文件
async function upload(url, file, onProgress = () => {}, config = {}) {
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const xhr = new XMLHttpRequest();
        
        // 进度处理
        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const progress = (event.loaded / event.total) * 100;
                onProgress(progress);
            }
        });
        
        // 发送请求
        xhr.open('POST', defaultConfig.baseURL + url);
        
        // 设置请求头
        const token = localStorage.getItem('access_token');
        if (token) {
            xhr.setRequestHeader('Authorization', `Bearer ${token}`);
        }
        
        return new Promise((resolve, reject) => {
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(JSON.parse(xhr.response));
                } else {
                    reject(xhr.statusText);
                }
            };
            
            xhr.onerror = () => reject(xhr.statusText);
            xhr.send(formData);
        });
    } catch (error) {
        return handleError(error);
    }
}

// 下载文件
async function download(url, filename, config = {}) {
    try {
        const response = await fetch(defaultConfig.baseURL + url, {
            ...defaultConfig,
            ...config,
            method: 'GET'
        });
        
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(downloadUrl);
    } catch (error) {
        return handleError(error);
    }
}

// 导出工具函数
export {
    get,
    post,
    put,
    del as delete,
    upload,
    download
}; 