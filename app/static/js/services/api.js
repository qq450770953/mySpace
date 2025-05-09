import { http } from '../utils/http';

// 认证相关API
export const authAPI = {
    login: (data) => http.post('/auth/login', data),
    register: (data) => http.post('/auth/register', data),
    logout: () => http.post('/auth/logout'),
    refreshToken: () => http.post('/auth/refresh'),
    getCurrentUser: () => http.get('/auth/me')
};

// 用户相关API
export const userAPI = {
    getUsers: (params) => http.get('/users', params),
    getUser: (id) => http.get(`/users/${id}`),
    createUser: (data) => http.post('/users', data),
    updateUser: (id, data) => http.put(`/users/${id}`, data),
    deleteUser: (id) => http.delete(`/users/${id}`),
    updateProfile: (data) => http.put('/users/profile', data),
    changePassword: (data) => http.put('/users/password', data)
};

// 项目相关API
export const projectAPI = {
    getProjects: (params) => http.get('/projects', params),
    getProject: (id) => http.get(`/projects/${id}`),
    createProject: (data) => http.post('/projects', data),
    updateProject: (id, data) => http.put(`/projects/${id}`, data),
    deleteProject: (id) => http.delete(`/projects/${id}`),
    getProjectMembers: (id) => http.get(`/projects/${id}/members`),
    addProjectMember: (id, data) => http.post(`/projects/${id}/members`, data),
    removeProjectMember: (id, userId) => http.delete(`/projects/${id}/members/${userId}`)
};

// 任务相关API
export const taskAPI = {
    getTasks: (params) => http.get('/tasks', params),
    getTask: (id) => http.get(`/tasks/${id}`),
    createTask: (data) => http.post('/tasks', data),
    updateTask: (id, data) => http.put(`/tasks/${id}`, data),
    deleteTask: (id) => http.delete(`/tasks/${id}`),
    updateTaskStatus: (id, status) => http.put(`/tasks/${id}/status`, { status }),
    assignTask: (id, userId) => http.put(`/tasks/${id}/assign`, { userId }),
    getTaskComments: (id) => http.get(`/tasks/${id}/comments`),
    addTaskComment: (id, data) => http.post(`/tasks/${id}/comments`, data)
};

// 资源相关API
export const resourceAPI = {
    getResources: (params) => http.get('/resources', params),
    getResource: (id) => http.get(`/resources/${id}`),
    createResource: (data) => http.post('/resources', data),
    updateResource: (id, data) => http.put(`/resources/${id}`, data),
    deleteResource: (id) => http.delete(`/resources/${id}`),
    allocateResource: (id, data) => http.post(`/resources/${id}/allocate`, data),
    releaseResource: (id, allocationId) => http.delete(`/resources/${id}/allocate/${allocationId}`)
};

// 风险相关API
export const riskAPI = {
    getRisks: (params) => http.get('/risks', params),
    getRisk: (id) => http.get(`/risks/${id}`),
    createRisk: (data) => http.post('/risks', data),
    updateRisk: (id, data) => http.put(`/risks/${id}`, data),
    deleteRisk: (id) => http.delete(`/risks/${id}`),
    updateRiskStatus: (id, status) => http.put(`/risks/${id}/status`, { status }),
    assignRisk: (id, userId) => http.put(`/risks/${id}/assign`, { userId })
};

// 仪表盘相关API
export const dashboardAPI = {
    getOverview: () => http.get('/dashboard/overview'),
    getProjectStats: () => http.get('/dashboard/projects'),
    getTaskStats: () => http.get('/dashboard/tasks'),
    getResourceStats: () => http.get('/dashboard/resources'),
    getRiskStats: () => http.get('/dashboard/risks')
};

// 通知相关API
export const notificationAPI = {
    getNotifications: (params) => http.get('/notifications', params),
    markAsRead: (id) => http.put(`/notifications/${id}/read`),
    markAllAsRead: () => http.put('/notifications/read-all'),
    deleteNotification: (id) => http.delete(`/notifications/${id}`)
};

// 文件上传相关API
export const fileAPI = {
    upload: (file, onProgress) => http.upload('/upload', file, onProgress),
    download: (id, filename) => http.download(`/files/${id}`, filename)
};

// 聊天相关API
export const chatAPI = {
    getMessages: (params) => http.get('/chat/messages', params),
    sendMessage: (data) => http.post('/chat/messages', data),
    getChats: () => http.get('/chat/chats'),
    createChat: (data) => http.post('/chat/chats', data)
};

// 看板相关API
export const kanbanAPI = {
    getBoards: () => http.get('/kanban/boards'),
    getBoard: (id) => http.get(`/kanban/boards/${id}`),
    createBoard: (data) => http.post('/kanban/boards', data),
    updateBoard: (id, data) => http.put(`/kanban/boards/${id}`, data),
    deleteBoard: (id) => http.delete(`/kanban/boards/${id}`),
    getColumns: (boardId) => http.get(`/kanban/boards/${boardId}/columns`),
    createColumn: (boardId, data) => http.post(`/kanban/boards/${boardId}/columns`, data),
    updateColumn: (boardId, columnId, data) => http.put(`/kanban/boards/${boardId}/columns/${columnId}`, data),
    deleteColumn: (boardId, columnId) => http.delete(`/kanban/boards/${boardId}/columns/${columnId}`),
    moveTask: (boardId, taskId, data) => http.put(`/kanban/boards/${boardId}/tasks/${taskId}/move`, data)
}; 