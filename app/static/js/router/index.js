// 路由配置
const routes = [
    {
        path: '/',
        redirect: '/dashboard'
    },
    {
        path: '/login',
        name: 'login',
        component: () => import('../views/Login.vue'),
        meta: { requiresAuth: false }
    },
    {
        path: '/register',
        name: 'register',
        component: () => import('../views/Register.vue'),
        meta: { requiresAuth: false }
    },
    {
        path: '/dashboard',
        name: 'dashboard',
        component: () => import('../views/Dashboard.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/projects',
        name: 'projects',
        component: () => import('../views/Projects.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/projects/:id',
        name: 'project-detail',
        component: () => import('../views/ProjectDetail.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/tasks',
        name: 'tasks',
        component: () => import('../views/Tasks.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/tasks/:id',
        name: 'task-detail',
        component: () => import('../views/TaskDetail.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/resources',
        name: 'resources',
        component: () => import('../views/Resources.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/resources/:id',
        name: 'resource-detail',
        component: () => import('../views/ResourceDetail.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/risks',
        name: 'risks',
        component: () => import('../views/Risks.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/risks/:id',
        name: 'risk-detail',
        component: () => import('../views/RiskDetail.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/users',
        name: 'users',
        component: () => import('../views/Users.vue'),
        meta: { requiresAuth: true, requiresAdmin: true }
    },
    {
        path: '/users/:id',
        name: 'user-detail',
        component: () => import('../views/UserDetail.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/profile',
        name: 'profile',
        component: () => import('../views/Profile.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/settings',
        name: 'settings',
        component: () => import('../views/Settings.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/chat',
        name: 'chat',
        component: () => import('../views/Chat.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/kanban',
        name: 'kanban',
        component: () => import('../views/Kanban.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/gantt',
        name: 'gantt',
        component: () => import('../views/Gantt.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/notifications',
        name: 'notifications',
        component: () => import('../views/Notifications.vue'),
        meta: { requiresAuth: true }
    },
    {
        path: '/404',
        name: '404',
        component: () => import('../views/404.vue'),
        meta: { requiresAuth: false }
    },
    {
        path: '/403',
        name: '403',
        component: () => import('../views/403.vue'),
        meta: { requiresAuth: false }
    },
    {
        path: '/500',
        name: '500',
        component: () => import('../views/500.vue'),
        meta: { requiresAuth: false }
    },
    {
        path: '*',
        redirect: '/404'
    }
];

// 路由守卫
const router = {
    routes,
    
    beforeEach(to, from, next) {
        const requiresAuth = to.matched.some(record => record.meta.requiresAuth);
        const requiresAdmin = to.matched.some(record => record.meta.requiresAdmin);
        const isAuthenticated = store.getters.isAuthenticated;
        const isAdmin = store.getters.currentUser?.role === 'admin';
        
        if (requiresAuth && !isAuthenticated) {
            next('/login');
        } else if (requiresAdmin && !isAdmin) {
            next('/403');
        } else {
            next();
        }
    },
    
    afterEach(to, from) {
        // 更新页面标题
        document.title = to.meta.title ? `${to.meta.title} - Task Management System` : 'Task Management System';
        
        // 滚动到顶部
        window.scrollTo(0, 0);
    }
};

export default router; 