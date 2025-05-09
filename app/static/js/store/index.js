import { authAPI, userAPI } from '../services/api';

// 状态管理
const store = {
    state: {
        user: null,
        token: localStorage.getItem('access_token'),
        isAuthenticated: !!localStorage.getItem('access_token'),
        loading: false,
        error: null
    },
    
    mutations: {
        setUser(state, user) {
            state.user = user;
        },
        setToken(state, token) {
            state.token = token;
            state.isAuthenticated = !!token;
            if (token) {
                localStorage.setItem('access_token', token);
            } else {
                localStorage.removeItem('access_token');
            }
        },
        setLoading(state, loading) {
            state.loading = loading;
        },
        setError(state, error) {
            state.error = error;
        }
    },
    
    actions: {
        async login({ commit }, credentials) {
            try {
                commit('setLoading', true);
                const response = await authAPI.login(credentials);
                commit('setToken', response.token);
                commit('setUser', response.user);
                return response;
            } catch (error) {
                commit('setError', error.message);
                throw error;
            } finally {
                commit('setLoading', false);
            }
        },
        
        async register({ commit }, userData) {
            try {
                commit('setLoading', true);
                const response = await authAPI.register(userData);
                return response;
            } catch (error) {
                commit('setError', error.message);
                throw error;
            } finally {
                commit('setLoading', false);
            }
        },
        
        async logout({ commit }) {
            try {
                commit('setLoading', true);
                await authAPI.logout();
                commit('setToken', null);
                commit('setUser', null);
            } catch (error) {
                commit('setError', error.message);
                throw error;
            } finally {
                commit('setLoading', false);
            }
        },
        
        async refreshToken({ commit }) {
            try {
                const response = await authAPI.refreshToken();
                commit('setToken', response.token);
                return response;
            } catch (error) {
                commit('setToken', null);
                commit('setUser', null);
                throw error;
            }
        },
        
        async getCurrentUser({ commit }) {
            try {
                const user = await authAPI.getCurrentUser();
                commit('setUser', user);
                return user;
            } catch (error) {
                commit('setToken', null);
                commit('setUser', null);
                throw error;
            }
        },
        
        async updateProfile({ commit }, profileData) {
            try {
                commit('setLoading', true);
                const user = await userAPI.updateProfile(profileData);
                commit('setUser', user);
                return user;
            } catch (error) {
                commit('setError', error.message);
                throw error;
            } finally {
                commit('setLoading', false);
            }
        },
        
        async changePassword({ commit }, passwordData) {
            try {
                commit('setLoading', true);
                await userAPI.changePassword(passwordData);
            } catch (error) {
                commit('setError', error.message);
                throw error;
            } finally {
                commit('setLoading', false);
            }
        }
    },
    
    getters: {
        isAuthenticated: state => state.isAuthenticated,
        currentUser: state => state.user,
        isLoading: state => state.loading,
        error: state => state.error
    }
};

export default store; 