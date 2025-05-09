/**
 * 修复Bootstrap模态框按钮无法生效的问题
 */
document.addEventListener('DOMContentLoaded', function() {
    // 确保Bootstrap已加载
    if (typeof bootstrap === 'undefined') {
        console.error('Bootstrap未加载，无法修复模态框');
        // 使用Vanilla JS操作模态框
        vanillaModals();
        return;
    }

    // 检查Bootstrap版本和功能
    const hasModalAPI = bootstrap.Modal && 
                       (typeof bootstrap.Modal.getInstance === 'function' || 
                        typeof bootstrap.Modal.getOrCreateInstance === 'function');
    
    if (!hasModalAPI) {
        console.warn('当前Bootstrap版本不支持Modal API，使用替代方案');
        vanillaModals();
        return;
    }

    // 获取所有具有data-bs-toggle="modal"属性的按钮
    const modalTriggers = document.querySelectorAll('[data-bs-toggle="modal"]');
    
    // 为每个按钮绑定点击事件
    modalTriggers.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            
            // 获取模态框ID
            const targetSelector = button.getAttribute('data-bs-target');
            if (!targetSelector) {
                console.error('按钮缺少data-bs-target属性');
                return;
            }
            
            // 查找对应的模态框元素
            const targetModal = document.querySelector(targetSelector);
            if (!targetModal) {
                console.error(`未找到模态框: ${targetSelector}`);
                return;
            }
            
            // 使用Bootstrap的Modal API打开模态框
            try {
                // 检查并使用适当的方法实例化模态框
                let modalInstance;
                if (typeof bootstrap.Modal.getOrCreateInstance === 'function') {
                    modalInstance = bootstrap.Modal.getOrCreateInstance(targetModal);
                } else if (typeof bootstrap.Modal.getInstance === 'function') {
                    modalInstance = bootstrap.Modal.getInstance(targetModal);
                    if (!modalInstance) {
                        modalInstance = new bootstrap.Modal(targetModal);
                    }
                } else {
                    modalInstance = new bootstrap.Modal(targetModal);
                }
                modalInstance.show();
            } catch (error) {
                console.error('使用Bootstrap API打开模态框失败:', error);
                // 回退方案：使用Vanilla JS
                showModal(targetModal);
            }
        });
    });
    
    // 为所有模态框中的关闭按钮绑定事件
    document.querySelectorAll('.modal .btn-close, .modal .btn-secondary[data-bs-dismiss="modal"]').forEach(closeButton => {
        closeButton.addEventListener('click', function() {
            // 查找父模态框
            const modal = closeButton.closest('.modal');
            if (!modal) return;
            
            try {
                // 检查并使用适当的方法获取模态框实例
                let modalInstance;
                if (typeof bootstrap.Modal.getInstance === 'function') {
                    modalInstance = bootstrap.Modal.getInstance(modal);
                    if (modalInstance) {
                        modalInstance.hide();
                    } else {
                        throw new Error('未找到模态框实例');
                    }
                } else {
                    // 如果无法获取实例，尝试创建新实例
                    modalInstance = new bootstrap.Modal(modal);
                    modalInstance.hide();
                }
            } catch (error) {
                console.error('使用Bootstrap API关闭模态框失败:', error);
                // 回退方案：使用Vanilla JS
                hideModal(modal);
            }
        });
    });
    
    console.log('成功修复模态框按钮');
});

// 使用纯JavaScript操作模态框的回退方案
function vanillaModals() {
    // 为所有触发模态框的按钮绑定事件
    document.querySelectorAll('[data-bs-toggle="modal"]').forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            const targetSelector = button.getAttribute('data-bs-target');
            if (!targetSelector) return;
            
            const targetModal = document.querySelector(targetSelector);
            if (!targetModal) return;
            
            showModal(targetModal);
        });
    });
    
    // 为所有关闭按钮绑定事件
    document.querySelectorAll('.modal .btn-close, .modal .btn-secondary[data-bs-dismiss="modal"]').forEach(closeButton => {
        closeButton.addEventListener('click', function() {
            const modal = closeButton.closest('.modal');
            if (modal) {
                hideModal(modal);
            }
        });
    });
}

// 显示模态框
function showModal(modal) {
    modal.style.display = 'block';
    modal.classList.add('show');
    document.body.classList.add('modal-open');
    
    // 创建背景遮罩
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop fade show';
    document.body.appendChild(backdrop);
    
    // 存储背景遮罩用于后续关闭
    modal._backdrop = backdrop;
}

// 隐藏模态框
function hideModal(modal) {
    modal.classList.remove('show');
    setTimeout(() => {
        modal.style.display = 'none';
        document.body.classList.remove('modal-open');
        
        // 移除背景遮罩
        if (modal._backdrop) {
            modal._backdrop.remove();
            modal._backdrop = null;
        } else {
            // 尝试查找并移除所有背景遮罩
            document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
                backdrop.remove();
            });
        }
    }, 300);
} 