/**
 * 用于修复模态框和其他UI组件的脚本
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('fix-modals.js 加载完成');
    
    // 修复Bootstrap模态框的问题
    fixBootstrapModals();
    
    // 修复资源文件404问题
    fixResourceNotFound();
    
    // 添加资源文件加载错误处理
    handleResourceLoadErrors();
});

/**
 * 修复Bootstrap模态框的问题
 */
function fixBootstrapModals() {
    // 确保jQuery和Bootstrap都已加载
    if (typeof $ === 'undefined' || typeof $.fn.modal === 'undefined') {
        console.warn('Bootstrap或jQuery未加载，无法修复模态框');
        return;
    }

    // 修复模态框多次初始化问题
    $(document).off('show.bs.modal').on('show.bs.modal', '.modal', function () {
        var zIndex = 1040 + (10 * $('.modal:visible').length);
        $(this).css('z-index', zIndex);
        setTimeout(function() {
            $('.modal-backdrop').not('.modal-stack').css('z-index', zIndex - 1).addClass('modal-stack');
        }, 0);
    });
}

/**
 * 修复资源文件404问题
 */
function fixResourceNotFound() {
    // 检查是否有"Resource was not cached"错误
    if (document.body.textContent.includes('Content unavailable') || 
        document.body.textContent.includes('Resource was not cached')) {
        
        console.log('检测到资源文件未找到，尝试修复...');
        
        // 判断是否在dashboard页面
        const isOnDashboard = window.location.href.includes('/dashboard') || 
                             document.title.includes('仪表盘');
        
        if (isOnDashboard) {
            console.log('在仪表盘页面检测到资源问题，尝试重载页面...');
            
            // 清除角色缓存，强制重新初始化
            localStorage.removeItem('user_roles_initialized');
            
            // 添加页面刷新参数，跳过缓存
            const reloadUrl = window.location.href.includes('?') ? 
                window.location.href + '&reload=' + Date.now() :
                window.location.href + '?reload=' + Date.now();
            
            // 延迟2秒后重载
            setTimeout(() => {
                window.location.href = reloadUrl;
            }, 2000);
        }
    }
}

/**
 * 处理资源文件加载错误
 */
function handleResourceLoadErrors() {
    // 监听所有资源加载错误
    window.addEventListener('error', function(e) {
        const target = e.target;
        
        // 只处理资源加载错误
        if (target && (target.tagName === 'SCRIPT' || target.tagName === 'LINK' || target.tagName === 'IMG')) {
            console.error('资源加载失败:', target.src || target.href);
            
            // 如果是关键JS文件加载失败
            if ((target.src && target.src.includes('dashboard.js')) || 
                (target.href && target.href.includes('style.css'))) {
                
                console.warn('关键资源加载失败，尝试刷新页面...');
                
                // 在localStorage中记录失败状态，避免无限刷新
                const failCount = parseInt(localStorage.getItem('resource_load_fails') || '0');
                
                // 如果失败次数少于3次，尝试刷新
                if (failCount < 3) {
                    localStorage.setItem('resource_load_fails', (failCount + 1).toString());
                    
                    // 延迟3秒后刷新，给用户时间看到错误
                    setTimeout(() => {
                        window.location.reload(true); // 强制从服务器重新加载
                    }, 3000);
                } else {
                    console.error('多次尝试加载资源失败，请检查服务器状态或手动刷新页面');
                    // 重置计数器，允许用户手动刷新后再次尝试
                    localStorage.setItem('resource_load_fails', '0');
                }
            }
        }
    }, true);
}

/**
 * 在控制台中显示调试信息
 */
console.log('UI修复脚本已加载，系统就绪'); 