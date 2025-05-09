/**
 * 背景图片加载辅助脚本
 * 提供多种方法尝试加载背景图片
 */

(function() {
    // 在DOMContentLoaded和load事件都尝试加载背景图
    document.addEventListener('DOMContentLoaded', initBackgroundLoader);
    window.addEventListener('load', initBackgroundLoader);
    
    // 已尝试加载的标记，避免重复加载
    let initialized = false;
    
    function initBackgroundLoader() {
        if (initialized) return;
        initialized = true;
        
        console.log('Background Helper 初始化');
        loadBackgroundImages();
        
        // 1秒后再次尝试，以防第一次尝试失败
        setTimeout(loadBackgroundImages, 1000);
    }
    
    // 尝试加载所有可能的背景图片
    function loadBackgroundImages() {
        console.log('尝试加载背景图片...');
        
        // 1. 尝试标准容器方法
        const bgContainer = document.getElementById('bg-container');
        if (bgContainer) {
            tryLoadingBackgroundInContainer(bgContainer);
        }
        
        // 2. 尝试直接img元素方法
        const bgImage = document.getElementById('bg-image');
        if (bgImage) {
            console.log('找到bg-image元素，确保它可见');
            bgImage.style.opacity = '0.9';
            bgImage.style.zIndex = '-2';
        }
        
        // 3. 尝试body背景方法
        tryLoadingBodyBackground();
        
        // 4. 创建备用img元素
        tryCreateBackupImageElement();
    }
    
    // 尝试在容器中加载背景图片
    function tryLoadingBackgroundInContainer(container) {
        const pathsToTry = [
            '/static/images/background.png',
            '/static/uploads/background.png',
            window.location.origin + '/static/images/background.png',
            window.location.origin + '/static/uploads/background.png'
        ];
        
        // 依次尝试各种路径
        for (let i = 0; i < pathsToTry.length; i++) {
            const path = pathsToTry[i];
            const img = new Image();
            
            img.onload = function() {
                console.log(`容器背景方法: ✅ 路径 ${i + 1} 加载成功: ${path}`);
                container.style.backgroundImage = `url('${path}')`;
                container.style.backgroundSize = 'cover';
                container.style.backgroundPosition = 'center';
            };
            
            img.onerror = function() {
                console.error(`容器背景方法: ❌ 路径 ${i + 1} 加载失败: ${path}`);
            };
            
            img.src = path;
        }
    }
    
    // 尝试设置body背景
    function tryLoadingBodyBackground() {
        const pathsToTry = [
            '/static/images/background.png',
            '/static/uploads/background.png',
            window.location.origin + '/static/images/background.png',
            window.location.origin + '/static/uploads/background.png'
        ];
        
        for (let i = 0; i < pathsToTry.length; i++) {
            const path = pathsToTry[i];
            const img = new Image();
            
            img.onload = function() {
                console.log(`Body背景方法: ✅ 路径 ${i + 1} 加载成功: ${path}`);
                document.body.style.backgroundImage = `url('${path}')`;
                document.body.style.backgroundSize = 'cover';
                document.body.style.backgroundPosition = 'center';
                document.body.style.backgroundRepeat = 'no-repeat';
                document.body.style.backgroundAttachment = 'fixed';
            };
            
            img.onerror = function() {
                console.error(`Body背景方法: ❌ 路径 ${i + 1} 加载失败: ${path}`);
            };
            
            img.src = path;
        }
    }
    
    // 创建备用图片元素
    function tryCreateBackupImageElement() {
        if (document.getElementById('backup-bg-image')) return;
        
        const img = document.createElement('img');
        img.id = 'backup-bg-image';
        img.style.position = 'fixed';
        img.style.top = '0';
        img.style.left = '0';
        img.style.width = '100%';
        img.style.height = '100%';
        img.style.objectFit = 'cover';
        img.style.zIndex = '-3';
        img.style.opacity = '0';
        img.alt = '背景图片';
        
        // 添加到body最前面
        if (document.body.firstChild) {
            document.body.insertBefore(img, document.body.firstChild);
        } else {
            document.body.appendChild(img);
        }
        
        // 尝试多个路径
        const pathsToTry = [
            '/static/images/background.png',
            '/static/uploads/background.png',
            window.location.origin + '/static/images/background.png',
            window.location.origin + '/static/uploads/background.png'
        ];
        
        // 依次尝试
        let currentIndex = 0;
        
        function tryNextPath() {
            if (currentIndex >= pathsToTry.length) {
                console.error('备用图片元素: ❌ 所有路径都加载失败');
                return;
            }
            
            const path = pathsToTry[currentIndex];
            img.src = path;
            
            img.onload = function() {
                console.log(`备用图片元素: ✅ 路径 ${currentIndex + 1} 加载成功: ${path}`);
                img.style.opacity = '0.9';
            };
            
            img.onerror = function() {
                console.error(`备用图片元素: ❌ 路径 ${currentIndex + 1} 加载失败: ${path}`);
                currentIndex++;
                tryNextPath();
            };
        }
        
        tryNextPath();
    }
})(); 