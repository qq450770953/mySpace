import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import shutil

# 创建必要的目录
os.makedirs('app/static/css', exist_ok=True)
os.makedirs('app/static/js', exist_ok=True)

# 配置请求会话，添加重试机制
session = requests.Session()
retry = Retry(
    total=5,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["GET"]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)
session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

# 要下载的文件 - 使用多个CDN源以增加成功率
bootstrap_sources = [
    # 直接从Bootstrap官方CDN
    {
        'css': 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css',
        'js': 'https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js'
    },
    # 备用CDN 1 - Cloudflare
    {
        'css': 'https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/css/bootstrap.min.css',
        'js': 'https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.2.3/js/bootstrap.bundle.min.js'
    },
    # 备用CDN 2 - Unpkg
    {
        'css': 'https://unpkg.com/bootstrap@5.2.3/dist/css/bootstrap.min.css',
        'js': 'https://unpkg.com/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js'
    },
    # 国内CDN 1 - BootCDN
    {
        'css': 'https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/css/bootstrap.min.css',
        'js': 'https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.2.3/js/bootstrap.bundle.min.js'
    }
]

# 下载文件的函数
def download_file(url, save_path, retries=3):
    print(f'尝试下载 {url} 到 {save_path}...')
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        with open(save_path, 'wb') as f:
            f.write(response.content)
        print(f'✓ 成功下载并保存到 {save_path}')
        return True
    except Exception as e:
        print(f'✗ 下载失败: {str(e)}')
        return False

# 尝试从所有源下载文件
def try_all_sources():
    # 先尝试下载CSS
    css_success = False
    for source in bootstrap_sources:
        if download_file(source['css'], 'app/static/css/bootstrap.min.css'):
            css_success = True
            break
    
    # 再尝试下载JS
    js_success = False
    for source in bootstrap_sources:
        if download_file(source['js'], 'app/static/js/bootstrap.bundle.min.js'):
            js_success = True
            break
    
    # 检查下载结果
    if css_success and js_success:
        print('所有文件下载成功！')
        return True
    else:
        print('部分文件下载失败，将尝试使用内置备用文件...')
        return False

# 创建内置备用文件的函数
def create_fallback_files():
    print('创建备用简化的Bootstrap文件...')
    
    # 简化的CSS
    basic_css = """
    /* 基本的Bootstrap备用CSS */
    body { font-family: system-ui, sans-serif; line-height: 1.5; }
    .container { width: 100%; padding: 15px; margin-right: auto; margin-left: auto; }
    .row { display: flex; flex-wrap: wrap; margin-right: -15px; margin-left: -15px; }
    .col { flex: 1 0 0%; padding: 15px; }
    .btn { display: inline-block; font-weight: 400; text-align: center; vertical-align: middle; border: 1px solid transparent; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; border-radius: .25rem; }
    .btn-primary { color: #fff; background-color: #0d6efd; border-color: #0d6efd; }
    .alert { position: relative; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem; }
    .alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
    .alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
    .form-control { display: block; width: 100%; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; color: #495057; background-color: #fff; border: 1px solid #ced4da; border-radius: .25rem; }
    .table { width: 100%; margin-bottom: 1rem; color: #212529; border-collapse: collapse; }
    .table th, .table td { padding: .75rem; vertical-align: top; border-top: 1px solid #dee2e6; }
    """
    
    # 简化的JS
    basic_js = """
    /* 基本的Bootstrap备用JS */
    document.addEventListener('DOMContentLoaded', function() {
        // Modal处理
        const modalTriggers = document.querySelectorAll('[data-bs-toggle="modal"]');
        modalTriggers.forEach(trigger => {
            trigger.addEventListener('click', function() {
                const targetId = this.getAttribute('data-bs-target');
                const modal = document.querySelector(targetId);
                if (modal) {
                    modal.style.display = 'block';
                    modal.classList.add('show');
                    document.body.classList.add('modal-open');
                }
            });
        });
        
        // 模态框关闭按钮
        const closeButtons = document.querySelectorAll('[data-bs-dismiss="modal"]');
        closeButtons.forEach(button => {
            button.addEventListener('click', function() {
                const modal = this.closest('.modal');
                if (modal) {
                    modal.style.display = 'none';
                    modal.classList.remove('show');
                    document.body.classList.remove('modal-open');
                }
            });
        });
        
        // Alert关闭按钮
        const alertCloseButtons = document.querySelectorAll('.alert .btn-close');
        alertCloseButtons.forEach(button => {
            button.addEventListener('click', function() {
                const alert = this.closest('.alert');
                if (alert) {
                    alert.style.display = 'none';
                }
            });
        });
    });
    """
    
    try:
        # 写入CSS备用文件
        with open('app/static/css/bootstrap.min.css', 'w', encoding='utf-8') as f:
            f.write(basic_css)
        
        # 写入JS备用文件
        with open('app/static/js/bootstrap.bundle.min.js', 'w', encoding='utf-8') as f:
            f.write(basic_js)
        
        print('✓ 备用文件创建成功')
        return True
    except Exception as e:
        print(f'✗ 创建备用文件失败: {str(e)}')
        return False

# 主函数
def main():
    print('开始下载Bootstrap文件...')
    
    # 先尝试从CDN下载
    if not try_all_sources():
        # 如果CDN下载失败，创建备用文件
        create_fallback_files()
    
    print('下载和设置完成!')

if __name__ == "__main__":
    main() 