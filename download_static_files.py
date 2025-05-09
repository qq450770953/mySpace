import os
import requests
from urllib.parse import urljoin

# 创建目录
def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# 下载文件
def download_file(url, save_path):
    print(f"Downloading {url} to {save_path}")
    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, 'wb') as f:
            f.write(response.content)
        print(f"Successfully downloaded {save_path}")
    else:
        print(f"Failed to download {url}, status code: {response.status_code}")

# 创建目录
static_dir = 'app/static'
css_dir = os.path.join(static_dir, 'css')
js_dir = os.path.join(static_dir, 'js')
ensure_dir(css_dir)
ensure_dir(js_dir)

# 文件列表
files_to_download = {
    # Font Awesome
    'https://use.fontawesome.com/releases/v6.0.0/css/all.min.css': 'css/fontawesome-all.min.css',
    
    # DataTables CSS
    'https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css': 'css/dataTables.bootstrap5.min.css',
    'https://cdn.datatables.net/buttons/2.2.2/css/buttons.bootstrap5.min.css': 'css/buttons.bootstrap5.min.css',
    'https://cdn.datatables.net/responsive/2.2.9/css/responsive.bootstrap5.min.css': 'css/responsive.bootstrap5.min.css',
    
    # Chart.js CSS
    'D:\work\app\static\js\chart.js@3.7.1/dist/chart.min.css': 'css/chart.min.css',
    
    # jQuery
    'https://code.jquery.com/jquery-3.6.0.min.js': 'js/jquery.min.js',
    
    # DataTables JavaScript
    'https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js': 'js/jquery.dataTables.min.js',
    'https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js': 'js/dataTables.bootstrap5.min.js',
    'https://cdn.datatables.net/buttons/2.2.2/js/dataTables.buttons.min.js': 'js/dataTables.buttons.min.js',
    'https://cdn.datatables.net/buttons/2.2.2/js/buttons.bootstrap5.min.js': 'js/buttons.bootstrap5.min.js',
    'https://cdn.datatables.net/responsive/2.2.9/js/dataTables.responsive.min.js': 'js/dataTables.responsive.min.js',
    'https://cdn.datatables.net/responsive/2.2.9/js/responsive.bootstrap5.min.js': 'js/responsive.bootstrap5.min.js',
    
    # Socket.IO
    'https://cdn.socket.io/4.0.1/socket.io.min.js': 'js/socket.io.min.js',
}

# 下载文件
for url, path in files_to_download.items():
    save_path = os.path.join(static_dir, path)
    download_file(url, save_path)

print("All files downloaded successfully!") 