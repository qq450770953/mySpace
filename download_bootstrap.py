import os
import requests

# 创建必要的目录
os.makedirs('app/static/vendor/bootstrap/css', exist_ok=True)
os.makedirs('app/static/vendor/bootstrap/js', exist_ok=True)

# 要下载的文件
files = {
    'css': [
        ('https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css', 'bootstrap.min.css'),
        ('https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css', 'bootstrap-icons.css')
    ],
    'js': [
        ('https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js', 'bootstrap.bundle.min.js')
    ]
}

# 下载文件
for category, urls in files.items():
    for url, filename in urls:
        print(f'Downloading {filename}...')
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(f'app/static/vendor/bootstrap/{category}/{filename}', 'wb') as f:
                f.write(response.content)
            print(f'Successfully downloaded {filename}')
        except Exception as e:
            print(f'Error downloading {filename}: {str(e)}')

print('Download complete!') 