import os
import requests
from pathlib import Path

def download_file(url, target_path):
    """Download a file from URL to target path"""
    response = requests.get(url)
    if response.status_code == 200:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'wb') as f:
            f.write(response.content)
        print(f"Downloaded: {target_path}")
    else:
        print(f"Failed to download: {url}")

def setup_static_files():
    """Setup required static files"""
    base_dir = Path(__file__).parent.parent / 'static'
    
    # DataTables files
    datatables_files = {
        'css': [
            ('https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css', 'css/dataTables.bootstrap5.min.css'),
            ('https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css', 'css/buttons.bootstrap5.min.css'),
            ('https://cdn.datatables.net/responsive/2.5.0/css/responsive.bootstrap5.min.css', 'css/responsive.bootstrap5.min.css')
        ],
        'js': [
            ('https://code.jquery.com/jquery-3.7.1.min.js', 'js/jquery.min.js'),
            ('https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js', 'js/jquery.dataTables.min.js'),
            ('https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js', 'js/dataTables.bootstrap5.min.js'),
            ('https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js', 'js/dataTables.responsive.min.js'),
            ('https://cdn.datatables.net/responsive/2.5.0/js/responsive.bootstrap5.min.js', 'js/responsive.bootstrap5.min.js')
        ]
    }
    
    # Chart.js files
    chart_files = {
        'css': [
            ('https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.min.css', 'css/chart.min.css')
        ],
        'js': [
            ('https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js', 'js/chart.min.js')
        ]
    }
    
    # Font Awesome files
    font_awesome_files = {
        'webfonts': [
            ('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-solid-900.woff2', 'webfonts/fa-solid-900.woff2'),
            ('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/webfonts/fa-solid-900.ttf', 'webfonts/fa-solid-900.ttf')
        ]
    }
    
    # Download all files
    for category, files in datatables_files.items():
        for url, path in files:
            download_file(url, base_dir / path)
            
    for category, files in chart_files.items():
        for url, path in files:
            download_file(url, base_dir / path)
            
    for category, files in font_awesome_files.items():
        for url, path in files:
            download_file(url, base_dir / path)
            
    # Create main.js if it doesn't exist
    main_js_path = base_dir / 'js' / 'main.js'
    if not main_js_path.exists():
        with open(main_js_path, 'w') as f:
            f.write('// Main JavaScript file\n')
        print(f"Created: {main_js_path}")

if __name__ == '__main__':
    setup_static_files() 