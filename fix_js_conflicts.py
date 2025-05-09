#!/usr/bin/env python
"""
修复JavaScript变量冲突工具
"""
import os
import re
import sys
import shutil
from datetime import datetime

# 项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_JS_DIR = os.path.join(BASE_DIR, 'app', 'static', 'js')

# 创建备份目录
def create_backup_dir():
    backup_dir = os.path.join(BASE_DIR, 'js_backups', datetime.now().strftime('%Y%m%d_%H%M%S'))
    os.makedirs(backup_dir, exist_ok=True)
    return backup_dir

# 备份文件
def backup_file(file_path, backup_dir):
    file_name = os.path.basename(file_path)
    backup_path = os.path.join(backup_dir, file_name)
    shutil.copy2(file_path, backup_path)
    print(f"已备份: {file_path} -> {backup_path}")
    return backup_path

# 检查并修复csrf.js文件中的变量声明
def fix_csrf_js():
    csrf_js_path = os.path.join(STATIC_JS_DIR, 'csrf.js')
    if not os.path.exists(csrf_js_path):
        print(f"错误: CSRF.js文件不存在: {csrf_js_path}")
        return False
    
    with open(csrf_js_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 检查是否已经使用了闭包
    if "// 使用自执行函数创建闭包，避免全局变量命名冲突" in content:
        print("CSRF.js已经修复，不需要更改")
        return True
    
    # 备份文件
    backup_dir = create_backup_dir()
    backup_file(csrf_js_path, backup_dir)
    
    # 修复变量冲突
    new_content = content
    
    # 1. 替换全局变量声明
    new_content = re.sub(
        r'// CSRF令牌处理\s*\n\s*let csrfToken = null;\s*\n\s*let tokenRefreshPromise = null;',
        '''// 使用自执行函数创建闭包，避免全局变量命名冲突
(function() {
    // CSRF令牌处理 - 放在模块作用域内防止冲突
    let _csrfToken = null;
    let _tokenRefreshPromise = null;''',
        new_content
    )
    
    # 2. 替换变量引用
    new_content = new_content.replace('csrfToken', '_csrfToken')
    new_content = new_content.replace('tokenRefreshPromise', '_tokenRefreshPromise')
    
    # 3. 添加闭包结束
    new_content = re.sub(
        r'// 导出函数\s*\nwindow\.getCsrfToken = getCsrfToken;',
        '''// 导出函数到全局作用域
window.getCsrfToken = getCsrfToken;''',
        new_content
    )
    
    # 4. 在文件末尾添加闭包结束
    if not new_content.strip().endswith('})();'):
        new_content = new_content.rstrip() + '\n})();'
    
    # 写回文件
    with open(csrf_js_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"已修复: {csrf_js_path}")
    return True

# 检查并修复login.js文件中的变量声明
def fix_login_js():
    login_js_path = os.path.join(STATIC_JS_DIR, 'login.js')
    if not os.path.exists(login_js_path):
        print(f"警告: Login.js文件不存在: {login_js_path}")
        return False
    
    with open(login_js_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 检查是否已经使用了formCsrfToken变量
    if "formCsrfToken" in content:
        print("Login.js已经修复，不需要更改")
        return True
    
    # 备份文件
    backup_dir = create_backup_dir()
    backup_file(login_js_path, backup_dir)
    
    # 修复变量冲突
    # 1. 替换csrfToken变量
    content = re.sub(
        r'const csrfToken = csrfTokenField \? csrfTokenField\.value : \'\';',
        r'const formCsrfToken = csrfTokenField ? csrfTokenField.value : \'\';',
        content
    )
    
    # 2. 替换tokenToUse的赋值
    content = re.sub(
        r'let tokenToUse = csrfToken;',
        r'let tokenToUse = formCsrfToken;',
        content
    )
    
    # 3. 修改getCsrfToken函数为getPageCsrfToken
    content = re.sub(
        r'function getCsrfToken\(\)',
        r'function getPageCsrfToken()',
        content
    )
    
    # 4. 修改函数调用
    content = re.sub(
        r'tokenToUse = getCsrfToken\(\);',
        r'tokenToUse = typeof window.getCsrfToken === \'function\' ? window.getCsrfToken() : getPageCsrfToken();',
        content
    )
    
    # 5. 修改内部变量引用
    content = re.sub(
        r'const csrfToken = getCsrfToken\(\);',
        r'const pageCsrfToken = getPageCsrfToken();',
        content
    )
    content = re.sub(
        r'if \(csrfToken\)',
        r'if (pageCsrfToken)',
        content
    )
    content = re.sub(
        r'options\.headers\[\'X-CSRF-TOKEN\'\] = csrfToken;',
        r'options.headers[\'X-CSRF-TOKEN\'] = pageCsrfToken;',
        content
    )
    
    # 写回文件
    with open(login_js_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"已修复: {login_js_path}")
    return True

# 检查并修复HTML模板中的脚本引用
def fix_html_templates():
    templates_fixed = 0
    templates_dir = os.path.join(BASE_DIR, 'app', 'templates')
    
    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.html'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 检查是否包含CSRF.js和login.js
                has_csrf_js = 'csrf.js' in content
                has_login_js = 'login.js' in content
                
                if has_csrf_js and has_login_js:
                    # 确保CSRF.js在login.js之前加载
                    if content.find('csrf.js') > content.find('login.js'):
                        # 备份文件
                        backup_dir = create_backup_dir()
                        backup_file(file_path, backup_dir)
                        
                        # 修改脚本加载顺序
                        modified = re.sub(
                            r'(<script[^>]*src=[^>]*login\.js[^>]*></script>).*?(<script[^>]*src=[^>]*csrf\.js[^>]*></script>)',
                            r'\2\n\1',
                            content,
                            flags=re.DOTALL
                        )
                        
                        # 更新version参数以避免缓存
                        modified = re.sub(
                            r'(login\.js\?v=)(\d+\.\d+\.\d+)',
                            lambda m: f"{m.group(1)}{float(m.group(2)) + 0.1:.1f}",
                            modified
                        )
                        
                        # 写回文件
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(modified)
                        
                        print(f"已修复脚本顺序: {file_path}")
                        templates_fixed += 1
    
    print(f"共修复 {templates_fixed} 个HTML模板")
    return templates_fixed > 0

# 主程序
def main():
    print("开始修复JavaScript变量冲突...")
    
    # 修复CSRF.js
    if fix_csrf_js():
        print("CSRF.js修复成功")
    else:
        print("CSRF.js修复失败")
    
    # 修复login.js
    if fix_login_js():
        print("Login.js修复成功")
    else:
        print("Login.js修复失败")
    
    # 修复HTML模板
    if fix_html_templates():
        print("HTML模板修复成功")
    else:
        print("没有HTML模板需要修复")
    
    print("JavaScript变量冲突修复完成")

if __name__ == "__main__":
    main() 