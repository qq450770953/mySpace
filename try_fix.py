import re

def fix_projects_file():
    """修复projects.py文件"""
    with open('app/routes/projects.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 使用正则表达式删除错误部分
    pattern = r'from werkzeug\.exceptions import Redirect.*?@project_bp\.errorhandler\(Redirect\)[\s\S]*?重定向循环\), 500'
    fixed_content = re.sub(pattern, '', content, flags=re.DOTALL)
    
    with open('app/routes/projects_fixed.py', 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    print("已创建修复后的文件: app/routes/projects_fixed.py")
    return True

if __name__ == '__main__':
    fix_projects_file() 