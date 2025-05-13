# -*- coding: utf-8 -*-
"""
修复Python文件中的编码问题
"""

import re

# 需要修复的文件路径
file_path = 'app/routes/projects_backup_full.py'

# 需要修复的函数定义集合 - 添加换行符
docstring_patterns = [
    r'def\s+\w+\([^)]*\):\s*"""[^"]*"""',  # 匹配 def func(): """docstring"""
]

def fix_encoding():
    try:
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()

        # 在文件顶部添加编码声明（如果没有）
        if not content.startswith('# -*- coding'):
            content = '# -*- coding: utf-8 -*-\n' + content

        # 修复docstring问题，在docstring后添加换行符
        for pattern in docstring_patterns:
            def add_newline(match):
                return match.group(0) + '\n'
            
            content = re.sub(pattern, add_newline, content)

        # 写回文件
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
            
        print(f"已修复文件: {file_path}")
        return True
    except Exception as e:
        print(f"修复出错: {e}")
        return False

if __name__ == "__main__":
    fix_encoding() 