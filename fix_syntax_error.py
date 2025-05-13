# -*- coding: utf-8 -*-
"""
修复Python文件中的语法错误
"""
import re

def fix_syntax_errors():
    # 读取原始文件
    file_path = 'app/routes/projects_backup_full.py'
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            lines = file.readlines()
        
        # 在所有包含中文注释的函数定义后添加换行符
        pattern = re.compile(r'def\s+\w+\([^)]*\):\s*""".*"""')
        
        # 创建修复后的内容
        fixed_lines = []
        for line in lines:
            if pattern.search(line):
                # 如果是函数定义行包含文档字符串，确保文档字符串后有换行符
                if not line.rstrip().endswith('\n'):
                    fixed_lines.append(line.rstrip() + '\n')
                    # 添加额外的空行确保分隔
                    fixed_lines.append('\n')
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        
        # 写回文件
        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(fixed_lines)
        
        print(f"已修复文件 {file_path} 中的语法错误")
        return True
    except Exception as e:
        print(f"修复出错: {e}")
        return False

if __name__ == "__main__":
    fix_syntax_errors() 