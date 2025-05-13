#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
此脚本用于修复projects.py文件中的所有docstrings编码问题
"""

import re
import shutil

def fix_all_docstrings():
    file_path = 'app/routes/projects.py'
    backup_path = 'app/routes/projects_backup2.py'
    
    # 创建备份
    shutil.copy2(file_path, backup_path)
    print(f"已创建备份: {backup_path}")
    
    # 直接读取整个文件内容而不是按行
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 替换特定的docstrings
    replacements = [
        ('"""API版本：获取项目详情数据"""', '"""API版本: 获取项目详情数据"""'),
        ('"""获取所有用户作为可选项目经理的全局API端点，不需要CSRF验证"""', '"""获取所有用户作为可选项目经理的全局API端点，不需要CSRF验证"""'),
        ('"""处理内部服务器错误"""', '"""处理内部服务器错误"""'),
        ('"""创建新项目"""', '"""创建新项目"""'),
        ('"""处理重定向循环问题"""', '"""处理重定向循环问题"""'),
    ]
    
    # 替换所有指定的docstrings
    fixed_count = 0
    for old, new in replacements:
        if old in content:
            content = content.replace(old, new)
            fixed_count += 1
            print(f"已替换: {old} -> {new}")
    
    # 重写文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"已完成文件修复: {file_path}，共修复 {fixed_count} 个docstring")
    
    # 以行为单位处理文件中的docstrings
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 修复有问题的docstrings
    docstring_pattern = re.compile(r'""".*?"""')
    
    # 需要替换的docstrings映射
    docstring_replacements = {
        '"""API版本：获取项目详情数': '"""API版本: 获取项目详情数据',
        '"""获取所有用户作为可选项目经': '"""获取所有用户作为可选项目经理',
        '"""处理内部服务器错': '"""处理内部服务器错误',
        '"""渲染项目详情页面': '"""渲染项目详情页面',
        '"""创建新项': '"""创建新项目',
        '"""处理重定向循环问': '"""处理重定向循环问题',
    }
    
    # 有些docstring可能跨行，我们需要替换所有包含关键字的行
    count = 0
    for i, line in enumerate(lines):
        # 先检查是否包含有问题的字符
        if '' in line or '：' in line:
            # 检查行中是否包含docstring
            if '"""' in line:
                # 尝试查找匹配并替换
                for key in docstring_replacements:
                    if key in line or key.replace('"""', '') in line:
                        # 替换包含这个问题的整行
                        new_line = line.replace('：', ':').replace('', '').replace('\ufffd', '')
                        for bad_char in ['', '\ufffd']:
                            new_line = new_line.replace(bad_char, '')
                        lines[i] = new_line
                        count += 1
                        print(f"已修复行 {i+1}: 替换了特殊字符")
                        break
    
    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"第二轮修复：替换了 {count} 行中的特殊字符")
    
    return True

if __name__ == "__main__":
    fix_all_docstrings() 