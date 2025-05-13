#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
此脚本通过直接编辑文件的特定行，修复projects.py中的编码问题
"""

def fix_specific_line():
    file_path = 'app/routes/projects.py'
    
    # 读取所有行
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 替换有问题的行
    for i in range(len(lines)):
        # 查找包含"API版本："的行进行特殊处理
        if '"""API版本：' in lines[i]:
            lines[i] = '    """API版本: 获取项目详情数据"""\n'
            print(f"已修复行 {i+1}: {lines[i].strip()}")
    
    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"已完成文件修复: {file_path}")
    return True

if __name__ == "__main__":
    fix_specific_line() 