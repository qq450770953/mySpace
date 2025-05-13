#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
修复projects.py中第1238行的未终止字符串
"""

def fix_line_1238():
    file_path = 'app/routes/projects.py'
    
    # 读取所有行
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 修复特定行
    line_number = 1238 - 1  # 索引从0开始
    if line_number < len(lines):
        print(f"原始行 {line_number+1}:\n{lines[line_number]}")
        lines[line_number] = '        logger.info("获取项目经理列表API被调用")\n'
        print(f"修复后行 {line_number+1}:\n{lines[line_number]}")
    
    # 写回文件
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"已修复文件: {file_path}")
    return True

if __name__ == "__main__":
    fix_line_1238() 