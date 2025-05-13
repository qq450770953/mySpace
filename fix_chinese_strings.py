#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
此脚本用于修复projects.py文件中的中文字符串编码问题，特别是未终止的字符串
"""

import os
import re
import shutil

def fix_chinese_strings():
    source_file = 'app/routes/projects.py'
    backup_file = 'app/routes/projects_fixed_encoding.py'
    
    # 创建备份
    shutil.copy2(source_file, backup_file)
    print(f"已创建备份: {backup_file}")
    
    # 读取文件内容
    with open(source_file, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 修复字符串问题
    replacements = [
        # CSRF错误处理
        (r"'可能缺少必要的CSRF令牌，请刷新页面后重�?", "'可能缺少必要的CSRF令牌，请刷新页面后重试'"),
        
        # 未终止的docstring
        (r'"""创建新项�?"', '"""创建新项目"""'),
        
        # 其他常见错误字符串
        (r"'管理者ID必须是整�?", "'管理者ID必须是整数'"),
        (r"'没有权限访问此项�?", "'没有权限访问此项目'"),
        (r"'项目名称已存�?", "'项目名称已存在'"),
        (r"'创建新项�?", "'创建新项目'"),
        (r"'更新了描�?", "'更新了描述'"),
        (r"'无效的状态�?", "'无效的状态值'"),
        (r"'无效的开始日期格�?", "'无效的开始日期格式'"),
        (r"'无效的结束日期格�?", "'无效的结束日期格式'"),
        (r"'指定的负责人不存�?", "'指定的负责人不存在'"),
        
        # 带有数据占位符的字符串
        (r'名称�?"(.*?)" 改为 "(.*?)"', r'名称从"\1" 改为 "\2"'),
        (r'负责人从 (.*?) 改为 (.*?)}', r'负责人从 \1 改为 \2'),
        
        # 任何带有�?的字符串(可能是未正确编码的中文字符)
        (r'�?', '？'),
        (r'�?', ''),
        (r'�?', ''),
        
        # 甘特图相关
        (r"# 准备甘特图数�?", "# 准备甘特图数据"),
        (r"# 使用正确的日期字�?", "# 使用正确的日期字符串"),
        
        # 注释中的问题
        (r"# 搜索标题和描�?", "# 搜索标题和描述"),
        (r"# 限制每页最大数�?", "# 限制每页最大数量"),
        
        # 权限检查
        (r"# 权限检�?", "# 权限检查"),
    ]
    
    # 执行所有替换
    for old, new in replacements:
        content = re.sub(old, new, content)
    
    # 写回文件
    with open(source_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"已修复文件: {source_file}")
    return True

if __name__ == "__main__":
    fix_chinese_strings() 