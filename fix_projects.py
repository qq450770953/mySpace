#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
此脚本用于修复projects.py文件中的两个问题：
1. 修复未终止的字符串（编码问题）
2. 删除对不存在的Redirect类的导入和相关的错误处理器
"""

import os
import re
import shutil

def fix_projects_file():
    source_file = 'app/routes/projects.py'
    backup_file = 'app/routes/projects_backup.py'
    
    # 创建备份
    shutil.copy2(source_file, backup_file)
    print(f"已创建备份: {backup_file}")
    
    # 读取文件内容，指定使用UTF-8编码
    with open(source_file, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 修复问题1: 修复未终止的字符串
    content = content.replace("'可能缺少必要的CSRF令牌，请刷新页面后重�?", 
                            "'可能缺少必要的CSRF令牌，请刷新页面后重试'")
    
    content = content.replace("'管理者ID必须是整�?", "'管理者ID必须是整数'")
    content = content.replace("'没有权限访问此项�?", "'没有权限访问此项目'")
    content = content.replace("'记录API调�?", "'记录API调用'")
    content = content.replace("'未找到活跃用户，返回默认项目经理列�?", 
                            "'未找到活跃用户，返回默认项目经理列表'")
    content = content.replace("'使用默认用户列表 - 未找到活跃用�?", 
                            "'使用默认用户列表 - 未找到活跃用户'")
    content = content.replace("'管理�?(默认)'", "'管理员(默认)'")
    content = content.replace("'项目经理 (默认)'", "'项目经理(默认)'")
    content = content.replace("'开发主�?(默认)'", "'开发主管(默认)'")
    content = content.replace("'使用默认用户列表 - 数据库查询失�?", 
                            "'使用默认用户列表 - 数据库查询失败'")
    content = content.replace("'返回 {len(project_managers)} 个可选的项目负责�?", 
                            "'返回 {len(project_managers)} 个可选的项目负责人'")
    content = content.replace("'管理�?(出错后备选项)'", "'管理员(出错后备选项)'")
    content = content.replace("'内部服务器错�?", "'内部服务器错误'")
    content = content.replace("'重定向循环问�?", "'重定向循环问题'")
    content = content.replace("'重定向循环处�?", "'重定向循环处理:'")
    content = content.replace("'未分�?", "'未分配'")
    content = content.replace("'返回友好的错误页�?", "'返回友好的错误页面'")
    content = content.replace("'创建新项�?", "'创建新项目'")
    content = content.replace("'导入权限相关的工�?", "'导入权限相关的工具'")
    content = content.replace("'准备甘特图数�?", "'准备甘特图数据'")
    content = content.replace("'使用正确的日期字�?", "'使用正确的日期字符串'")
    content = content.replace("'支持多状态过�?", "'支持多状态过滤'")
    content = content.replace("'搜索标题和描�?", "'搜索标题和描述'")
    content = content.replace("'限制每页最大数�?", "'限制每页最大数量'")
    content = content.replace("'预加载关联数�?", "'预加载关联数据'")
    content = content.replace("'格式化项目数�?", "'格式化项目数据'")
    content = content.replace("'API版本：获取项目详情数?", "'API版本：获取项目详情数据'")
    content = content.replace("assignee_name = assignee.name if assignee else \"未分?", "assignee_name = assignee.name if assignee else \"未分配\"")
    content = content.replace("assignee_name = assignee.name if assignee else '未分?", "assignee_name = assignee.name if assignee else '未分配'")
    
    # 修复API版本的docstring问题
    content = re.sub(r'"""API版本：获取项目详情数.*?"""', '"""API版本: 获取项目详情数据"""', content)
    
    # 修复问题2: 删除对不存在的Redirect类的导入和相关错误处理器
    # 删除导入行
    content = re.sub(r'from werkzeug\.exceptions import Redirect\s+', '', content)
    
    # 删除错误处理器
    pattern = r'@project_bp\.errorhandler\(Redirect\)[\s\S]*?return render_template\(\'error\.html\', error=\'页面加载失败，可能存在重定向循环\'\), 500\s*'
    content = re.sub(pattern, '', content)
    
    # 删除提及Redirect的注释行
    content = re.sub(r'# 使用能够正确处理重定向的异常.*?\n', '', content)
    
    # 写入修改后的内容
    with open(source_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"已修复文件: {source_file}")
    print("1. 已修复未终止的字符串")
    print("2. 已删除Redirect相关的代码")
    
    return True

if __name__ == "__main__":
    fix_projects_file() 