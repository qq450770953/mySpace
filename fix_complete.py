#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
完整修复projects.py文件的脚本，处理所有编码问题和移除Redirect相关代码
"""

import re
import shutil
import os

def fix_projects_file():
    source_file = 'app/routes/projects.py'
    backup_file = 'app/routes/projects_backup_full.py'
    
    # 创建备份
    shutil.copy2(source_file, backup_file)
    print(f"已创建备份: {backup_file}")
    
    # 读取文件内容
    with open(source_file, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 1. 删除对不存在的Redirect类的导入
    content = re.sub(r'from\s+werkzeug\.exceptions\s+import\s+Redirect', '', content)
    
    # 2. 删除Redirect错误处理器
    content = re.sub(r'@project_bp\.errorhandler\(Redirect\)[\s\S]*?return render_template\(.*?重定向循环.*?\), 500', '', content)
    
    # 3. 删除提及Redirect的注释行
    content = re.sub(r'# 使用能够正确处理重定向的异常.*?\n', '', content)
    
    # 4. 替换所有中文后面的特殊字符，使用普通的中文
    content = content.replace("令牌，请刷新页面后重�?", "令牌，请刷新页面后重试")
    content = content.replace("管理者ID必须是整�?", "管理者ID必须是整数")
    content = content.replace("没有权限访问此项�?", "没有权限访问此项目")
    content = content.replace("全局项目经理列表API被调�?", "全局项目经理列表API被调用")
    content = content.replace("使用默认用户列表 - 未找到活跃用�?", "使用默认用户列表 - 未找到活跃用户")
    content = content.replace("返回默认项目经理列�?", "返回默认项目经理列表")
    content = content.replace("管理�?", "管理员")
    content = content.replace("使用默认用户列表 - 数据库查询失�?", "使用默认用户列表 - 数据库查询失败")
    content = content.replace("开发主�?", "开发主管")
    content = content.replace("返回 {len(project_managers)} 个可选的项目负责�?", "返回 {len(project_managers)} 个可选的项目负责人")
    content = content.replace("内部服务器错�?", "内部服务器错误")
    content = content.replace("未分�?", "未分配")
    
    # 5. 修复所有有问题的docstrings
    content = content.replace('"""API版本：获取项目详情数�?"""', '"""API版本: 获取项目详情数据"""')
    content = content.replace('"""获取所有用户作为可选项目经�?', '"""获取所有用户作为可选项目经理')
    content = content.replace('"""处理内部服务器错�?"""', '"""处理内部服务器错误"""')
    content = content.replace('"""创建新项�?"""', '"""创建新项目"""')
    content = content.replace('"""导入权限相关的工�?"""', '"""导入权限相关的工具"""')
    content = content.replace('"""准备甘特图数�?"""', '"""准备甘特图数据"""')
    content = content.replace('"""使用正确的日期字�?"""', '"""使用正确的日期字符串"""')
    content = content.replace('"""支持多状态过�?"""', '"""支持多状态过滤"""')
    content = content.replace('"""搜索标题和描�?"""', '"""搜索标题和描述"""')
    content = content.replace('"""限制每页最大数�?"""', '"""限制每页最大数量"""')
    content = content.replace('"""预加载关联数�?"""', '"""预加载关联数据"""')
    content = content.replace('"""格式化项目数�?"""', '"""格式化项目数据"""')
    
    # 写入修改后的内容
    with open(source_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # 第二轮修复 - 处理任何遗漏的问题
    with open(source_file, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    
    # 处理每一行
    for i, line in enumerate(lines):
        # 检查特殊字符
        if '\ufffd' in line:
            # 移除Unicode替换字符
            lines[i] = line.replace('\ufffd', '')
        
        # 修复使用中文冒号的地方
        if '：' in line:
            lines[i] = line.replace('：', ':')
    
    # 写回文件
    with open(source_file, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"已完成文件修复: {source_file}")
    print("1. 已删除Redirect相关代码")
    print("2. 已修复所有编码问题")
    
    return True

if __name__ == "__main__":
    fix_projects_file() 