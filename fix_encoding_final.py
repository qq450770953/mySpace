# -*- coding: utf-8 -*-
"""
全面修复Python文件中的编码和语法问题的最终解决方案
"""

def fix_python_file():
    file_path = 'app/routes/projects_backup_full.py'
    try:
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()
        
        # 检查并添加编码声明
        if not content.startswith('# -*- coding: utf-8 -*-'):
            content = '# -*- coding: utf-8 -*-\n' + content
        
        # 修复常见的语法错误 - 在文档字符串后添加换行符
        content = content.replace('def update_project(project_id):\n    """更新项目信息"""', 
                                 'def update_project(project_id):\n    """更新项目信息"""\n    ')
        
        content = content.replace('def get_project(project_id):\n    """获取单个项目详情"""', 
                                 'def get_project(project_id):\n    """获取单个项目详情"""\n    ')
        
        content = content.replace('def delete_project(project_id):\n    """删除项目"""', 
                                 'def delete_project(project_id):\n    """删除项目"""\n    ')
        
        content = content.replace('def get_project_members(project_id):\n    """获取项目成员列表"""', 
                                 'def get_project_members(project_id):\n    """获取项目成员列表"""\n    ')
        
        content = content.replace('def add_project_member(project_id):\n    """添加项目成员"""', 
                                 'def add_project_member(project_id):\n    """添加项目成员"""\n    ')
        
        content = content.replace('def remove_project_member(project_id, user_id):\n    """移除项目成员"""', 
                                 'def remove_project_member(project_id, user_id):\n    """移除项目成员"""\n    ')
        
        content = content.replace('def detail(project_id):\n    """渲染项目详情页面"""', 
                                 'def detail(project_id):\n    """渲染项目详情页面"""\n    ')
        
        content = content.replace('def detail_api(project_id):\n    """API版本: 获取项目详情数据"""', 
                                 'def detail_api(project_id):\n    """API版本: 获取项目详情数据"""\n    ')
        
        content = content.replace('def get_project_api(project_id):\n    """API端点: 获取单个项目详情"""', 
                                 'def get_project_api(project_id):\n    """API端点: 获取单个项目详情"""\n    ')
        
        content = content.replace('def update_project_api(project_id):\n    """API端点: 更新项目信息"""', 
                                 'def update_project_api(project_id):\n    """API端点: 更新项目信息"""\n    ')
        
        content = content.replace('def delete_project_api(project_id):\n    """API端点: 删除项目"""', 
                                 'def delete_project_api(project_id):\n    """API端点: 删除项目"""\n    ')
        
        content = content.replace('def get_projects_api():\n    """API端点: 获取项目列表"""', 
                                 'def get_projects_api():\n    """API端点: 获取项目列表"""\n    ')
        
        content = content.replace('def get_project_auth_api(project_id):\n    """API端点: 通过认证获取单个项目详情"""', 
                                 'def get_project_auth_api(project_id):\n    """API端点: 通过认证获取单个项目详情"""\n    ')
        
        content = content.replace('def get_project_noauth(project_id):\n    """无需认证的项目API端点 - 用于前端交互"""', 
                                 'def get_project_noauth(project_id):\n    """无需认证的项目API端点 - 用于前端交互"""\n    ')
        
        content = content.replace('def create_project_auth():\n    """创建项目的认证API端点"""', 
                                 'def create_project_auth():\n    """创建项目的认证API端点"""\n    ')
        
        content = content.replace('def get_project_managers():\n    """获取所有用户作为可选项目经理"""', 
                                 'def get_project_managers():\n    """获取所有用户作为可选项目经理"""\n    ')
        
        # 修复其他潜在问题 - 替换掉所有可能导致错误的特殊字符
        content = content.replace('�', '')
        
        # 写回文件
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        
        print(f"已完成对 {file_path} 的全面修复")
        return True
    except Exception as e:
        print(f"修复出错: {e}")
        return False

if __name__ == "__main__":
    fix_python_file() 