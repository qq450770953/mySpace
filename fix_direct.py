# -*- coding: utf-8 -*-

# 打开文件替换有问题的代码部分
with open('app/routes/projects_backup_full.py', 'r', encoding='utf-8', errors='replace') as file:
    content = file.read()

# 查找并替换问题代码段
problem_code = '''@project_bp.route('/<int:project_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_PROJECT)
def update_project(project_id):
    #"""更新项目信息"""
    
    try:'''

fixed_code = '''@project_bp.route('/<int:project_id>', methods=['PUT'])
@jwt_required()
@permission_required(PERMISSION_MANAGE_PROJECT)
def update_project(project_id):
    """更新项目信息"""
    try:'''

# 替换代码
new_content = content.replace(problem_code, fixed_code)

# 查找并替换字符串问题
new_content = new_content.replace("'项目名称已存?}", "'项目名称已存在'}")
new_content = new_content.replace("'指定的负责人不存?}", "'指定的负责人不存在'}")
new_content = new_content.replace("'无效的状态?}", "'无效的状态值'}")
new_content = new_content.replace("'用户不存?}", "'用户不存在'}")
new_content = new_content.replace("'项目不存?}", "'项目不存在'}")
new_content = new_content.replace("'项目不存?,", "'项目不存在',")
new_content = new_content.replace("'error': '无效的请求数?,", "'error': '无效的请求数据',")

# 写回文件
with open('app/routes/projects_backup_full.py', 'w', encoding='utf-8') as file:
    file.write(new_content)

print("修复完成: 已解决语法问题") 