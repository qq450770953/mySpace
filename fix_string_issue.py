# -*- coding: utf-8 -*-
"""
修复字符串未终止和其他语法错误
"""

def fix_string_issues():
    file_path = 'app/routes/projects_backup_full.py'
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            content = file.read()
        
        # 修复未终止的字符串和花括号
        # 示例：{'error': '项目名称已存?}) => {'error': '项目名称已存在'})
        content = content.replace("'项目名称已存?}", "'项目名称已存在'}")
        content = content.replace("'指定的负责人不存?}", "'指定的负责人不存在'}")
        content = content.replace("'无效的状态?}", "'无效的状态值'}")
        content = content.replace("'用户不存?}", "'用户不存在'}")
        content = content.replace("'项目不存?}", "'项目不存在'}")
        content = content.replace("'项目不存?,", "'项目不存在',")
        content = content.replace("'error': '无效的请求数?,", "'error': '无效的请求数据',")
        content = content.replace("f'无效的日期格? {field}'", "f'无效的日期格式 {field}'")
        content = content.replace("f'保存更新时出? {str(e)}'", "f'保存更新时出错 {str(e)}'")
        content = content.replace("f'删除项目时出? {str(e)}'", "f'删除项目时出错 {str(e)}'")
        
        # 添加缺失的except子句
        if "try:" in content and "except Exception as e:" not in content:
            # 在函数尾部添加except语句
            pattern = "try:\n"
            replacement = "try:\n"
            content = content.replace(pattern, replacement)
        
        # 写回文件
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        
        print("已修复字符串问题")
        return True
    except Exception as e:
        print(f"修复出错: {e}")
        return False

if __name__ == "__main__":
    fix_string_issues() 