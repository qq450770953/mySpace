#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
这个脚本用于修复projects.py中的错误处理器问题
"""

def main():
    # 读取原始文件
    with open('app/routes/projects.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 找到错误处理器的位置
    start_line = -1
    end_line = -1
    for i, line in enumerate(lines):
        if '@project_bp.errorhandler(500)' in line:
            start_line = i
        elif start_line > 0 and i > start_line and '@project_bp.errorhandler(Redirect)' in line:
            # 找到Redirect错误处理器的开始
            for j in range(i, len(lines)):
                if 'def handle_redirect_loop' in lines[j]:
                    for k in range(j, len(lines)):
                        # 找到函数的结束
                        if k+1 < len(lines) and lines[k+1].strip() and not lines[k+1].startswith(' ') and not lines[k+1].startswith('\t'):
                            end_line = k
                            break
                    break
            break
    
    # 检查是否找到了错误处理器
    if start_line > 0 and end_line > start_line:
        print(f"找到错误处理器，从行 {start_line} 到行 {end_line}")
        
        # 删除Redirect导入行
        import_line = -1
        for i in range(start_line+1, end_line):
            if 'from werkzeug.exceptions import Redirect' in lines[i]:
                import_line = i
                break
        
        if import_line > 0:
            print(f"找到导入行: {import_line}")
            # 保留500错误处理器，删除其他
            with open('app/routes/projects_fixed.py', 'w', encoding='utf-8') as f:
                for i, line in enumerate(lines):
                    if i <= start_line+4:  # 保留500错误处理器
                        f.write(line)
                    elif i > end_line:  # 继续写后面的内容
                        f.write(line)
            
            print("已创建修复后的文件: app/routes/projects_fixed.py")
        else:
            print("未找到导入行")
    else:
        print("未找到错误处理器")

if __name__ == "__main__":
    main() 