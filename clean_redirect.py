try:
    # 尝试使用UTF-8编码
    with open('app/routes/projects.py', 'r', encoding='utf-8') as f:
        lines = f.readlines()
except UnicodeDecodeError:
    # 如果失败，尝试使用GBK或其他编码
    with open('app/routes/projects.py', 'r', encoding='gbk') as f:
        lines = f.readlines()

cleaned_lines = []
skip_mode = False

for line in lines:
    if '@project_bp.errorhandler(Redirect)' in line:
        skip_mode = True
        continue
    
    if skip_mode and not line.strip():
        skip_mode = False
    
    if not skip_mode and 'from werkzeug.exceptions import Redirect' not in line:
        cleaned_lines.append(line)

try:
    # 尝试使用UTF-8编码
    with open('app/routes/projects.py', 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)
except:
    # 如果失败，尝试使用GBK或其他编码
    with open('app/routes/projects.py', 'w', encoding='gbk') as f:
        f.writelines(cleaned_lines)

print("文件已清理完成") 