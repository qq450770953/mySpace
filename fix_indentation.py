import re

def fix_indentation(filename, pattern, replacement):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    fixed_content = re.sub(pattern, replacement, content)
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    print(f"Fixed indentation in {filename}")

# Fix indentation issues in all affected files
fixes = [
    # Fix main.py tasks function
    {
        'filename': 'app/routes/main.py',
        'pattern': r'        else:\n        current_user = get_jwt_identity\(\)',
        'replacement': '        else:\n            current_user = get_jwt_identity()'
    },
    # Fix main.py tasks if not current_user
    {
        'filename': 'app/routes/main.py',
        'pattern': r'        current_user = get_jwt_identity\(\)\n        if not current_user:',
        'replacement': '            current_user = get_jwt_identity()\n            if not current_user:'
    },
    # Fix main.py risks return
    {
        'filename': 'app/routes/main.py',
        'pattern': r'    return render_template\(\'risks.html\'\)\n    except',
        'replacement': '        return render_template(\'risks.html\')\n    except'
    },
    # Fix main.py reports return
    {
        'filename': 'app/routes/main.py',
        'pattern': r'    return render_template\(\'reports.html\'\)\n    except',
        'replacement': '        return render_template(\'reports.html\')\n    except'
    },
    # Fix main.py resources return
    {
        'filename': 'app/routes/main.py',
        'pattern': r'    return render_template\(\'resources.html\'\)\n    except',
        'replacement': '        return render_template(\'resources.html\')\n    except'
    },
    # Fix projects.py
    {
        'filename': 'app/routes/projects.py',
        'pattern': r'        else:\n        current_user = get_jwt_identity\(\)',
        'replacement': '        else:\n            current_user = get_jwt_identity()'
    },
    # Fix risks.py get_risk
    {
        'filename': 'app/routes/risks.py',
        'pattern': r'        else:\n        current_user_id = get_jwt_identity\(\)',
        'replacement': '        else:\n            current_user_id = get_jwt_identity()'
    },
    # Fix risks.py update_risk
    {
        'filename': 'app/routes/risks.py',
        'pattern': r'        else:\n        current_user_id = get_jwt_identity\(\)',
        'replacement': '        else:\n            current_user_id = get_jwt_identity()'
    },
    # Fix risks.py delete_risk
    {
        'filename': 'app/routes/risks.py',
        'pattern': r'        else:\n        current_user_id = get_jwt_identity\(\)',
        'replacement': '        else:\n            current_user_id = get_jwt_identity()'
    },
    # Fix risks.py project risks
    {
        'filename': 'app/routes/risks.py',
        'pattern': r'        # 获取项目风险\n    risks = Risk.query.filter_by\(project_id=project_id\).all\(\)',
        'replacement': '        # 获取项目风险\n        risks = Risk.query.filter_by(project_id=project_id).all()'
    }
]

for fix in fixes:
    try:
        fix_indentation(fix['filename'], fix['pattern'], fix['replacement'])
    except Exception as e:
        print(f"Error fixing {fix['filename']}: {str(e)}") 