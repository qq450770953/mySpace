from app import create_app
from app.models.auth import User, Role, Permission
from app.utils.permissions import (
    ROLE_ADMIN, ROLE_PROJECT_MANAGER, ROLE_USER,
    PERMISSION_MANAGE_USERS, PERMISSION_MANAGE_PROJECT, PERMISSION_MANAGE_TASK,
    PERMISSION_MANAGE_RISKS, PERMISSION_MANAGE_RESOURCES, PERMISSION_VIEW_PROJECT,
    PERMISSION_VIEW_TASK
)

app = create_app()

def get_permissions_for_role(role_name):
    with app.app_context():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return f"Role '{role_name}' not found"
        
        permissions = [p.name for p in role.permissions]
        return permissions

def should_show_button(role_name, permission_required):
    with app.app_context():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return False
        
        # 检查角色是否有所需权限
        has_permission = False
        for permission in role.permissions:
            if permission.name == permission_required:
                has_permission = True
                break
        
        # 管理员特殊处理
        if role_name == ROLE_ADMIN:
            return True
        
        return has_permission

def print_button_visibility():
    roles = [ROLE_ADMIN, ROLE_PROJECT_MANAGER, ROLE_USER]
    buttons = [
        {"name": "新建用户按钮", "permission": PERMISSION_MANAGE_USERS},
        {"name": "编辑用户按钮", "permission": PERMISSION_MANAGE_USERS},
        {"name": "新建项目按钮", "permission": PERMISSION_MANAGE_PROJECT},
        {"name": "编辑项目按钮", "permission": PERMISSION_MANAGE_PROJECT},
        {"name": "新建任务按钮", "permission": PERMISSION_MANAGE_TASK},
        {"name": "编辑任务按钮", "permission": PERMISSION_MANAGE_TASK},
        {"name": "新建风险按钮", "permission": PERMISSION_MANAGE_RISKS},
        {"name": "编辑风险按钮", "permission": PERMISSION_MANAGE_RISKS},
        {"name": "新建资源按钮", "permission": PERMISSION_MANAGE_RESOURCES},
        {"name": "编辑资源按钮", "permission": PERMISSION_MANAGE_RESOURCES}
    ]
    
    print("-" * 80)
    print(f"{'按钮名称':<15} | {'管理员':<10} | {'项目经理':<10} | {'普通用户':<10}")
    print("-" * 80)
    
    for button in buttons:
        admin_visible = "✅" if should_show_button(ROLE_ADMIN, button["permission"]) else "❌"
        manager_visible = "✅" if should_show_button(ROLE_PROJECT_MANAGER, button["permission"]) else "❌"
        user_visible = "✅" if should_show_button(ROLE_USER, button["permission"]) else "❌"
        
        print(f"{button['name']:<15} | {admin_visible:<10} | {manager_visible:<10} | {user_visible:<10}")

if __name__ == "__main__":
    print("\n角色权限列表:")
    for role in [ROLE_ADMIN, ROLE_PROJECT_MANAGER, ROLE_USER]:
        permissions = get_permissions_for_role(role)
        print(f"\n{role} 权限:")
        for perm in permissions:
            print(f"  - {perm}")
    
    print("\n\n按钮可见性:")
    print_button_visibility() 