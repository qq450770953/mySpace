from app import create_app
from app.utils.permissions import init_roles_permissions
from app.models.auth import User, Role, Permission
from app.extensions import db

app = create_app()

with app.app_context():
    # 初始化角色和权限
    success = init_roles_permissions()
    
    if success:
        print("角色和权限初始化成功")
        
        # 获取角色
        admin_role = Role.query.filter_by(name='admin').first()
        manager_role = Role.query.filter_by(name='manager').first()
        user_role = Role.query.filter_by(name='user').first()
        
        # 打印角色权限
        print("\n=== 角色及其权限 ===")
        
        if admin_role:
            admin_permissions = [p.name for p in admin_role.permissions]
            print(f"管理员权限: {', '.join(admin_permissions)}")
            
        if manager_role:
            manager_permissions = [p.name for p in manager_role.permissions]
            print(f"项目经理权限: {', '.join(manager_permissions)}")
            
        if user_role:
            user_permissions = [p.name for p in user_role.permissions]
            print(f"普通用户权限: {', '.join(user_permissions)}")
            
        # 确保所有用户都有角色
        users_without_roles = User.query.filter(~User.roles.any()).all()
        if users_without_roles:
            print(f"\n发现 {len(users_without_roles)} 个没有角色的用户，分配默认普通用户角色")
            for user in users_without_roles:
                user.roles.append(user_role)
            db.session.commit()
            print("已更新")
        
        # 输出管理员列表
        admins = User.query.join(User.roles).filter(Role.name == 'admin').all()
        if admins:
            print(f"\n管理员用户: {', '.join([u.username for u in admins])}")
            
        # 输出项目经理列表
        managers = User.query.join(User.roles).filter(Role.name == 'manager').all()
        if managers:
            print(f"项目经理用户: {', '.join([u.username for u in managers])}")
            
    else:
        print("角色和权限初始化失败") 