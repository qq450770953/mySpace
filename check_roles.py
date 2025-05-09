from app import create_app
from app.models.auth import Role, Permission

app = create_app()
with app.app_context():
    roles = Role.query.all()
    
    print('Current roles and permissions:')
    for role in roles:
        print(f"Role: {role.name}")
        print(f"  Permissions: {[p.name for p in role.permissions]}")
        print("----------------------------") 