import click
from flask.cli import with_appcontext, AppGroup
from app.extensions import db
from app.models.auth import User, Role, Permission
from app.models.task import Project, Task
from app.models.resource import Resource
from app.models.risk import Risk
from datetime import datetime, timedelta
import random
from app.seed_data import create_test_data
from app.utils.permissions import init_roles_permissions
import logging

# 创建命令组
admin_cli = AppGroup('admin')
dev_cli = AppGroup('dev')
test_cli = AppGroup('test')

logger = logging.getLogger(__name__)

@click.command('init-db')
@with_appcontext
def init_db_command():
    """初始化数据库"""
    try:
        db.create_all()
        click.echo('数据库已初始化。')
    except Exception as e:
        click.echo(f'数据库初始化失败: {str(e)}')
        raise

@click.command('seed-db')
@with_appcontext
def seed_db():
    """创建测试数据"""
    try:
        create_test_data(clear_db=False)
        click.echo('测试数据创建完成。')
    except Exception as e:
        click.echo(f'测试数据创建失败: {str(e)}')
        raise

@click.command('reset-db')
@with_appcontext
def reset_db():
    """清空数据库并重新创建测试数据"""
    try:
        create_test_data(clear_db=True)
        click.echo('数据库已重置，测试数据创建完成。')
    except Exception as e:
        click.echo(f'数据库重置失败: {str(e)}')
        raise

@click.command('create-test-data')
@with_appcontext
def create_test_data_command():
    """Create test data in the database."""
    try:
        click.echo('Creating test data...')
        create_test_data(clear_db=True)
        click.echo('Test data created successfully!')
    except Exception as e:
        click.echo(f'Test data creation failed: {str(e)}')
        raise

@click.command('download-static')
@with_appcontext
def download_static_command():
    """Download required static files"""
    from app.utils.download_static import setup_static_files
    setup_static_files()
    click.echo('Static files downloaded successfully!')

def register_commands(app):
    """注册命令"""
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_db)
    app.cli.add_command(reset_db)
    app.cli.add_command(create_test_data_command)
    app.cli.add_command(download_static_command)
    app.cli.add_command(admin_cli)
    app.cli.add_command(dev_cli)
    app.cli.add_command(test_cli)

@admin_cli.command('create-admin')
@click.argument('username')
@click.argument('email')
@click.argument('password')
def create_admin(username, email, password):
    """创建新的管理员用户"""
    try:
        from app.models.auth import User, Role
        
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            click.echo('Admin role not found. Creating...')
            admin_role = Role(name='admin', description='Administrator')
            db.session.add(admin_role)
            db.session.commit()
        
        user = User(username=username, email=email)
        user.set_password(password)
        user.roles = [admin_role]
        
        db.session.add(user)
        db.session.commit()
        
        click.echo(f'Admin user {username} created successfully.')
    except Exception as e:
        db.session.rollback()
        click.echo(f'Error: {str(e)}')

@admin_cli.command('init-permissions')
def initialize_permissions():
    """重新初始化所有角色和权限"""
    try:
        # 初始化角色和权限
        success = init_roles_permissions()
        
        if success:
            # 遍历所有用户，确保他们的角色是正确的
            for user in User.query.all():
                if user.roles:
                    role_names = [role.name for role in user.roles]
                    click.echo(f"用户 {user.username} 当前角色: {', '.join(role_names)}")
                    
                    # 确保角色存在且权限正确
                    updated_roles = []
                    for role_name in role_names:
                        role = Role.query.filter_by(name=role_name).first()
                        if role:
                            updated_roles.append(role)
                        else:
                            click.echo(f"角色 {role_name} 不存在，将被忽略")
                    
                    if updated_roles:
                        user.roles = updated_roles
                    else:
                        # 如果所有角色都无效，默认为普通用户
                        default_role = Role.query.filter_by(name='user').first()
                        if default_role:
                            user.roles = [default_role]
                            click.echo(f"用户 {user.username} 被重置为普通用户角色")
                else:
                    # 没有角色的用户设置为普通用户
                    default_role = Role.query.filter_by(name='user').first()
                    if default_role:
                        user.roles = [default_role]
                        click.echo(f"用户 {user.username} 被设置为普通用户角色")
            
            db.session.commit()
            click.echo("所有角色和权限初始化成功，用户角色已更新")
        else:
            click.echo("角色和权限初始化失败")
        
    except Exception as e:
        db.session.rollback()
        click.echo(f'错误: {str(e)}')

@dev_cli.command('reset-db')
def reset_db():
    """重置数据库（删除所有表并重新创建）"""
    try:
        from sqlalchemy import create_engine, inspect, MetaData
        from app import db
        from flask import current_app
        
        click.echo('删除所有表...')
        db.drop_all()
        db.create_all()
        
        click.echo('数据库已重置')
    except Exception as e:
        click.echo(f'错误: {str(e)}')

@dev_cli.command('seed-db')
@click.option('--clear/--no-clear', default=False, help='清空数据库后再创建测试数据')
def seed_db(clear):
    """创建测试数据"""
    try:
        from app.seed_data import create_test_data
        
        click.echo('创建测试数据...')
        create_test_data(clear_db=clear)
        
        click.echo('测试数据创建成功')
    except Exception as e:
        click.echo(f'错误: {str(e)}')

@test_cli.command('run-tests')
def run_tests():
    """运行单元测试"""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner().run(tests) 