from app.models import User, Project, Task, Resource, Risk, TeamMember, Role, ProjectMember
from app.extensions import db
from datetime import datetime, timedelta
import random
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)

def clear_database():
    """Clear all data from the database"""
    try:
        # 获取所有表名
        tables = db.session.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='table' 
            AND name NOT LIKE 'sqlite_%'
            AND name NOT LIKE 'alembic_%'
        """)).fetchall()
        
        # 按依赖关系排序删除表
        for table in tables:
            table_name = table[0]
            try:
                logger.info(f"Clearing table {table_name}")
                db.session.execute(text(f'DELETE FROM {table_name}'))
            except Exception as e:
                logger.error(f"Error clearing table {table_name}: {str(e)}")
                db.session.rollback()
                continue
        
        db.session.commit()
        logger.info("Database cleared successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing database: {str(e)}")
        raise

def create_test_data(clear_db=False):
    """创建测试数据
    
    Args:
        clear_db (bool): 是否在创建测试数据前清空数据库，默认为 False
    """
    try:
        # 只有在明确要求时才清空数据库
        if clear_db:
            logger.info("Clearing database before creating test data")
            clear_database()
        else:
            # Clear only user_roles to avoid integrity errors
            try:
                logger.info("Clearing user_roles table")
                db.session.execute(text('DELETE FROM user_roles'))
                db.session.commit()
            except Exception as e:
                logger.error(f"Error clearing user_roles: {str(e)}")
                db.session.rollback()
        
        # 创建角色
        logger.info("Creating roles...")
        roles = {}
        role_names = ['admin', 'manager', 'developer', 'tester', 'user']
        role_descriptions = {
            'admin': '管理员',
            'manager': '项目经理',
            'developer': '开发人员',
            'tester': '测试人员',
            'user': '普通用户'
        }
        
        for name in role_names:
            try:
                role = Role(name=name, description=role_descriptions[name])
                db.session.add(role)
                roles[name] = role
                db.session.commit()
                logger.info(f"Created role: {name}")
            except IntegrityError:
                logger.warning(f"Role {name} already exists, skipping")
                db.session.rollback()
                # Try to get existing role
                role = Role.query.filter_by(name=name).first()
                if role:
                    roles[name] = role
            except Exception as e:
                logger.error(f"Error creating role {name}: {str(e)}")
                db.session.rollback()
                continue

        # 创建测试用户
        logger.info("Creating test users...")
        users = []
        
        # 创建管理员用户
        try:
            admin = User(
                username='admin',
                email='admin@example.com',
                name='管理员'
            )
            admin.set_password('admin123')
            admin.roles = [roles['admin']]
            users.append(admin)
            db.session.add(admin)
            db.session.commit()
            logger.info("Created admin user")
        except IntegrityError:
            logger.warning("Admin user already exists, skipping")
            db.session.rollback()
            admin = User.query.filter_by(username='admin').first()
            if admin:
                users.append(admin)
        
        # 创建系统用户
        try:
            system = User(
                username='system',
                email='system@example.com',
                name='系统用户'
            )
            system.set_password('system123')
            system.roles = [roles['admin']]
            users.append(system)
            db.session.add(system)
            db.session.commit()
            logger.info("Created system user")
        except IntegrityError:
            logger.warning("System user already exists, skipping")
            db.session.rollback()
            system = User.query.filter_by(username='system').first()
            if system:
                users.append(system)
        
        # 创建项目经理用户
        try:
            manager = User(
                username='manager',
                email='manager@example.com',
                name='项目经理'
            )
            manager.set_password('manager123')
            manager.roles = [roles['manager']]
            users.append(manager)
            db.session.add(manager)
            db.session.commit()
            logger.info("Created manager user")
        except IntegrityError:
            logger.warning("Manager user already exists, skipping")
            db.session.rollback()
            manager = User.query.filter_by(username='manager').first()
            if manager:
                users.append(manager)
        
        # 创建测试用户
        try:
            test_user = User(
                username='test',
                email='test@example.com',
                name='测试用户'
            )
            test_user.set_password('test123')
            test_user.roles = [roles['user']]
            users.append(test_user)
            db.session.add(test_user)
            db.session.commit()
            logger.info("Created test user")
        except IntegrityError:
            logger.warning("Test user already exists, skipping")
            db.session.rollback()
            test_user = User.query.filter_by(username='test').first()
            if test_user:
                users.append(test_user)
        
        # 创建其他测试用户
        for i in range(3):
            try:
                user = User(
                    username=f'test_user_{i+1}',
                    email=f'test_user_{i+1}@example.com',
                    name=f'测试用户 {i+1}'
                )
                user.set_password('test123')
                user.roles = [random.choice([roles['developer'], roles['tester']])]
                users.append(user)
                db.session.add(user)
                db.session.commit()
                logger.info(f"Created test user {i+1}")
            except IntegrityError:
                logger.warning(f"Test user {i+1} already exists, skipping")
                db.session.rollback()
                user = User.query.filter_by(username=f'test_user_{i+1}').first()
                if user:
                    users.append(user)
            except Exception as e:
                logger.error(f"Error creating test user {i+1}: {str(e)}")
                continue
        
        # 创建测试项目
        logger.info("Creating test projects...")
        projects = []
        for i in range(3):
            try:
                project = Project(
                    name=f'测试项目 {i+1}',
                    description=f'这是第 {i+1} 个测试项目',
                    start_date=datetime.now(),
                    end_date=datetime.now() + timedelta(days=30),
                    status=random.choice(['未开始', '进行中', '已完成']),
                    owner_id=admin.id
                )
                projects.append(project)
                db.session.add(project)
                db.session.commit()
                logger.info(f"Created test project {i+1}")
            except Exception as e:
                logger.error(f"Error creating test project {i+1}: {str(e)}")
                db.session.rollback()
                continue

        # 为每个项目分配项目经理
        logger.info("Assigning project managers...")
        for project in projects:
            try:
                manager = random.choice([u for u in users if 'manager' in [r.name for r in u.roles]])
                project_member = ProjectMember(
                    project_id=project.id,
                    user_id=manager.id,
                    role='project_manager'
                )
                db.session.add(project_member)
                db.session.commit()
                logger.info(f"Assigned manager to project {project.id}")
            except Exception as e:
                logger.error(f"Error assigning manager to project {project.id}: {str(e)}")
                db.session.rollback()
                continue

        # 创建测试任务
        logger.info("Creating test tasks...")
        for project in projects:
            for i in range(5):
                try:
                    creator = random.choice(users)
                    task = Task(
                        title=f'测试任务 {i+1}',
                        description=f'这是第 {i+1} 个测试任务',
                        due_date=datetime.now() + timedelta(days=7),
                        status=random.choice(['未开始', '进行中', '已完成']),
                        priority=random.choice(['低', '中', '高']),
                        project_id=project.id,
                        assignee_id=random.choice([u.id for u in users if any(r.name in ['developer', 'tester'] for r in u.roles)]),
                        created_by=creator.id
                    )
                    db.session.add(task)
                    db.session.commit()
                    logger.info(f"Created test task {i+1} for project {project.id}")
                except Exception as e:
                    logger.error(f"Error creating test task {i+1} for project {project.id}: {str(e)}")
                    db.session.rollback()
                    continue

        # 创建测试资源
        logger.info("Creating test resources...")
        for i in range(10):
            try:
                resource = Resource(
                    name=f'测试资源 {i+1}',
                    type=random.choice(['人力', '设备', '材料']),
                    capacity=random.randint(1, 10),
                    description=f'这是第 {i+1} 个测试资源'
                )
                db.session.add(resource)
                db.session.commit()
                logger.info(f"Created test resource {i+1}")
            except Exception as e:
                logger.error(f"Error creating test resource {i+1}: {str(e)}")
                db.session.rollback()
                continue
                
        logger.info("Test data creation completed successfully")
        
    except Exception as e:
        logger.error(f"Error creating test data: {str(e)}")
        db.session.rollback()
        raise 