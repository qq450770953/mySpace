import pytest
from app.models import db, User, Task, Project

@pytest.fixture
def user(app):
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password='testpass'
        )
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def project(app, user):
    with app.app_context():
        project = Project(
            title='Test Project',
            description='Test Description',
            created_by=user.id
        )
        db.session.add(project)
        db.session.commit()
        return project

@pytest.fixture
def task(app, user, project):
    with app.app_context():
        task = Task(
            title='Test Task',
            description='Test Description',
            status='pending',
            priority='medium',
            project_id=project.id,
            assignee_id=user.id,
            created_by=user.id
        )
        db.session.add(task)
        db.session.commit()
        return task

def test_user_creation(user):
    assert user.username == 'testuser'
    assert user.email == 'test@example.com'
    assert user.check_password('testpass')

def test_project_creation(project, user):
    assert project.title == 'Test Project'
    assert project.description == 'Test Description'
    assert project.created_by == user.id

def test_task_creation(task, user, project):
    assert task.title == 'Test Task'
    assert task.status == 'pending'
    assert task.priority == 'medium'
    assert task.project_id == project.id
    assert task.assignee_id == user.id
    assert task.created_by == user.id 