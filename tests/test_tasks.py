import pytest
from app import create_app
from app.models import db, Task, User
from datetime import datetime, timedelta

@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def test_user(app):
    with app.app_context():
        user = User(
            username='testuser',
            name='Test User',
            email='test@example.com',
            password='testpass'
        )
        db.session.add(user)
        db.session.commit()
        return user

@pytest.fixture
def test_task(app, test_user):
    with app.app_context():
        task = Task(
            title='Test Task',
            description='Test Description',
            status='pending',
            priority='medium',
            due_date=datetime.utcnow() + timedelta(days=7),
            assignee_id=test_user.id,
            created_by=test_user.id
        )
        db.session.add(task)
        db.session.commit()
        return task

def test_task_list(client, test_user, test_task):
    # 测试获取任务列表
    response = client.get('/tasks/list')
    assert response.status_code == 200
    data = response.get_json()
    assert 'tasks' in data
    assert len(data['tasks']) > 0
    assert data['tasks'][0]['title'] == 'Test Task'

def test_create_task(client, test_user):
    # 测试创建任务
    task_data = {
        'title': 'New Task',
        'description': 'New Description',
        'status': 'pending',
        'priority': 'high',
        'due_date': (datetime.utcnow() + timedelta(days=7)).isoformat(),
        'assignee_id': test_user.id
    }
    response = client.post('/tasks', json=task_data)
    assert response.status_code == 201
    data = response.get_json()
    assert data['title'] == 'New Task'
    assert data['status'] == 'pending'

def test_update_task(client, test_user, test_task):
    # 测试更新任务
    update_data = {
        'title': 'Updated Task',
        'status': 'in_progress',
        'priority': 'high'
    }
    response = client.put(f'/tasks/{test_task.id}', json=update_data)
    assert response.status_code == 200
    data = response.get_json()
    assert data['title'] == 'Updated Task'
    assert data['status'] == 'in_progress'

def test_delete_task(client, test_task):
    # 测试删除任务
    response = client.delete(f'/tasks/{test_task.id}')
    assert response.status_code == 204
    
    # 验证任务已被删除
    response = client.get(f'/tasks/{test_task.id}')
    assert response.status_code == 404

def test_task_validation(client, test_user):
    # 测试任务验证
    # 测试缺少必要字段
    task_data = {
        'description': 'Invalid Task',
        'status': 'pending'
    }
    response = client.post('/tasks', json=task_data)
    assert response.status_code == 400
    
    # 测试无效的状态值
    task_data = {
        'title': 'Invalid Status Task',
        'status': 'invalid_status',
        'priority': 'high'
    }
    response = client.post('/tasks', json=task_data)
    assert response.status_code == 400

def test_task_permissions(client, test_user, test_task):
    # 测试任务权限
    # 测试未授权访问
    response = client.get('/tasks/list')
    assert response.status_code == 401
    
    # 测试访问不存在的任务
    response = client.get('/tasks/99999')
    assert response.status_code == 404 