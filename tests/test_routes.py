import pytest
from flask import url_for
from app.models import User, Task, Project

def test_login(client):
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_get_tasks(client, user, task):
    # Login first
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    token = response.json['access_token']
    
    # Get tasks
    response = client.get('/tasks/list', headers={
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['title'] == 'Test Task'

def test_create_task(client, user, project):
    # Login first
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    token = response.json['access_token']
    
    # Create task
    response = client.post('/tasks', json={
        'title': 'New Task',
        'description': 'New Description',
        'status': 'pending',
        'priority': 'high',
        'project_id': project.id
    }, headers={
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 201
    assert response.json['title'] == 'New Task'

def test_get_projects(client, user, project):
    # Login first
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    token = response.json['access_token']
    
    # Get projects
    response = client.get('/projects/list', headers={
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]['title'] == 'Test Project'

def test_create_project(client, user):
    # Login first
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpass'
    })
    token = response.json['access_token']
    
    # Create project
    response = client.post('/projects', json={
        'title': 'New Project',
        'description': 'New Description'
    }, headers={
        'Authorization': f'Bearer {token}'
    })
    assert response.status_code == 201
    assert response.json['title'] == 'New Project' 