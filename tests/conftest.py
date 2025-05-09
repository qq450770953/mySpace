import pytest
from app import create_app
from app.models import db

@pytest.fixture(scope='session')
def app():
    app = create_app('testing')
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'JWT_SECRET_KEY': 'test-secret-key',
        'JWT_ACCESS_TOKEN_EXPIRES': 3600
    })
    return app

@pytest.fixture(scope='session')
def client(app):
    return app.test_client()

@pytest.fixture(scope='session')
def runner(app):
    return app.test_cli_runner()

@pytest.fixture(autouse=True)
def _setup_app_context_for_test(app):
    with app.app_context():
        yield 