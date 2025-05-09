import requests
import json
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_csrf_token():
    url = 'http://localhost:5000/auth/csrf-token?bypass_jwt=true'
    try:
        logger.info(f'Getting CSRF token from {url}')
        response = requests.get(url)
        response.raise_for_status()
        token_data = response.json()
        csrf_token = token_data.get('csrf_token')
        logger.info(f'Got CSRF token: {csrf_token}')
        return csrf_token
    except Exception as e:
        logger.error(f'Failed to get CSRF token: {str(e)}')
        return None

def test_register():
    # 获取CSRF令牌
    csrf_token = get_csrf_token()
    if not csrf_token:
        logger.error('Cannot proceed without CSRF token')
        return

    url = 'http://localhost:5000/register'
    data = {
        'username': 'testuser',
        'password': 'testpass',
        'email': 'test@example.com',
        'name': 'Test User',
        'csrf_token': csrf_token
    }
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-CSRF-TOKEN': csrf_token
    }
    
    try:
        logger.info(f'Sending request to {url} with data: {data}')
        response = requests.post(url, json=data, headers=headers)
        logger.info(f'Status Code: {response.status_code}')
        logger.info(f'Response Headers: {dict(response.headers)}')
        logger.info(f'Response: {response.text}')
        
        # 尝试解析JSON响应
        try:
            json_response = response.json()
            logger.info(f'JSON Response: {json_response}')
        except json.JSONDecodeError:
            logger.warning('Response is not JSON format')
            
        response.raise_for_status()
        logger.info('Registration successful')
        
    except requests.exceptions.RequestException as e:
        logger.error(f'Request failed: {str(e)}')
    except Exception as e:
        logger.error(f'Unexpected error: {str(e)}')

if __name__ == '__main__':
    test_register() 