import requests
import json
import traceback
import os

try:
    # 首先尝试从API获取数据
    print("Sending request to debug-projects endpoint...")
    headers = {'Accept': 'application/json'}
    response = requests.get('http://localhost:5000/main/debug-projects', headers=headers)
    print(f"Status code: {response.status_code}")
    
    if response.status_code == 200:
        try:
            data = response.json()
            print("JSON response received from API:")
            print(json.dumps(data, indent=2))
        except json.JSONDecodeError as je:
            print(f"JSON decode error: {je}")
            print(f"Response content: {response.text[:500]}...")
            
            # 如果API请求失败，尝试从本地文件读取
            print("\nFalling back to local JSON file...")
            if os.path.exists('projects.json'):
                with open('projects.json', 'r', encoding='utf-8') as f:
                    local_data = json.load(f)
                    print("JSON data loaded from local file:")
                    print(json.dumps(local_data, indent=2))
            else:
                print("Local projects.json file not found.")
    else:
        print(f"Error status code: {response.status_code}")
        print(f"Response content: {response.text[:500]}...")
        
        # 尝试从本地文件读取
        print("\nFalling back to local JSON file...")
        if os.path.exists('projects.json'):
            with open('projects.json', 'r', encoding='utf-8') as f:
                local_data = json.load(f)
                print("JSON data loaded from local file:")
                print(json.dumps(local_data, indent=2))
        else:
            print("Local projects.json file not found.")
except Exception as e:
    print(f"Request error: {str(e)}")
    print(traceback.format_exc())
    
    # 尝试从本地文件读取
    print("\nFalling back to local JSON file...")
    try:
        if os.path.exists('projects.json'):
            with open('projects.json', 'r', encoding='utf-8') as f:
                local_data = json.load(f)
                print("JSON data loaded from local file:")
                print(json.dumps(local_data, indent=2))
        else:
            print("Local projects.json file not found.")
    except Exception as file_error:
        print(f"Error reading local file: {str(file_error)}") 