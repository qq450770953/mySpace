import requests
import json

try:
    response = requests.get('http://localhost:5000/simple/projects')
    print(f"Status code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        # Pretty print the JSON response
        print(json.dumps(data, indent=2))
    else:
        print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {str(e)}") 