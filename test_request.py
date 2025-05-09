import requests
import traceback

try:
    response = requests.get('http://localhost:5000/main/projects?bypass_jwt=true')
    print(f"Status code: {response.status_code}")
    print(f"Response: {response.text[:500]}...")
except Exception as e:
    print(f"Error: {str(e)}")
    print(traceback.format_exc()) 