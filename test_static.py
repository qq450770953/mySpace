import requests
import json
import traceback

try:
    print("Sending request to static test endpoint...")
    response = requests.get('http://localhost:5000/static-test')
    print(f"Status code: {response.status_code}")
    print(f"Response headers: {response.headers}")
    
    # Print raw content
    print(f"Raw content: {response.content}")
    
    # Try to parse as JSON
    try:
        if response.content:
            data = response.json()
            print("JSON content:")
            print(json.dumps(data, indent=2))
        else:
            print("Empty response content")
    except json.JSONDecodeError as je:
        print(f"JSON decode error: {je}")
        print(f"Response text: {response.text}")
except Exception as e:
    print(f"Request error: {str(e)}")
    print(traceback.format_exc()) 