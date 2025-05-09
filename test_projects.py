import requests
import json
import traceback

try:
    print("Sending request to projects endpoint with bypass_jwt=true...")
    response = requests.get('http://localhost:5000/main/projects?bypass_jwt=true')
    print(f"Status code: {response.status_code}")
    
    if response.status_code == 200:
        print("Successful response!")
        print("HTML response received - checking for error indicators...")
        
        # Check for error indicators in HTML
        error_indicators = ["错误", "Internal Server Error", "500"]
        found_errors = []
        for indicator in error_indicators:
            if indicator in response.text:
                found_errors.append(indicator)
        
        if found_errors:
            print(f"Found error indicators in response: {', '.join(found_errors)}")
        else:
            print("No error indicators found in the HTML response.")
    else:
        print(f"Error status code: {response.status_code}")
        print(f"Response content: {response.text[:500]}...")
except Exception as e:
    print(f"Request error: {str(e)}")
    print(traceback.format_exc()) 