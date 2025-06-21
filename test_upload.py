import requests
import json

url = "http://localhost:8000/prepare/register-data"

headers = {
    "Authorization": "Bearer mock_token_patient_12345"
}

# Read the sample file
with open("sample-medical-report.txt", "rb") as f:
    file_content = f.read()

files = {
    "file": ("sample-medical-report.txt", file_content, "text/plain")
}

data = {
    "owner_public_key": "GA5HNMXP4XZL634C3DXKU6AM5WAJ6OKMOIKZ2R3SN22WZXRKCS2XA4MZ",
    "encrypted_key_for_owner": "dGVzdF9rZXk=",
    "metadata": '{"title":"Blood Test","data_type":"lab_result"}'
}

try:
    response = requests.post(url, headers=headers, files=files, data=data)
    print("Status Code:", response.status_code)
    print("Response:")
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))
    else:
        print(response.text)
except Exception as e:
    print(f"Error: {e}") 