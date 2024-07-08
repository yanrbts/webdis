import requests
import json
import random
import string

def register():
    url = "http://127.0.0.1:7379/register"

    data = {
        "machine":"f526255265340d994510f8d1652e1eb12",
        "username":"13989701110",
        "flag":0
    }

    json_data = json.dumps(data)
    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        print('Response:', response.json())
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

if __name__ == "__main__":
    register()