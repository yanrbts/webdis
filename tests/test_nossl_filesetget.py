import requests
import json
import random
import string
import time
from datetime import datetime

def random_string(length):
    letters_and_digits = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def fileset(num):
    url = 'http://127.0.0.1:7379/fileset'
    data = {
        "filename":f"file{num}",
        "uuid":f"fileuuid{num}",
        "filepath":f"/path/to/file{num}.xls",
        "machine":"f526255265340d994510f8d1652e1eb3"
    }

    json_data = json.dumps(data)
    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        print(response.json())
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

def fileget(num):
    url = 'http://127.0.0.1:7379/fileget'
    # action = random.choice([1, 2])
    data = {
        "uuid":f"fileuuid{num}"
    }
    json_data = json.dumps(data)
    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        print(response.json())
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

if __name__ == "__main__":
    for i in range(30):
        tmp = random_string(8)
        fileset(tmp)
        fileget(tmp)