import requests
import json
import random
import string
import time
from datetime import datetime

def random_string(length):
    letters_and_digits = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def settrace():
    url = 'http://127.0.0.1:7379/filesettrace'

    number = random.randint(1, 1000000)
    data = {
        "machine":"f526255265340d994510f8d1652e1eb3",
        "uuid":f"fileuuid{number}",
        "filename":f"file{number}",
        "filepath":f"/path/to/file{number}.txt",
        "username":random_string(11),
        "time":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "action":random.choice([1, 2, 3])
    }

    json_data = json.dumps(data)
    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        print(response.json())
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

def getauth(page, action):
    url = 'http://127.0.0.1:7379/filegetauth'
    # action = random.choice([1, 2])
    data = {
        "machine":"f526255265340d994510f8d1652e1eb3",
        "page":page,
        "action":action
    }
    json_data = json.dumps(data)
    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        return response.json()
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

def getauthorapply(action):
    page = 0

    while True:
        response = getauth(page, action)
        page = response["page"]
        if page != 0:
            # print('Response:', response)
            n = len(response['data'])
            if action == 1:
                print(f"Number of apply: {n}")
            elif action == 2:
                print(f"Number of auth: {n}")
        else:
            n = len(response['data'])
            if action == 1:
                print(f"Number of apply: {n}")
            elif action == 2:
                print(f"Number of auth: {n}")
            break

if __name__ == "__main__":
    for _ in range(30):
        settrace()
    getauthorapply(1)
    getauthorapply(2)