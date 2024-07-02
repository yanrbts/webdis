import requests
import json
import random
import string

def random_string(length):
    letters_and_digits = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def settrace():
    url = 'http://127.0.0.1:7379/fileauth'

    data = {
        "machine":"f526255265340d994510f8d1652e1eb3",
        "uuid":"fileuuid17",
        "filename":"file17",
        "filepath":"/path/to/file17.txt",
        "username":random_string(11),
        "time":"2024-05-23",
        "action":3
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
    settrace()