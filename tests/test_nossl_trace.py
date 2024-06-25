import requests
import json
import random
import string

cert_file_path = "/home/yrb/src/kserver/cert/client.pem"
ca_path = "/home/yrb/src/kserver/cert/rootCA.pem"

def random_string(length):
    letters_and_digits = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def setfile():
    url = 'http://127.0.0.1:7379/fileset'

    data = {
        "filename":"file7",
        "uuid":"fileuuid7",
        "filepath":"/path/to/file7.txt",
        "machine":"f526255265340d994510f8d1652e1eb3"
    }

    json_data = json.dumps(data)

    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        print('Response:', response.json())
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

def settrace():
    url = 'http://127.0.0.1:7379/filesettrace'

    data = {
        "machine":"f526255265340d994510f8d1652e1eb3",
        "uuid":"fileuuid7",
        "username":random_string(11),
        "time":"2024-05-23",
        "action":0
    }

    json_data = json.dumps(data)

    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        print('Response:', response.json())
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)

def gettracespage(page):
    url = 'http://127.0.0.1:7379/filegettrace'

    data = {
        "uuid":"fileuuid7",
        "page":page
    }

    json_data = json.dumps(data)

    response = requests.post(url, data=json_data, 
                             headers={'Content-Type': 'application/json'})

    if response.status_code == 200:
        # print('Response:', response.text)
        return response.json()
    else:
        print(f'Request failed with status code {response.status_code}')
        print('Response:', response.text)
    

def gettraces():
    page = 0

    while True:
        response =  gettracespage(page)
        page = response["page"]
        if page != 0:
            # print('Response:', response)
            n = len(response['traces'])
            print(f"Number of traces: {n}")
        else:
            n = len(response['traces'])
            print(f"Number of traces: {n}")
            break

if __name__ == "__main__":
    setfile()
    for _ in range(30):
        settrace()
    gettraces()