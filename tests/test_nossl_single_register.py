import requests
import json
import random
import string
from datetime import datetime, timedelta

g_provinces = [
    "北京市",
    "天津市",
    "河北省",
    "山西省",
    "内蒙古",
    "辽宁省",
    "吉林省",
    "黑龙江省",
    "上海市",
    "江苏省",
    "浙江省",
    "安徽省",
    "福建省",
    "江西省",
    "山东省",
    "河南省",
    "湖北省",
    "湖南省",
    "广东省",
    "广西省",
    "海南省",
    "重庆市",
    "四川省",
    "贵州省",
    "云南省",
    "西藏省",
    "陕西省",
    "甘肃省",
    "青海省",
    "宁夏省",
    "新疆省",
    "台湾省",
    "香港特备行政区",
    "澳门特别行政区"
]

g_etype = [
    "华为",
    "vivo",
    "oppo",
    "Android"
]

def random_device():
    return random.choice(g_etype)

def random_area():
    return random.choice(g_provinces)

def random_string(length):
    letters_and_digits = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def random_username():
    random_number = random.randint(1, 1000000)
    username = f'user{random_number}'
    return username

def generate_random_today_time():
    # 获取当前日期
    today = datetime.now().date()
    
    # 生成当天的开始时间和结束时间
    start_time = datetime.combine(today, datetime.min.time())
    end_time = datetime.combine(today, datetime.max.time())
    
    # 生成当天的随机时间
    random_time = start_time + timedelta(seconds=random.randint(0, int((end_time - start_time).total_seconds())))
    
    # 返回随机时间的字符串表示，格式为"%Y-%m-%d %H:%M:%S"
    return random_time.strftime("%Y-%m-%d %H:%M:%S")

def generate_random_uuid():
    # 生成一个长度为32的随机十六进制字符串
    hex_chars = string.hexdigits[:16]  # '0123456789abcdef'
    random_uuid = ''.join(random.choices(hex_chars, k=32))
    return random_uuid

def register():
    url = "http://127.0.0.1:7379/register"

    data = {
        "machine": "f526255265340d994510f8d1652e1eb1",
        "username": "15727311932",
        "area": random_area(),
        "device": random_device(),
        "logintime": generate_random_today_time(),
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