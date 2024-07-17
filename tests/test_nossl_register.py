import requests
import json
import random
import string
from datetime import datetime, timedelta

g_provinces = [
    "北京",
    "天津",
    "河北",
    "山西",
    "内蒙古",
    "辽宁",
    "吉林",
    "黑龙江",
    "上海",
    "江苏",
    "浙江",
    "安徽",
    "福建",
    "江西",
    "山东",
    "河南",
    "湖北",
    "湖南",
    "广东",
    "广西",
    "海南",
    "重庆",
    "四川",
    "贵州",
    "云南",
    "西藏",
    "陕西",
    "甘肃",
    "青海",
    "宁夏",
    "新疆",
    "台湾",
    "香港",
    "澳门"
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
        "machine": generate_random_uuid(),
        "username": random_username(),
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