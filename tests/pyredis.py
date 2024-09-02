import redis
import random
import string
from locust import HttpUser, TaskSet, task, between

# 连接Redis
redis_client = redis.StrictRedis(host='192.168.29.128', port=6379, db=0)

# Lua脚本
lua_script = """
local set_key = KEYS[1]
local counter_key = KEYS[2]
local user_id = ARGV[1]
local expiry = tonumber(ARGV[2])
if redis.call('SISMEMBER', set_key, user_id) == 0 then
    redis.call('SADD', set_key, user_id)
    redis.call('HINCRBY', counter_key, 'count', 1)
    redis.call('EXPIRE', set_key, expiry)
    redis.call('EXPIRE', counter_key, expiry)
    return 'Added'
else
    return 'Already Exists'
end
"""

# 预编译Lua脚本
lua_sha = redis_client.script_load(lua_script)

def generate_random_uuid():
    # 生成一个长度为32的随机十六进制字符串
    hex_chars = string.hexdigits[:16]  # '0123456789abcdef'
    random_uuid = ''.join(random.choices(hex_chars, k=32))
    return random_uuid

class UserBehavior(TaskSet):
    @task
    def execute_redis_script(self):
        set_key = "login_users:2024-08-08"
        counter_key = "login_count:2024-08-08"
        user_id = generate_random_uuid()
        expiry = 86400  # 一天

        # 执行Lua脚本
        result = redis_client.evalsha(lua_sha, 2, set_key, counter_key, user_id, expiry)
        # print(f"Result: {result}")

        # 获取计数
        count = redis_client.hget(counter_key, "count")
        print(f"Current count: {count}")

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 3)

if __name__ == "__main__":
    import os
    os.system("locust -f path_to_this_script.py")
