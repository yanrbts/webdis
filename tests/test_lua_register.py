import redis
import concurrent.futures
import time
from datetime import datetime
import random
import string
import uuid

def run_lua_script(redis_client, set_key, counter_key, user_id, expiry):
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
    
    return redis_client.eval(lua_script, 2, set_key, counter_key, user_id, expiry)

def generate_random_uuid():
    # 生成一个长度为32的随机十六进制字符串
    hex_chars = string.hexdigits[:16]  # '0123456789abcdef'
    random_uuid = ''.join(random.choices(hex_chars, k=32))
    return random_uuid

def test_concurrent_load(redis_host='192.168.29.128', redis_port=6379, num_requests=100000):
    pool = redis.ConnectionPool(host=redis_host, port=redis_port, db=0, max_connections=500)
    redis_client = redis.Redis(connection_pool=pool)
    
    set_key = f"login_users:{get_current_date()}"
    counter_key = f"login_count:{get_current_date()}"
    expiry = 3600
    
    user_ids = [generate_random_uuid() for _ in range(num_requests)]
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(run_lua_script, redis_client, set_key, counter_key, user_id, expiry) for user_id in user_ids]
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                print(result)
            except Exception as e:
                print(f"An error occurred: {e}")

    end_time = time.time()
    print(f"Test completed in {end_time - start_time} seconds")

def get_current_date():
    return datetime.now().strftime("%Y-%m-%d")

def get_login_counts(rds):
    """Get the number of people logged in today and the cumulative number of people logged in"""
    try:
        current_date = get_current_date()
        counter_key = f"login_count:{current_date}"

        # Get the number of people logged in on the day
        today_login_count = rds.hget(counter_key, 'count')
        today_login_count = int(today_login_count) if today_login_count else 0

        # Get the cumulative number of logins
        total_login_count = rds.get('total_login_count')
        total_login_count = int(total_login_count) if total_login_count else 0

        return today_login_count, total_login_count
    except redis.ConnectionError as e:
        print(f"[-] Failed to connect to Redis: {e}")
        return 0, 0
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return 0, 0

if __name__ == "__main__":
    # Run the high concurrency test
    test_concurrent_load()

    # Connect to Redis
    rds = redis.Redis(host='192.168.29.128', port=6379, db=0)

    # Get and print login counts
    today_login_count, total_login_count = get_login_counts(rds)
    print(f"Today's login count: {today_login_count}")
    print(f"Total login count: {total_login_count}")
