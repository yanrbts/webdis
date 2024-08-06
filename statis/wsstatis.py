import redis
import asyncio
import websockets
import json
import click
import sys
import signal
import os
import time
from datetime import datetime
import argparse
from rich.console import Console
from rich.tree import Tree

parser = argparse.ArgumentParser(description='Description of your program')
args = None
suffix_map = {}
wsip = None
wsport = None
rdsip = None
rdsport = None

def logo():

    return f"""\033[92m
██╗    ██╗███████╗███████╗████████╗ █████╗ ████████╗██╗███████╗
██║    ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║██╔════╝
██║ █╗ ██║███████╗███████╗   ██║   ███████║   ██║   ██║███████╗
██║███╗██║╚════██║╚════██║   ██║   ██╔══██║   ██║   ██║╚════██║
╚███╔███╔╝███████║███████║   ██║   ██║  ██║   ██║   ██║███████║
 ╚══╝╚══╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝
\033[93m \t\t*** Welcome to wsstatis  *** \033[33m
\033[93m \t\t*** Version : 0.0.1      *** \033[33m
\033[93m \t\t*** https://www.kxyx.com *** \033[33m
\033[93m \t\t*** Author : yanruibing  *** \033[33m
\033[0m"""

def get_current_date():
    """Gets the string representation of the current date in the format YYYY-MM-DD"""
    return datetime.now().strftime('%Y-%m-%d')

def init_redis():
    try:
        global rdsip, rdsport
        rdsip = "127.0.0.1" if args.redisip is None else args.redisip
        rdsport = 6379 if args.redisport is None else args.redisport
        rds = redis.Redis(host=rdsip, port=rdsport, db=0)
        rds.ping()
        click.secho(f"[*] Connected to ({rdsip}:{rdsport}) Redis!", fg="green")
        return rds
    except redis.ConnectionError as e:
        click.secho(f"[-] Failed to connect to Redis: {e}", fg="red")
        sys.exit(1)

def get_usertotal(rds):
    try:
        cursor = '0'
        count = 0
        pattern = 'userkey:*'
        
        while True:
            cursor, keys = rds.scan(cursor, match=pattern, count=1000)
            count += len(keys)
            if cursor == 0:
                break
        return count
    except redis.ConnectionError as e:
        click.secho(f"[-] Failed to connect to Redis: {e}", fg="red")
        return 0
    except Exception as e:
        click.secho(f"[-] An error occurred: {e}", fg="red")
        return 0

# def get_today_userinfos(rds):
#     current_date = datetime.now().strftime("%Y-%m-%d")
#     setkey = f"login_users:{current_date}"

#     members = rds.smembers(setkey)
#     user_list = [member.decode('utf-8') for member in members]

#     return user_list

# def get_today_userinfos(rds):
#     current_date = datetime.now().strftime("%Y-%m-%d")
#     setkey = f"login_users:{current_date}"
#     current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

#     members = rds.smembers(setkey)
#     user_list = []

#     for member in members:
#         try:
#             # 将 member 解码为字符串
#             member_str = member.decode('utf-8')
#             user = rds.hget(f"userkey:{member_str}", member_str)
#             if user:
#                 user_info = json.loads(user)

#                 user_info['onlineState'] = 1
#                 user_list.append(user_info)
#             else:
#                 print(f"No data found for member: {member_str}")
#         except json.JSONDecodeError as e:
#             print(f"Failed to decode JSON for member: {member}, Error: {e}")

#     return user_list
    
def get_today_userinfos(rds):
    current_date = datetime.now().strftime("%Y-%m-%d")
    setkey = f"login_users:{current_date}"

    members = rds.smembers(setkey)
    user_list = []

    pipeline = rds.pipeline()

    for member in members:
        member_str = member.decode('utf-8')
        pipeline.hget(f"userkey:{member_str}", member_str)

    results = pipeline.execute()

    for member, user in zip(members, results):
        member_str = member.decode('utf-8')
        if user:
            try:
                user_info = json.loads(user)
                user_info['onlineState'] = 1
                user_list.append(user_info)
            except json.JSONDecodeError as e:
                print(f"Failed to decode JSON for member: {member_str}, Error: {e}")
        else:
            print(f"No data found for member: {member_str}")

    return user_list

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
        click.secho(f"[-] Failed to connect to Redis: {e}", fg="red")
        return 0, 0
    except Exception as e:
        click.secho(f"[-] An error occurred: {e}", fg="red")
        return 0, 0

def get_total_trace_count(rds):
    """Get the total number of traceability information"""
    try:
        total_trace_count = rds.get('total_trace_count')
        total_trace_count = int(total_trace_count) if total_trace_count else 0

        return total_trace_count
    except redis.ConnectionError as e:
        click.secho(f"[-] Get Trace count Failed to connect to Redis: {e}", fg="red")
        return 0
    except Exception as e:
        click.secho(f"[-] Get Trace count An error occurred: {e}", fg="red")
        return 0

def get_last_trace_info(rds):
    """Get the latest 20 file traceability information"""
    try:
        last_trace = rds.lrange('latest_trace', 0, -1)

        # Decode bytes to string
        last_trace = [item.decode('utf-8') for item in last_trace]
        # Convert to JSON
        # last_trace_json = json.dumps(last_trace, indent=4)

        return last_trace
    except redis.ConnectionError as e:
        click.secho(f"[-] Get Trace count Failed to connect to Redis: {e}", fg="red")
        return []
    except Exception as e:
        click.secho(f"[-] Get Trace count An error occurred: {e}", fg="red")
        return []

def get_recent_auth_and_apply(rds):
    """# Get the number of applications and authorizations in the last 5 days"""
    try:
        # Get the date of the last 5 days
        dates = rds.zrevrange("dates", 0, 4)
        data = {}
        recent_date = []
        recent_auths = []
        recent_apply = []
        for date in dates:
            date = date.decode('utf-8')
            # Get the number of authorizations in the last 5 days
            count = rds.hget(f"auth:{date}", "count")
            count = int(count.decode('utf-8')) if count else 0
            recent_auths.append(count)

            # Get the number of applications in the last 5 days
            count = rds.hget(f"apply:{date}", "count")
            count = int(count.decode('utf-8')) if count else 0
            recent_apply.append(count)


            recent_date.append(date)

        data["datelist"] = recent_date
        data["authlist"] = recent_auths
        data["applylist"] = recent_apply 
        return data
    except redis.ConnectionError as e:
        click.secho(f"[-] Get recent Auth and Apply count Failed to connect to Redis: {e}", fg="red")
        return {}
    except Exception as e:
        click.secho(f"[-] Get recent Auth and Apply An error occurred: {e}", fg="red")
        return {}
    
def get_file(rds, keys):
    pipeline = rds.pipeline()  # 使用 Pipeline 执行批量操作
    all_data = {}

    for key in keys:
        key = key.decode('utf-8')
        pipeline.hgetall(key)

    results = pipeline.execute()

    for key, value in zip(keys, results):
        key = key.decode('utf-8')
        filtered_value = {k: v for k, v in value.items() if not k.decode('utf-8').startswith('trace:')}
        all_data[key] = filtered_value

    for key, value in all_data.items():
        for inner_key, json_data in value.items():
            try:
                data = json.loads(json_data.decode('utf-8'))
                filepath = data.get('filepath', '')
                if not filepath:
                    continue
                filename = filepath.split('/')[-1]

                suffix = filename.split('.')[-1]
                if suffix:
                    if suffix not in suffix_map:
                        suffix_map[suffix] = 1
                    else:
                        suffix_map[suffix] += 1
            except Exception as e:
                click.secho(f"[-] Error processing JSON data: {e}", fg="red")

def get_filetotal(rds):
    try:
        cursor = '0'
        count = 0
        pattern = 'filekey:*'
        
        while True:
            cursor, keys = rds.scan(cursor, match=pattern, count=10000)
            count += len(keys)
            get_file(rds, keys)
            if cursor == 0:
                break
        return count
    except redis.ConnectionError as e:
        click.secho(f"[-] Failed to connect to Redis: {e}", fg="red")
        return 0
    except Exception as e:
        click.secho(f"[-] An error occurred: {e}", fg="red")
        return 0

def get_area_device_bykeys(rds, keys):
    pipeline = rds.pipeline()  # 使用 Pipeline 执行批量操作
    area_map = {}
    device_map = {}

    # 批量获取所有键的数据
    for key in keys:
        pipeline.hgetall(key)

    results = pipeline.execute()

    # 解析结果
    for key, value in zip(keys, results):
        key = key.decode('utf-8')  # 解析 key
        if value:
            for inner_key, json_data in value.items():
                try:
                    data = json.loads(json_data.decode('utf-8'))

                    # 处理区域计数
                    area = data.get('area', '')
                    if area:
                        area_map[area] = area_map.get(area, 0) + 1

                    # 处理设备计数
                    device = data.get('device', '')
                    if device:
                        device_map[device] = device_map.get(device, 0) + 1

                except json.JSONDecodeError as e:
                    click.secho(f"[-] JSON decode error for key '{key}', inner key '{inner_key}': {e}", fg="red")
                except Exception as e:
                    click.secho(f"[-] Error processing data for key '{key}', inner key '{inner_key}': {e}", fg="red")

    return area_map, device_map

def get_total_area_and_device(rds):
    area_map = {}
    device_map = {}

    try:
        cursor = '0'
        pattern = 'userkey:*'
        
        while True:
            cursor, keys = rds.scan(cursor, match=pattern, count=1000)
            if keys:
                # 获取 area 和 device 数据
                new_area_map, new_device_map = get_area_device_bykeys(rds, keys)

                # 合并结果
                for area, count in new_area_map.items():
                    if area in area_map:
                        area_map[area] += count
                    else:
                        area_map[area] = count

                for device, count in new_device_map.items():
                    if device in device_map:
                        device_map[device] += count
                    else:
                        device_map[device] = count

            if cursor == 0:
                break

    except redis.ConnectionError as e:
        click.secho(f"[-] Get Area and Device Failed to connect to Redis: {e}", fg="red")
    except Exception as e:
        click.secho(f"[-] Get Area and Device An error occurred: {e}", fg="red")

    sorted_device_map = dict(sorted(device_map.items(), key=lambda item: item[1], reverse=True))
    return area_map, sorted_device_map


async def statis_data(rds):
    global suffix_map
    suffix_map.clear()

    last_traces = []
    recent_record = {}
    file_total = get_filetotal(rds)
    today_login_count, total_login_count = get_login_counts(rds)
    onlineusers = get_today_userinfos(rds)
    total_trace_counts = get_total_trace_count(rds)
    last_traces = get_last_trace_info(rds)
    recent_record = get_recent_auth_and_apply(rds)
    area_list, device_list = get_total_area_and_device(rds)
    
    data = {
        "today_user_count": today_login_count,
        "total_login_count": total_login_count,
        "total_trace_counts": total_trace_counts,
        "filetotal": file_total,
        "fileext": suffix_map,
        "online_users": onlineusers,
        "area_list": area_list,
        "device_list": device_list,
        "last_traces": last_traces,
        "recent_count": recent_record
    }
    return data

def countdown(total_seconds):
    while total_seconds > 0:
        if total_seconds >= 3600:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            print(f"\033[92m[-] Time remaining: {hours:.0f}h {minutes:02.0f}m {seconds:05.2f}s \033[0m", end="\r")
            time.sleep(1)
        elif total_seconds >= 60:
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            print(f"\033[92m[-] Time remaining: {minutes:.0f}m {seconds:05.2f}s \033[0m", end="\r")
            time.sleep(1)
        else:
            print(f"\033[92m[-] Time remaining: {total_seconds:.2f}s \033[0m", end="\r")
            time.sleep(1)
        total_seconds -= 1

# Display data using a tree structure for easy observation. 
# If the amount of data in the printed log is large, 
# it will be difficult to read.

def add_branch(tree, key, value):
    if key == "online_users" or key == "last_traces":
        # 只显示 online_users 节点的子节点数量
        if isinstance(value, list):
            count = len(value)
            tree.add(f"[green]{key}[/green]: [yellow]{count}[/yellow]")
        return
    
    if isinstance(value, dict):
        branch = tree.add(f"[bold]{key}[/bold]")
        for k, v in value.items():
            add_branch(branch, k, v)
    elif isinstance(value, list):
        branch = tree.add(f"[bold]{key}[/bold]")
        for i, v in enumerate(value):
            add_branch(branch, f"[{i}]", v)
    else:
        tree.add(f"[green]{key}[/green]: [yellow]{value}[/yellow]")

def show_tree(data, s, ms):
    console = Console()
    tree = Tree(f"ROOT({wsip}:{wsport})")

    for key, value in data.items(): 
        add_branch(tree, key, value)
    os.system('clear')
    print(logo())
    print(f"\033[92m[*] Wsstatis server: {wsip}:{wsport} \033[0m")
    print(f"\033[92m[*] Redis server: {rdsip}:{rdsport} \033[0m")
    print(f"\033[92m[*] Execution Time: {s}.{ms:03d} seconds \033[0m")
    console.print(tree)
    countdown(args.n)

async def websocket_handler(websocket, path, rds):
    while True:
        try:
            start_time = time.time()  # 记录开始时间
            data = await statis_data(rds)
            await websocket.send(json.dumps(data))
            end_time = time.time()  # 记录结束时间

            elapsed_time = end_time - start_time  # 计算耗时
            seconds = int(elapsed_time)  # 秒部分
            milliseconds = int((elapsed_time - seconds) * 1000)  # 毫秒部分


            show_tree(data, seconds, milliseconds)
            # Adjust the refresh interval to reduce the pressure on Redis
            await asyncio.sleep(args.n)  
        except websockets.ConnectionClosedOK as e:
            click.secho(f"[-] Connection closed: {e}", fg="yellow")
            break
        except websockets.ConnectionClosedError as e:
            click.secho(f"[-] Connection error: {e}", fg="red")
            break
        except Exception as e:
            click.secho(f"[-] An unexpected error occurred: {e}", fg="red")
            break

async def main():
    rds = init_redis()
    global stop_event
    stop_event = asyncio.Event()

    global wsip, wsport
    wsip = "0.0.0.0" if args.wsip is None else args.wsip
    wsport = 8765 if args.wsport is None else args.wsport
    click.secho(f"[*] websocket server ({wsip}:{wsport})!", fg="green")
    async with websockets.serve(lambda ws, path: websocket_handler(ws, path, rds), wsip, wsport):
        await stop_event.wait()

def signal_handler(sig, frame):
    global stop_event
    if stop_event is not None:
        stop_event.set()
    click.secho("[*] Received KeyboardInterrupt. Cleaning up...", fg="green")
    sys.exit(0)

if __name__ == "__main__":
    print(logo())

    # parser.add_argument('-u','--mysqluser', metavar='', type=str, required=True,
    #                     help='Specify mysql username')

    parser.add_argument('-w','--wsip', metavar='', type=str,
                        help='Specify websocket server IP')
    parser.add_argument('-s','--wsport', metavar='', type=int,
                        help='Specify websocket server port')
    parser.add_argument('-i','--redisip', metavar='', type=str,
                        help='Specify redis server IP')
    parser.add_argument('-p','--redisport', metavar='', type=int,
                        help='Specify redis port')
    parser.add_argument('-n', metavar='', type=int, default=5,
                        help='Specify the time interval for read data, in units of one Second, the default is 5 Second')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="increase output verbosity")

    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        args = parser.parse_args()
        if args.verbose:
            click.secho(f"Wsstatis version : 1.0.0")
            sys.exit(0)
        
        asyncio.run(main())
    except KeyboardInterrupt:
        click.secho("[*] Server has shut down gracefully.", fg="green")
        signal_handler(signal.SIGINT, None)
