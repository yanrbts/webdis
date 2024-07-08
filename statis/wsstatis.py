import redis
import asyncio
import websockets
import json
import click
import sys
import signal
from datetime import datetime
import argparse

parser = argparse.ArgumentParser(description='Description of your program')
args = None
suffix_map = {}

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
        ip = "127.0.0.1" if args.redisip is None else args.redisip
        port = 6379 if args.redisport is None else args.redisport
        rds = redis.Redis(host=ip, port=port, db=0)
        rds.ping()
        click.secho(f"[*] Connected to ({ip}:{port}) Redis!", fg="green")
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
    
def get_file(rds, keys):
    pipeline = rds.pipeline()  # 使用 Pipeline 执行批量操作
    all_data = {}

    for key in keys:
        key = key.decode('utf-8')
        pipeline.hgetall(key)

    results = pipeline.execute()

    for key, value in zip(keys, results):
        key = key.decode('utf-8')
        all_data[key] = value

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

async def statis_data(rds):
    global suffix_map
    suffix_map.clear()

    provinces = []
    filetype = []
    user_total = get_usertotal(rds)
    file_total = get_filetotal(rds)
    today_login_count, total_login_count = get_login_counts(rds)

    data = {
        "today_user_count": today_login_count,
        "total_login_count": total_login_count,
        "provinces": provinces,
        "filetype": filetype,
        "usertotal": user_total,
        "filetotal": file_total,
        "fileext": suffix_map
    }
    
    click.secho(
        f"[*] today count:{today_login_count},"
        f" total count:{total_login_count},"
        f" total files:{file_total},"
        f" file type:{json.dumps(suffix_map)}", fg="green")
    return data

async def websocket_handler(websocket, path, rds):
    while True:
        try:
            data = await statis_data(rds)
            await websocket.send(json.dumps(data))
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

    ip = "0.0.0.0" if args.wsip is None else args.wsip
    port = 8765 if args.wsport is None else args.wsport
    click.secho(f"[*] websocket server ({args.wsip}:{port})!", fg="green")
    async with websockets.serve(lambda ws, path: websocket_handler(ws, path, rds), ip, port):
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
