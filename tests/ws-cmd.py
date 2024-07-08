import asyncio
import websockets
import json

async def connect_to_webdis():
    uri = "ws://localhost:7379/.json"
    try:
        async with websockets.connect(uri) as websocket:
            while True:
                # 发送 PING 命令
                await websocket.send(json.dumps(["PING"]))
                
                # 接收响应
                response = await websocket.recv()
                print(f"Received: {response}")
                
                # 可以在这里处理接收到的响应，例如根据需要发送其他命令
                
                # 添加适当的延迟，防止过度频繁发送
                await asyncio.sleep(5)
                
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"Connection closed with error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# 运行异步函数，保持连接
asyncio.get_event_loop().run_until_complete(connect_to_webdis())
