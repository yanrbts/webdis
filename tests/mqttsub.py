# import paho.mqtt.client as mqtt

# # MQTT Broker 地址和端口
# broker = "127.0.0.1"
# port = 1883
# topic = "test/topic"

# def on_connect(client, userdata, flags, rc):
#     print(f"Connected with result code {rc}")
#     # 订阅主题
#     client.subscribe(topic, qos=1)

# def on_message(client, userdata, msg):
#     print(f"Received message: {msg.payload.decode()} on topic {msg.topic} with QoS {msg.qos}")

# client = mqtt.Client(client_id="subscriber_client", clean_session=False)
# client.on_connect = on_connect
# client.on_message = on_message

# client.connect(broker, port, 60)
# client.loop_forever()
########################################################################
# import paho.mqtt.client as mqtt

# broker = "127.0.0.1"
# port = 1883
# topic = "test/topic"
# processed_message_ids = set()  # 存储已处理的消息 ID

# def on_connect(client, userdata, flags, rc):
#     print(f"Connected with result code {rc}")
#     client.subscribe(topic, qos=1)

# def on_message(client, userdata, msg):
#     message = msg.payload.decode()
#     message_id = message.split("ID ")[-1]  # 从消息中提取 ID
#     if message_id not in processed_message_ids:
#         processed_message_ids.add(message_id)
#         print(f"Received message: {message} on topic {msg.topic} with QoS {msg.qos}")
#     else:
#         print(f"Ignored duplicate message with ID {message_id}")

# client = mqtt.Client(client_id="subscriber_client", clean_session=False)
# client.on_connect = on_connect
# client.on_message = on_message

# client.connect(broker, port, 60)
# client.loop_forever()

import paho.mqtt.client as mqtt

broker = "192.168.1.105"
port = 1883
topic = "test/topic"

def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    client.subscribe(topic, qos=1)

def on_message(client, userdata, msg):
    message = msg.payload.decode()
    print(f"Received message: {message} on topic {msg.topic} with QoS {msg.qos}")

def on_disconnect(client, userdata, rc):
    if rc != 0:
        print(f"Unexpected disconnection. Result code: {rc}")

client = mqtt.Client(client_id="subscriber_client1", clean_session=False)  # 使用持久化会话
client.on_connect = on_connect
client.on_message = on_message
client.on_disconnect = on_disconnect

client.connect(broker, port, 60)

try:
    client.loop_forever()
except KeyboardInterrupt:
    print("Exiting...")
    client.disconnect()



