# import paho.mqtt.client as mqtt

# # MQTT Broker 地址和端口
# broker = "127.0.0.1"
# port = 1883
# topic = "test/topic"
# message = "Test message4"

# def on_connect(client, userdata, flags, rc):
#     print(f"Connected with result code {rc}")
#     # 发布消息，设置 QoS 为 1 和保留标志为 True
#     client.publish(topic, payload=message, qos=1, retain=False)
#     print(f"Published message: '{message}' to topic '{topic}' with QoS 1 and retain True")
#     # 断开连接
#     client.disconnect()

# client = mqtt.Client()
# client.on_connect = on_connect

# client.connect(broker, port, 60)
# client.loop_forever()

###################################################################
# import paho.mqtt.client as mqtt
# import uuid

# broker = "127.0.0.1"
# port = 1883
# topic = "test/topic"
# message_id = str(uuid.uuid4())  # 生成唯一标识符
# message = f"Message with ID {message_id}"

# def on_connect(client, userdata, flags, rc):
#     print(f"Connected with result code {rc}")
#     client.publish(topic, payload=message, qos=1, retain=False)
#     print(f"Published message: '{message}' to topic '{topic}' with ID {message_id}")

# client = mqtt.Client()
# client.on_connect = on_connect

# client.connect(broker, port, 60)
# client.loop_forever()

import paho.mqtt.client as mqtt
import uuid

broker = "192.168.1.105"
port = 1883
topic = "test/topic"

def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")
    for i in range(1):
        message_id = str(uuid.uuid4())  # 生成唯一标识符
        message = f"Message {i+1} ID {message_id}"
        client.publish(topic, payload=message, qos=1, retain=True)  # 使用保留消息
        print(f"Published message: '{message}' to topic '{topic}' with QoS 1 and retain=True")
    client.disconnect()

client = mqtt.Client()
client.on_connect = on_connect

client.connect(broker, port, 60)
client.loop_forever()



