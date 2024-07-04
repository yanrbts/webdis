from locust import HttpUser, TaskSet, task, between
import os

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/filegettrace", json={"uuid":"fileuuid7","page":0})

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)

    def on_start(self):
        # SSL/TLS 证书路径
        cert_path = os.path.join(os.path.dirname(__file__), "../cert/client.pem")
        key_path = os.path.join(os.path.dirname(__file__), "../cert/client.key")
        ca_cert_path = os.path.join(os.path.dirname(__file__), "../cert/rootCA.pem")

        if not os.path.isfile(cert_path):
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")
        if not os.path.isfile(key_path):
            raise FileNotFoundError(f"Key file not found: {key_path}")
        if not os.path.isfile(ca_cert_path):
            raise FileNotFoundError(f"CA certificate file not found: {ca_cert_path}")

        # 设置 HTTPS 客户端
        self.client.verify = ca_cert_path
        self.client.cert = (cert_path, key_path)