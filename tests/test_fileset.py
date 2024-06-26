from locust import HttpUser, TaskSet, task, between
import os

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/fileset", json={
            "filename": "file100",
            "uuid": "fileuuid100",
            "filepath": "/path/to/file100.txt",
            "machine": "f526255265340d994510f8d1652e1eb1"
        })

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

    # 如果证书不需要验证 CA，可以使用以下代码：
    # def on_start(self):
    #     # SSL/TLS 证书路径
    #     cert_path = os.path.join(os.path.dirname(__file__), "path/to/client_cert.pem")
    #     key_path = os.path.join(os.path.dirname(__file__), "path/to/client_key.pem")
    #
    #     # 设置 HTTPS 客户端，不验证 CA 证书
    #     self.client.verify = False
    #     self.client.cert = (cert_path, key_path)
