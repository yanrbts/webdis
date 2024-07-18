from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/filesettrace", json={
            "machine": "uuid",
            "fileuuid": "fileuuid",
            "filename": "file1",
            "filepath": "/path/to/file1.txt",
            "username": "user",
            "time": "2024-05-23",
            "action": 0
            })

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)
