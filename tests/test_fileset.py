from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/fileset", json={
            "filename": "file1",
            "uuid": "file1uuid",
            "filepath": "/path/to/file1.txt",
            "machine": "f526255265340d994510f8d1652e1eb1"
        })

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)
