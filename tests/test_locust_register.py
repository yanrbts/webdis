from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/register", json={
            "machine":"f526255265340d994510f8d1652e1eb16",
            "username":"15727311932",
            "area": "beijing",
            "device": "Android",
            "logintime": "2024-07-17 12:50:30",
            "flag":0})

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)