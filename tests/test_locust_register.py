from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/register", json={
            "machine":"f526255265340d994510f8d1652e1eb16",
            "username":"15727311932",
            "flag":0})

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)