from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task
    def test_post(self):
        self.client.post("/filegettrace", json={"uuid":"fileuuid7","page":0})

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)