import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_login_success():
    response = client.post("/token", data={"username": "admin", "password": "SecurePass123!"})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_failure():
    response = client.post("/token", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 401

def test_detect_without_token():
    response = client.get("/detect?log_line=test")
    assert response.status_code == 401

def test_detect_with_token():
    login = client.post("/token", data={"username": "admin", "password": "SecurePass123!"})
    token = login.json()["access_token"]
    response = client.get("/detect?log_line=admin%27%20OR%201=1--",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["is_anomaly"] == True

def test_empty_log_line():
    login = client.post("/token", data={"username": "admin", "password": "SecurePass123!"})
    token = login.json()["access_token"]
    response = client.get("/detect?log_line=",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400