from fastapi import FastAPI, HTTPException, Depends, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from security_monitor import monitor
from middleware import ErrorTrackingMiddleware, get_client_ip
import math
import re

app = FastAPI(title="Secure Log Anomaly API", version="2.0")
app.add_middleware(ErrorTrackingMiddleware)

#  JWT & bcrypt 
SECRET_KEY = "sut34drm9Xq!7LmP2vK8aN5zR1hY6eTw"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$.qxRmL5/Ulk7a9XPmWdd3OyvvnT8x2yNjoc9f73BX67pRVEkzdOte",  
        "role": "analyst"
    }
}

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = fake_users_db.get(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Anomaly Detection 
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for i in range(256):
        p = text.count(chr(i)) / len(text)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def detect_anomaly(log_line: str):
    findings = []
    if re.search(r"('|%27)\s*(OR|or)\s+\d+\s*=\s*\d+", log_line, re.IGNORECASE):
        findings.append("SQL injection")
    if "..\\" in log_line or "../" in log_line or "..%2f" in log_line.lower():
        findings.append("Path traversal")
    if re.search(r"(cmd\.exe|powershell|bash|sh|whoami)", log_line, re.IGNORECASE):
        findings.append("Command execution attempt")
    entropy = shannon_entropy(log_line)
    if entropy > 4.5:
        findings.append(f"High entropy ({entropy:.2f})")
    return {
        "is_anomaly": len(findings) > 0,
        "findings": findings,
        "entropy": round(entropy, 2)
    }

#  API Endpoints
@app.post("/token")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = get_client_ip(request)
    user = authenticate_user(username, password)
    if not user:
        if monitor.record_login_failure(client_ip):
            raise HTTPException(status_code=429, detail="Too many failed login attempts")
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    monitor.login_failures[client_ip] = []  # reset on success
    token = create_access_token(data={"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/detect")
async def analyze(request: Request, log_line: str, current_user = Depends(get_current_user)):
    client_ip = get_client_ip(request)
    # Rate limiting (total requests)
    if monitor.record_request(client_ip, 200):
        raise HTTPException(status_code=429, detail="Too many requests from your IP")
    if not log_line or len(log_line.strip()) == 0:
        raise HTTPException(status_code=400, detail="Log line cannot be empty")
    if len(log_line) > 10000:
        raise HTTPException(status_code=400, detail="Log line too long (max 10000 chars)")
    return detect_anomaly(log_line)

@app.get("/")
def root():
    return {
        "project": "Secure Log Anomaly Detection API",
        "status": "Running",
        "documentation": "/docs",
        "version": "2.0"
    }
