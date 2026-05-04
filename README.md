# Secure Log Anomaly Detection API

A production‑ready FastAPI microservice that detects anomalies in log lines (SQL injection, path traversal, command execution, high entropy) with **JWT authentication**, **bcrypt hashing**, **rate limiting**, and a **full DevSecOps CI/CD pipeline** (Bandit, pip‑audit, Trivy) that blocks critical vulnerabilities.

---

## 🚀 Features

- **JWT authentication** with bcrypt password hashing  
- **Anomaly detection** – rule‑based (SQLi, path traversal, command exec) + Shannon entropy  
- **Security monitoring** – failed login bursts (5 failures/60 sec), IP rate limiting (100 req/60 sec), error bursts  
- **Input validation** – rejects empty or over‑long log lines  
- **Containerized** with Docker  
- **CI/CD pipeline** (GitHub Actions) – runs Bandit SAST, pip‑audit, pytest, Docker build, Trivy image scan, and **fails on CRITICAL vulnerabilities**  
- **Cloud deployment ready** – includes a Render deploy step (add secrets to enable)

---

## 📁 Project Structure
```log-anomaly-api/
├── .github/workflows/
│ └── ci-cd.yml # DevSecOps pipeline
├── tests/
│ └── test_api.py
├── Dockerfile
├── requirements.txt
├── main.py
├── security_monitor.py
├── middleware.py
└── README.md
```

## 🛠️ Local Setup

### Prerequisites
- Python 3.11+
- Docker (optional, for containerised run)

### 1. Clone the repository
```
git clone https://github.com/Shivkanya-04/Secure-Log-Anomaly-Detection-API.git
cd Secure-Log-Anomaly-Detection-API
````
2. Install dependencies
```
pip install -r requirements.txt
```

3. Run the API
```
uvicorn main:app --reload
```
4. Test the endpoints
Get a JWT token:
```
curl -X POST http://localhost:8000/token \
  -d "username=admin&password=SecurePass123!"
```
Analyze a log line (requires token):

```
TOKEN=<your-token>
curl -X GET "http://localhost:8000/detect?log_line=admin%27%20OR%201=1--" \
  -H "Authorization: Bearer $TOKEN"
```
Expected response:
```
json
{
  "is_anomaly": true,
  "findings": ["SQL injection"],
  "entropy": 3.51
}
```
Run with Docker
```
docker build -t log-anomaly-api .
docker run -d -p 8000:8000 --name my-api log-anomaly-api
```
Test the same curl commands against http://localhost:8000.

### CI/CD Pipeline (GitHub Actions)
The workflow ```(.github/workflows/ci-cd.yml) ```runs on every push to main:

| Step | Tool | Purpose |
| :--- | :--- | :--- |
| SAST | Bandit | Finds security issues in Python code |
| Dependency | scan	pip‑audit | Checks for known vulnerabilities in packages |
| Unit tests | pytest |	Validates API behaviour (import fix pending) |
| Image build |	Docker |	Builds the container |
| Container scan | Trivy |	Scans for CRITICAL OS & language vulnerabilities |
| Deploy	| Render | Deploys to cloud after secrets are added |

Security gate: The pipeline exits with 1 if Trivy finds any CRITICAL vulnerability – preventing insecure images from being deployed.

### Deployment to Render
1. Create a Web Service connected to your GitHub repo
2. Set environment: Docker, port 8000
3. Copy Service ID and generate an API Key
4. Add two secrets in your GitHub repository:
```RENDER_SERVICE_ID and RENDER_API_KEY```
5. After the next push, the deploy job will automatically deploy your API to a public URL.

### Testing the Security Controls
| Control | Test |
| :--- | :--- |
| Failed login burst |	Send 6 wrong passwords in 60 sec → ```429 Too Many Requests``` |
| Rate limiting	| Send >100 requests in 60 sec → ```429 Too Many Requests``` |
| JWT protection |	Call /detect without token → ```401 Unauthorized``` |
| Input validation | Call /detect?log_line= → ```400 Bad Request``` |

🛡️ Security Features Summary
1. JWT authentication (HS256, 30‑min expiry)
2. bcrypt password hashing
3. Rate limiting & login burst detection (per IP)
4. Input validation (length, null bytes)
5. Security headers (via middleware)
6. CI/CD security scanning (Bandit, pip‑audit, Trivy)
7. Security gate – pipeline fails on CRITICAL vulnerabilities
