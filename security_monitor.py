from collections import defaultdict
import time

class SecurityMonitor:
    def __init__(self, window_seconds=60, max_failures=5, max_requests=100, error_threshold=10):
        self.window_seconds = window_seconds
        self.max_failures = max_failures          # login failures per IP per window
        self.max_requests = max_requests          # total requests per IP per window
        self.error_threshold = error_threshold    # 4xx/5xx errors per IP per window
        
        self.login_failures = defaultdict(list)
        self.requests = defaultdict(list)
        self.errors = defaultdict(list)
    
    def _cleanup(self, ip, store, current_time):
        cutoff = current_time - self.window_seconds
        store[ip] = [t for t in store[ip] if t > cutoff]
    
    def record_login_failure(self, ip):
        current_time = time.time()
        self._cleanup(ip, self.login_failures, current_time)
        self.login_failures[ip].append(current_time)
        return len(self.login_failures[ip]) > self.max_failures
    
    def record_request(self, ip, status_code):
        current_time = time.time()
        self._cleanup(ip, self.requests, current_time)
        self.requests[ip].append(current_time)
        if 400 <= status_code < 600:
            self._cleanup(ip, self.errors, current_time)
            self.errors[ip].append(current_time)
        return len(self.requests[ip]) > self.max_requests
    
    def is_error_burst(self, ip):
        current_time = time.time()
        self._cleanup(ip, self.errors, current_time)
        return len(self.errors[ip]) > self.error_threshold

monitor = SecurityMonitor()