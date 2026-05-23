"""
middleware/middleware.py
GraphQL Security Middleware — FastAPI Reverse Proxy

Sits between the attacker/client and the real GraphQL API.
Intercepts every /graphql request, runs security rules,
and either BLOCKS it (with a structured error) or FORWARDS it.

Architecture:
  [Client] → [This Middleware :8080/graphql] → [Target API :4000/graphql]

Endpoints:
  POST /graphql     — main proxy + security enforcement
  GET  /graphql     — GraphiQL passthrough
  GET  /health      — health check
  GET  /stats       — live enforcement statistics dashboard
  POST /config      — runtime rule configuration (toggle rules on/off)

Run with:
  uvicorn middleware:app --host 0.0.0.0 --port 8080 --reload
"""

import httpx
import json
import time
import os
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
import re

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt

from rules import validate_request, Config

# ── JWT Authentication Setup ──────────────────────────────────────────────────

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "Missing required environment variable: JWT_SECRET_KEY. "
        "Please set JWT_SECRET_KEY before starting the middleware."
    )
ALGORITHM = "HS256"
TOKEN_EXPIRATION_HOURS = 12

# Demo users: {username: (password, role)}
DEMO_USERS = {
    "admin": ("admin123", "admin"),
    "user": ("user123", "public"),
}


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str


def generate_jwt_token(username: str, role: str) -> str:
    """
    Generate a JWT token with username, role, and expiration.
    
    Args:
        username: Username
        role: User role (admin or public)
    
    Returns:
        JWT token string
    """
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRATION_HOURS),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def verify_jwt_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload or None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user(request: Request) -> Optional[dict]:
    """
    Extract the authenticated user from request state.
    
    Returns a dict with 'username' and 'role' if authenticated,
    or None if no valid token is attached.
    
    Usage in endpoints:
        user = get_current_user(request)
        if user:
            print(f"Authenticated as: {user['username']} (role: {user['role']})")
    """
    return getattr(request.state, "user", None)


# ── Response Sanitization ─────────────────────────────────────────────────────
# Removes sensitive internal details from error messages before sending to clients

SENSITIVE_PATTERNS = [
    # Stack traces (Python, Node.js, Java, etc.)
    r"Traceback\s*\(.*?\)",
    r"File\s+['\"].*?['\"],\s+line\s+\d+",
    r"at\s+\w+\s+\([^)]*\)",
    r"in\s+[a-zA-Z_]\w*\s+at\s+",
    
    # Database connection strings
    r"(?i)(password|pwd|secret|token|api_key|apikey)\s*[:=]\s*['\"]?[^\s'\"]+",
    r"(?i)postgresql?://[^\s]+",
    r"(?i)mysql://[^\s]+",
    r"(?i)mongodb://[^\s]+",
    r"(?i)redis://[^\s]+",
    
    # AWS/Cloud credentials
    r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[^\s]+",
    r"AKIA[0-9A-Z]{16}",  # AWS access key
    
    # File paths (common in stack traces)
    r"/[a-zA-Z0-9._\-/]+\.py:\d+",
    r"C:\\[a-zA-Z0-9._\-\\]+\.py:\d+",
    
    # Internal error types
    r"TypeError|ValueError|KeyError|AttributeError|IndexError|RuntimeError",
    r"SQLException|DatabaseException|ConnectionException",
    r"Exception at 0x[0-9a-fA-F]+",
]

# Compile regex patterns for performance
COMPILED_PATTERNS = [re.compile(pattern) for pattern in SENSITIVE_PATTERNS]


def is_sensitive_content(text: str) -> bool:
    """
    Check if text contains sensitive information.
    
    Returns True if any sensitive pattern is detected.
    """
    if not isinstance(text, str):
        return False
    
    for pattern in COMPILED_PATTERNS:
        if pattern.search(text):
            return True
    
    return False


def sanitize_error_message(message: str) -> str:
    """
    Remove sensitive information from error messages.
    
    Args:
        message: Original error message
    
    Returns:
        Sanitized error message
    """
    if not isinstance(message, str):
        return message
    
    original_message = message
    
    # Replace sensitive patterns with generic placeholders
    for pattern in COMPILED_PATTERNS:
        message = pattern.sub("[REDACTED]", message)
    
    # If after sanitization it looks like just redactions, use generic message
    if "[REDACTED]" in message and len(message.split("[REDACTED]")) > 5:
        return "Internal server error"
    
    # If message is too long or contains many redactions, truncate
    if len(message) > 200 or message.count("[REDACTED]") > 3:
        return "Internal server error"
    
    return message


def sanitize_response(response_data: dict) -> dict:
    """
    Sanitize GraphQL response by removing sensitive information.
    
    Args:
        response_data: Parsed JSON response from GraphQL API
    
    Returns:
        Sanitized response data
    """
    if not isinstance(response_data, dict):
        return response_data
    
    sanitized = response_data.copy()
    
    # ── Sanitize errors array ──────────────────────────────────────────────────
    if "errors" in sanitized and isinstance(sanitized["errors"], list):
        sanitized_errors = []
        
        for error in sanitized["errors"]:
            if isinstance(error, dict):
                sanitized_error = error.copy()
                
                # Sanitize error message
                if "message" in sanitized_error:
                    message = sanitized_error["message"]
                    if is_sensitive_content(message):
                        print(f"[SANITIZE] Sensitive content detected in error message")
                        sanitized_error["message"] = sanitize_error_message(message)
                
                # Remove extensions field to prevent leaking backend internals
                if "extensions" in sanitized_error:
                    print(f"[SANITIZE] Removing error.extensions to prevent backend information leakage")
                    del sanitized_error["extensions"]
                
                sanitized_errors.append(sanitized_error)
            else:
                sanitized_errors.append(error)
        
        sanitized["errors"] = sanitized_errors
    return sanitized


def generate_request_id() -> str:
    """
    Generate a unique request ID for tracing.
    
    Returns: Short unique ID (first 12 chars of UUID4)
    """
    return str(uuid.uuid4())[:12]


def get_request_id(request: Request) -> str:
    """
    Get or create request ID from request state.
    
    Args:
        request: FastAPI request object
    
    Returns:
        Request ID string
    """
    if not hasattr(request.state, "request_id"):
        request.state.request_id = generate_request_id()
    return request.state.request_id


# ── Structured Error Response Builders ─────────────────────────────────────────

def create_security_error_response(rule_id: str, message: str, severity: str, details: str, request_id: str) -> dict:
    """
    Create a structured security error response for blocked requests.
    
    Args:
        rule_id: Security rule ID (e.g., R01, R05)
        message: Professional error message for the client
        severity: Severity level (low, medium, high, critical)
        details: Technical details (sanitized)
        request_id: Unique request ID for tracing
    
    Returns:
        Dictionary ready for JSONResponse
    """
    return {
        "errors": [
            {
                "message": message,
                "extensions": {
                    "code": f"SECURITY_RULE_{rule_id}",
                    "rule": rule_id,
                    "severity": severity,
                    "details": details,
                    "request_id": request_id,
                },
            }
        ],
        "blocked": True,
        "rule": rule_id,
    }


def create_client_error_response(message: str, request_id: str) -> dict:
    """
    Create a structured client error response (400 Bad Request).
    
    Args:
        message: Professional error message for the client
        request_id: Unique request ID for tracing
    
    Returns:
        Dictionary ready for JSONResponse
    """
    return {
        "errors": [
            {
                "message": message,
                "extensions": {
                    "code": "CLIENT_ERROR",
                    "request_id": request_id,
                },
            }
        ],
    }


def create_server_error_response(message: str, request_id: str) -> dict:
    """
    Create a structured server error response (5xx).
    
    Args:
        message: Professional error message for the client
        request_id: Unique request ID for tracing
    
    Returns:
        Dictionary ready for JSONResponse
    """
    return {
        "errors": [
            {
                "message": message,
                "extensions": {
                    "code": "SERVER_ERROR",
                    "request_id": request_id,
                },
            }
        ],
    }


def create_auth_error_response(message: str, code: str, request_id: str) -> dict:
    """
    Create a structured authentication/authorization error response.
    
    Args:
        message: Professional error message for the client
        code: Error code (AUTH_REQUIRED, INSUFFICIENT_PERMISSIONS, etc.)
        request_id: Unique request ID for tracing
    
    Returns:
        Dictionary ready for JSONResponse
    """
    return {
        "errors": [
            {
                "message": message,
                "extensions": {
                    "code": code,
                    "request_id": request_id,
                },
            }
        ],
    }


# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="GraphQL Security Middleware",
    description="Defensive layer for GraphQL APIs — Problem #18",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000", "http://localhost:8080"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── Security Headers Middleware ────────────────────────────────────────────────
# Adds HTTP security headers to all responses

@app.middleware("http")
async def add_security_headers_middleware(request: Request, call_next):
    """
    Add security headers to all responses:
    - Strict-Transport-Security: enforce HTTPS
    - X-Content-Type-Options: prevent MIME sniffing
    - X-Frame-Options: prevent clickjacking
    """
    response = await call_next(request)
    
    # Enforce HTTPS-only communication
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Prevent clickjacking attacks
    response.headers["X-Frame-Options"] = "DENY"
    
    return response

# ── JWT Verification Middleware ───────────────────────────────────────────────
# Intercepts all requests, extracts Authorization header, verifies JWT token
# and attaches user info to request.state.user

PUBLIC_ENDPOINTS = {"/login", "/health", "/stats", "/stats/dashboard", "/"}


@app.middleware("http")
async def jwt_verification_middleware(request: Request, call_next):
    """
    JWT Verification Middleware
    
    Intercepts all requests and verifies Authorization header.
    If valid Bearer token is present:
      - Extracts username and role
      - Attaches to request.state.user = {"username": "...", "role": "..."}
    
    Public endpoints (login, health, stats, etc.) bypass verification.
    Protected endpoints can check request.state.user using get_current_user().
    
    Invalid/expired tokens return 401 Unauthorized.
    """
    # Skip verification for public endpoints
    if request.url.path in PUBLIC_ENDPOINTS or request.url.path.startswith("/stats"):
        return await call_next(request)
    
    # Extract Authorization header
    auth_header = request.headers.get("Authorization")
    
    if not auth_header:
        # No token provided — set user to None
        request.state.user = None
        return await call_next(request)
    
    # Parse Bearer token
    if not auth_header.startswith("Bearer "):
        request.state.user = None
        return await call_next(request)
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Verify token
    payload = verify_jwt_token(token)
    
    if payload is None:
        # Invalid or expired token
        request_id = get_request_id(request)
        return JSONResponse(
            status_code=401,
            content=create_auth_error_response(
                message="Authentication failed. Please provide a valid token.",
                code="AUTH_INVALID_TOKEN",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # Attach user info to request state
    request.state.user = {
        "username": payload.get("username"),
        "role": payload.get("role"),
    }
    
    return await call_next(request)

# ── Client IP Extraction (Reverse Proxy Aware) ────────────────────────────────

def get_client_ip(request: Request) -> str:
    """
    Extract client IP address, respecting X-Forwarded-For header for reverse proxy scenarios.
    
    In reverse proxy setups (load balancers, CDN), the direct request.client.host is the proxy's IP.
    The X-Forwarded-For header contains the original client IP (left-most).
    
    Falls back to direct client IP if header is not present.
    
    Args:
        request: FastAPI Request object
    
    Returns:
        Client IP address string
    """
    # Check for X-Forwarded-For header (contains original client IP + proxy chain)
    # Format: original_client_ip, proxy1_ip, proxy2_ip, ...
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # Take the first IP (original client)
        ips = x_forwarded_for.split(",")
        if ips:
            return ips[0].strip()
    
    # Fallback to direct client connection IP
    if request.client:
        return request.client.host
    
    return "unknown"

# ── Target backend URL ────────────────────────────────────────────────────────
TARGET_GRAPHQL_URL = "http://localhost:4000/graphql"

# ── File Logging Setup ────────────────────────────────────────────────────────
# Persistent logging for blocked requests

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

BLOCKED_LOG_FILE = os.path.join(LOG_DIR, "blocked_requests.log")
FORWARDED_LOG_FILE = os.path.join(LOG_DIR, "forwarded_requests.log")


def log_blocked_request(rule_id: str, reason: str, client_ip: str, query_preview: str, request_id: str = ""):
    """
    Append blocked request to log file.
    
    Args:
        rule_id: Security rule ID (e.g., R01, R05)
        reason: Blocking reason
        client_ip: Client IP address
        query_preview: Query excerpt for context
        request_id: Unique request ID for tracing
    """
    try:
        timestamp = datetime.now().isoformat()
        log_entry = {
            "request_id": request_id,
            "timestamp": timestamp,
            "rule_id": rule_id,
            "reason": reason,
            "client_ip": client_ip,
            "query_preview": query_preview[:120] + "..." if len(query_preview) > 120 else query_preview,
        }
        
        with open(BLOCKED_LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[LOG] Error writing to blocked_requests.log: {e}")


def log_forwarded_request(client_ip: str, query_preview: str = "", request_id: str = ""):
    """
    Append forwarded request to log file.
    
    Args:
        client_ip: Client IP address
        query_preview: Query excerpt (optional)
        request_id: Unique request ID for tracing
    """
    try:
        timestamp = datetime.now().isoformat()
        log_entry = {
            "request_id": request_id,
            "timestamp": timestamp,
            "client_ip": client_ip,
            "query_preview": query_preview[:120] + "..." if len(query_preview) > 120 else query_preview,
        }
        
        with open(FORWARDED_LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[LOG] Error writing to forwarded_requests.log: {e}")

# ── Live Statistics ───────────────────────────────────────────────────────────

stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "forwarded_requests": 0,
    "blocks_by_rule": defaultdict(int),
    "blocks_by_ip": defaultdict(int),
    "recent_blocks": [],        # last 20 blocked requests
    "recent_probe_reports": [],  # last 5 probe reports
    "start_time": datetime.now().isoformat(),
}


def record_block(rule_id: str, reason: str, client_ip: str, query_preview: str, request_id: str = "", rule_details: dict = None):
    stats["blocked_requests"] += 1
    stats["blocks_by_rule"][rule_id] += 1
    stats["blocks_by_ip"][client_ip] += 1
    
    entry = {
        "request_id": request_id,
        "timestamp": datetime.now().isoformat(),
        "timestamp_ms": int(time.time() * 1000),
        "rule_id": rule_id,
        "reason": reason,
        "client_ip": client_ip,
        "query_preview": query_preview[:120] + "..." if len(query_preview) > 120 else query_preview,
    }
    
    # If rule has detailed information (e.g., complexity breakdown), include it
    if rule_details:
        entry["details"] = rule_details
    
    stats["recent_blocks"].insert(0, entry)
    stats["recent_blocks"] = stats["recent_blocks"][:20]  # keep last 20
    
    # Write to persistent log file
    log_blocked_request(rule_id, reason, client_ip, query_preview, request_id=request_id)
    
    # Console log with enhanced detail for complexity checks
    if rule_id == "R03" and rule_details:
        # Enhanced logging for complexity scoring
        breakdown = rule_details.get("breakdown", {})
        details_str = f"[DETAILS] Score: {rule_details.get('score')}, Fields: {rule_details.get('field_count')}, Depth: {rule_details.get('depth')}, Lists: {rule_details.get('list_fields')}"
        if breakdown:
            breakdown_str = f"Field: {int(breakdown.get('field_cost', 0))}, Depth: {int(breakdown.get('depth_cost', 0))}, Lists: {breakdown.get('list_cost', 0)}"
            print(f"[MIDDLEWARE] 🚫 BLOCKED [{rule_id}] {request_id} from {client_ip}: {reason}")
            print(f"  {details_str} | Breakdown({breakdown_str})")
        else:
            print(f"[MIDDLEWARE] 🚫 BLOCKED [{rule_id}] {request_id} from {client_ip}: {reason}")
    else:
        print(f"[MIDDLEWARE] 🚫 BLOCKED [{rule_id}] {request_id} from {client_ip}: {reason}")


def record_forward(client_ip: str, query_preview: str = "", request_id: str = ""):
    stats["forwarded_requests"] += 1
    
    # Write to persistent log file
    log_forwarded_request(client_ip, query_preview, request_id=request_id)
    
    print(f"[MIDDLEWARE] ✅ FORWARDED {request_id} from {client_ip}")


# ── Main Proxy Endpoint ───────────────────────────────────────────────────────

@app.post("/graphql")
async def graphql_proxy(request: Request):
    """
    Main security enforcement point.
    1. Parse incoming body
    2. Run all security rules
    3. Block with 400/403 OR forward to real API
    """
    stats["total_requests"] += 1
    
    # Generate unique request ID for tracing
    request_id = get_request_id(request)
    
    # Extract client IP (respects X-Forwarded-For for reverse proxy scenarios)
    client_ip = get_client_ip(request)
    
    # Get authenticated user (if JWT middleware verified a token)
    current_user = get_current_user(request)
    
    # Authentication is mandatory for /graphql requests
    if not current_user:
        return JSONResponse(
            status_code=401,
            content=create_auth_error_response(
                message="Authentication required. Please provide a valid Authorization header.",
                code="AUTH_REQUIRED",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    if current_user:
        print(f"[GRAPHQL] Authenticated request from {current_user['username']} (role: {current_user['role']})")
    
    # Parse request body
    try:
        raw_body = await request.body()
        body = json.loads(raw_body)
    except (json.JSONDecodeError, Exception) as e:
        return JSONResponse(
            status_code=400,
            content=create_client_error_response(
                message="Invalid request format. Please check your JSON syntax.",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # Extract query preview for logging
    if isinstance(body, dict):
        query_preview = body.get("query", "")[:200]
    elif isinstance(body, list):
        query_preview = f"[BATCH: {len(body)} queries]"
    else:
        query_preview = str(body)[:200]
    
    # ── Run Security Rules ────────────────────────────────────────────────────
    # Pass user role for role-based access control (e.g., introspection rules)
    user_role = current_user.get("role") if current_user else None
    is_blocked, blocking_rule, all_results = validate_request(body, client_ip, user_role=user_role)
    
    if is_blocked and blocking_rule:
        record_block(
            rule_id=blocking_rule.rule_id,
            reason=blocking_rule.reason,
            client_ip=client_ip,
            query_preview=query_preview,
            request_id=request_id,
            rule_details=blocking_rule.details,
        )
        
        http_status = 429 if blocking_rule.rule_id == "R07" else 400
        
        return JSONResponse(
            status_code=http_status,
            content=create_security_error_response(
                rule_id=blocking_rule.rule_id,
                message=blocking_rule.reason,
                severity=blocking_rule.severity,
                details=blocking_rule.details,
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # ── Forward to Real API ───────────────────────────────────────────────────
    record_forward(client_ip, query_preview, request_id=request_id)
    
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                TARGET_GRAPHQL_URL,
                content=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Forwarded-For": client_ip,
                    "X-Security-Middleware": "graphql-auditor-v1",
                },
            )
        
        # ── Sanitize Response ─────────────────────────────────────────────────
        # Remove sensitive information from error messages
        try:
            response_data = response.json()
            sanitized_data = sanitize_response(response_data)
            return JSONResponse(
                status_code=response.status_code,
                content=sanitized_data,
                headers={"X-Request-ID": request_id},
            )
        except (json.JSONDecodeError, ValueError):
            # If response is not JSON, return as-is
            return Response(
                content=response.content,
                status_code=response.status_code,
                media_type=response.headers.get("content-type", "application/json"),
                headers={"X-Request-ID": request_id},
            )
    
    except httpx.TimeoutException:
        print(f"[MIDDLEWARE] ⏱️  TIMEOUT {request_id}: Backend request exceeded 20s limit")
        return JSONResponse(
            status_code=504,
            content=create_server_error_response(
                message="Backend request timeout. The server did not respond within the allowed time. Please try again.",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content=create_server_error_response(
                message="Backend service is currently unavailable. Please try again later.",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content=create_server_error_response(
                message="An internal server error occurred. Please contact support if this persists.",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )


@app.get("/graphql")
async def graphql_get_passthrough(request: Request):
    """Pass-through GET requests (GraphiQL browser UI).
    
    Requires authentication to prevent unauthorized schema exploration.
    """
    request_id = get_request_id(request)
    
    # Require authentication for GET /graphql
    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse(
            status_code=401,
            content=create_auth_error_response(
                message="Authentication required to access GraphQL interface.",
                code="AUTH_REQUIRED",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(TARGET_GRAPHQL_URL)
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "text/html"),
            headers={"X-Request-ID": request_id},
        )
    except Exception:
        return JSONResponse(
            status_code=502,
            content=create_server_error_response(
                message="Backend unavailable",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )


# ── Health & Stats Endpoints ──────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "middleware": "GraphQL Security Auditor",
        "target": TARGET_GRAPHQL_URL,
        "uptime_since": stats["start_time"],
        "config": {
            "introspection_allowed": Config.ALLOW_INTROSPECTION,
            "max_depth": Config.MAX_QUERY_DEPTH,
            "max_complexity": Config.MAX_QUERY_COMPLEXITY,
            "batching_allowed": Config.ALLOW_BATCHING,
            "rate_limit": f"{Config.RATE_LIMIT_REQUESTS_PER_MINUTE}/min",
        },
    }


@app.post("/login")
async def login(credentials: LoginRequest):
    """
    JWT Login Endpoint
    
    Demo users:
      - admin / admin123 → role: admin
      - user / user123 → role: public
    
    Returns:
      {
        "token": "eyJ0eXAi...",
        "role": "admin",
        "expires_in": 86400
      }
    """
    username = credentials.username
    password = credentials.password
    
    # Verify credentials against demo users
    if username not in DEMO_USERS:
        return JSONResponse(
            status_code=401,
            content={
                "error": "Invalid credentials",
                "message": f"User '{username}' not found",
            },
        )
    
    stored_password, role = DEMO_USERS[username]
    
    if password != stored_password:
        return JSONResponse(
            status_code=401,
            content={
                "error": "Invalid credentials",
                "message": "Incorrect password",
            },
        )
    
    # Generate JWT token
    token = generate_jwt_token(username, role)
    
    return {
        "token": token,
        "role": role,
        "expires_in": TOKEN_EXPIRATION_HOURS * 3600,  # in seconds
        "username": username,
    }


def _get_stats_data():
    """
    Internal helper to compute stats data (without authentication check).
    Used by both get_stats() and stats_dashboard() endpoints.
    
    Sanitizes recent_blocks to remove sensitive payload previews while preserving
    useful analytics data (rule IDs, timestamps, anonymized IPs).
    """
    block_rate = (
        round(stats["blocked_requests"] / stats["total_requests"] * 100, 1)
        if stats["total_requests"] > 0 else 0
    )
    
    # Sanitize recent_blocks to remove payload previews
    sanitized_blocks = []
    for block in stats["recent_blocks"]:
        client_ip = block.get("client_ip", "unknown")
        # Anonymize IP: show first octet only, mask rest
        if "." in client_ip:
            first_octet = client_ip.split(".")[0]
            anonymized_ip = f"{first_octet}.*.*.* "
        else:
            anonymized_ip = "*.*.*.* "
        
        sanitized_block = {
            "request_id": block.get("request_id"),
            "timestamp": block.get("timestamp"),
            "rule_id": block.get("rule_id"),
            "reason": block.get("reason"),
            "client_ip": anonymized_ip,
            # Removed: "query_preview" to prevent payload leakage in dashboard
        }
        sanitized_blocks.append(sanitized_block)
    
    return {
        "total_requests": stats["total_requests"],
        "blocked_requests": stats["blocked_requests"],
        "forwarded_requests": stats["forwarded_requests"],
        "block_rate_percent": block_rate,
        "blocks_by_rule": dict(stats["blocks_by_rule"]),
        "blocks_by_ip": dict(stats["blocks_by_ip"]),
        "recent_blocks": stats["recent_blocks"],
    }


@app.get("/stats/dashboard", response_class=HTMLResponse)
def stats_dashboard(request: Request):
    """Simple HTML dashboard showing live stats.
    
    ⛔ PROTECTED ENDPOINT — Admin only
    
    Requires:
    - Valid JWT token with Bearer prefix
    - User role must be "admin"
    """
    request_id = get_request_id(request)
    
    # Check if user is authenticated
    current_user = get_current_user(request)
    
    if current_user is None:
        return JSONResponse(
            status_code=401,
            content=create_auth_error_response(
                message="Authentication required.",
                code="AUTH_REQUIRED",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # Check if user is admin
    if current_user.get("role") != "admin":
        return JSONResponse(
            status_code=403,
            content=create_auth_error_response(
                message="Admin access required to view dashboard.",
                code="INSUFFICIENT_PERMISSIONS",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    s = _get_stats_data()
    rows = "".join(
        f"<tr><td>{b['timestamp']}</td><td><code>{b['rule_id']}</code></td>"
        f"<td>{b['client_ip']}</td><td>{b['reason']}</td>"
        f"<td><small><code>{b['query_preview']}</code></small></td></tr>"
        for b in s["recent_blocks"]
    )
    rules_rows = "".join(
        f"<tr><td>{rule}</td><td>{count}</td></tr>"
        for rule, count in s["blocks_by_rule"].items()
    )
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>GraphQL Security Middleware — Live Dashboard</title>
      <meta http-equiv="refresh" content="3">
      <style>
        body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 2rem; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
        h2 {{ color: #7ee787; margin-top: 2rem; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1rem 0; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
        .stat-number {{ font-size: 2rem; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: .8rem; color: #8b949e; margin-top: .3rem; }}
        .blocked {{ color: #f85149 !important; }}
        .forwarded {{ color: #7ee787 !important; }}
        table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
        th {{ background: #21262d; padding: .5rem; text-align: left; border-bottom: 1px solid #30363d; color: #58a6ff; }}
        td {{ padding: .4rem .5rem; border-bottom: 1px solid #21262d; }}
        tr:hover {{ background: #161b22; }}
        code {{ background: #21262d; padding: 2px 4px; border-radius: 3px; font-size: .85em; }}
        .config {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: .75rem; }}
        .badge-red {{ background: #f8514933; color: #f85149; border: 1px solid #f85149; }}
        .badge-green {{ background: #7ee78733; color: #7ee787; border: 1px solid #7ee787; }}
      </style>
    </head>
    <body>
      <h1>🛡 GraphQL Security Middleware — Live Dashboard</h1>
      <small style="color:#8b949e">Auto-refreshes every 3 seconds | Target: {TARGET_GRAPHQL_URL}</small>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-number">{s['total_requests']}</div>
          <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
          <div class="stat-number blocked">{s['blocked_requests']}</div>
          <div class="stat-label">Blocked 🚫</div>
        </div>
        <div class="stat-card">
          <div class="stat-number forwarded">{s['forwarded_requests']}</div>
          <div class="stat-label">Forwarded ✅</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">{s['block_rate_percent']}%</div>
          <div class="stat-label">Block Rate</div>
        </div>
      </div>

      <div class="config">
        <strong>Active Rules:</strong>
        &nbsp;
        <span class="badge {'badge-red' if not Config.ALLOW_INTROSPECTION else 'badge-green'}">R01 Introspection {'OFF' if not Config.ALLOW_INTROSPECTION else 'ON'}</span>
        &nbsp;
        <span class="badge badge-red">R02 Max Depth: {Config.MAX_QUERY_DEPTH}</span>
        &nbsp;
        <span class="badge badge-red">R03 Max Complexity: {Config.MAX_QUERY_COMPLEXITY}</span>
        &nbsp;
        <span class="badge {'badge-red' if not Config.ALLOW_BATCHING else 'badge-green'}">R04 Batching {'OFF' if not Config.ALLOW_BATCHING else 'ON'}</span>
        &nbsp;
        <span class="badge badge-red">R05 Injection Detection</span>
        &nbsp;
        <span class="badge badge-red">R07 Rate Limit: {Config.RATE_LIMIT_REQUESTS_PER_MINUTE}/min</span>
      </div>

      <h2>Blocks by Rule</h2>
      <table>
        <tr><th>Rule</th><th>Count</th></tr>
        {rules_rows if rules_rows else '<tr><td colspan="2" style="color:#8b949e">No blocks yet</td></tr>'}
      </table>

      <h2>Recent Blocked Requests (last 20)</h2>
      <table>
        <tr><th>Timestamp</th><th>Rule</th><th>IP</th><th>Reason</th><th>Query Preview</th></tr>
        {rows if rows else '<tr><td colspan="5" style="color:#8b949e">No blocks recorded yet</td></tr>'}
      </table>
    </body>
    </html>
    """


# ── Runtime Config Toggle ─────────────────────────────────────────────────────

@app.post("/config")
async def update_config(request: Request):
    """
    Toggle rules at runtime for live demo.
    
    ⛔ PROTECTED ENDPOINT — Admin only
    
    Requires:
    - Valid JWT token with Bearer prefix
    - User role must be "admin"
    
    Error responses:
    - 401 Unauthorized: No token or invalid token (from JWT middleware)
    - 403 Forbidden: Token valid but user is not admin
    
    Example request:
      POST /config
      Authorization: Bearer <admin_token>
      {"allow_introspection": true, "max_depth": 10}
    """
    
    # Generate unique request ID for tracing
    request_id = get_request_id(request)
    
    # ── Step 1: Check if user is authenticated ────────────────────────────────
    current_user = get_current_user(request)
    
    if current_user is None:
        # This should not happen in practice because JWT middleware would reject
        # unauthenticated requests before reaching this endpoint
        return JSONResponse(
            status_code=401,
            content=create_auth_error_response(
                message="Authentication required.",
                code="AUTH_REQUIRED",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # ── Step 2: Check if user is admin ────────────────────────────────────────
    if current_user.get("role") != "admin":
        # User is authenticated but does not have admin role
        return JSONResponse(
            status_code=403,
            content=create_auth_error_response(
                message="Admin access required to modify configuration.",
                code="INSUFFICIENT_PERMISSIONS",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # ── Step 3: User is authenticated and admin — proceed with config update ──
    print(f"[CONFIG] Admin update by {current_user['username']}")
    
    body = await request.json()
    changes = []
    
    if "allow_introspection" in body:
        Config.ALLOW_INTROSPECTION = bool(body["allow_introspection"])
        changes.append(f"ALLOW_INTROSPECTION = {Config.ALLOW_INTROSPECTION}")
    
    if "max_depth" in body:
        Config.MAX_QUERY_DEPTH = int(body["max_depth"])
        changes.append(f"MAX_QUERY_DEPTH = {Config.MAX_QUERY_DEPTH}")
    
    if "max_complexity" in body:
        Config.MAX_QUERY_COMPLEXITY = int(body["max_complexity"])
        changes.append(f"MAX_QUERY_COMPLEXITY = {Config.MAX_QUERY_COMPLEXITY}")
    
    if "allow_batching" in body:
        Config.ALLOW_BATCHING = bool(body["allow_batching"])
        changes.append(f"ALLOW_BATCHING = {Config.ALLOW_BATCHING}")
    
    if "rate_limit" in body:
        Config.RATE_LIMIT_REQUESTS_PER_MINUTE = int(body["rate_limit"])
        changes.append(f"RATE_LIMIT = {Config.RATE_LIMIT_REQUESTS_PER_MINUTE}/min")
    
    print(f"[MIDDLEWARE] Config updated by {current_user['username']}: {changes}")
    return {
        "updated": changes,
        "updated_by": current_user["username"],
        "user_role": current_user["role"],
        "current_config": {
            "allow_introspection": Config.ALLOW_INTROSPECTION,
            "max_depth": Config.MAX_QUERY_DEPTH,
            "max_complexity": Config.MAX_QUERY_COMPLEXITY,
            "allow_batching": Config.ALLOW_BATCHING,
            "rate_limit_per_min": Config.RATE_LIMIT_REQUESTS_PER_MINUTE,
        },
    }


@app.get("/logs")
def get_logs(request: Request):
    """
    View blocked and forwarded requests from persistent logs.
    
    ⛔ PROTECTED ENDPOINT — Admin only
    
    Requires:
    - Valid JWT token with Bearer prefix
    - User role must be "admin"
    
    Returns JSON with blocked and forwarded request entries.
    """
    request_id = get_request_id(request)
    
    # Check if user is authenticated
    current_user = get_current_user(request)
    
    if current_user is None:
        return JSONResponse(
            status_code=401,
            content=create_auth_error_response(
                message="Authentication required.",
                code="AUTH_REQUIRED",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    
    # Check if user is admin
    if current_user.get("role") != "admin":
        return JSONResponse(
            status_code=403,
            content=create_auth_error_response(
                message="Admin access required to view logs.",
                code="INSUFFICIENT_PERMISSIONS",
                request_id=request_id,
            ),
            headers={"X-Request-ID": request_id},
        )
    blocked_logs = []
    forwarded_logs = []
    
    # Read blocked logs
    if os.path.exists(BLOCKED_LOG_FILE):
        try:
            with open(BLOCKED_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        blocked_logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            blocked_logs = blocked_logs[-100:]  # last 100 entries
        except Exception as e:
            blocked_logs = [{"error": f"Error reading log: {e}"}]
    
    # Read forwarded logs
    if os.path.exists(FORWARDED_LOG_FILE):
        try:
            with open(FORWARDED_LOG_FILE, "r") as f:
                for line in f:
                    try:
                        forwarded_logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            forwarded_logs = forwarded_logs[-100:]  # last 100 entries
        except Exception as e:
            forwarded_logs = [{"error": f"Error reading log: {e}"}]
    
    return {
        "blocked_requests": blocked_logs,
        "forwarded_requests": forwarded_logs,
        "log_files": {
            "blocked": BLOCKED_LOG_FILE,
            "forwarded": FORWARDED_LOG_FILE,
        },
    }


@app.get("/")
def root():
    return {
        "service": "GraphQL Security Middleware with JWT Authentication",
        "problem": "#18 — GraphQL API Security Auditor",
        "endpoints": {
            "POST /login":   "JWT login (username, password) → token",
            "POST /graphql": "Secured GraphQL proxy (requires Bearer token)",
            "GET /graphql":  "GraphiQL UI passthrough",
            "GET /health":   "Health check + current config",
            "GET /stats":    "JSON enforcement statistics",
            "GET /stats/dashboard": "Live HTML dashboard",
            "GET /logs":     "Persistent blocked/forwarded request logs",
            "POST /config":  "Runtime rule configuration",
        },
        "authentication": {
            "demo_users": {
                "admin": {"password": "admin123", "role": "admin"},
                "user": {"password": "user123", "role": "public"},
            },
            "usage": "POST /login → Get token → Add 'Authorization: Bearer <token>' to GraphQL requests",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("middleware:app", host="0.0.0.0", port=8080, reload=True)
