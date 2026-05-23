# GraphQL API Security Auditor

**Problem Statement:** #18 - GraphQL API Security Auditor (Introspection & Injection)
**Target Architecture:** Cloud-Native / Microservices (Application Layer)

Team 05:
Ananya Santosh- BL.EN.U4CSE23207
Anvita Arasavilli- BL.EN.U4CSE23208
Janhavi Nilesh Parate- BL.EN.U4CSE23224
Keerthi DA- BL.EN.U4CSE23233
Lakshmi Priya Subramanian- BL.EN.U4CSE23236


## What problem does this solve?
A GraphQL API deployed without adequate security controls inherently exposes its entire data schema to any attacker via introspection. This lack of restriction allows malicious actors to map the API, discover sensitive fields, execute resource-exhausting nested or batched DoS queries, and exploit injection vulnerabilities in resolver arguments. This project solves these issues by providing a dual-purpose framework: an **offensive probe tool** to automatically discover these weaknesses, and a **defensive middleware reverse-proxy** that sits in front of any vulnerable GraphQL API to actively block such malicious traffic.

## Which architecture does it target?
**Cloud-Native** 

This project is built and distributed using Docker Compose, orchestrating the target API, the security middleware, and a MongoDB backend within isolated containers. It acts as a microservice proxy layer that can be seamlessly dropped into existing cloud environments.

## What MITRE ATT&CK techniques does it address?
*   **T1190 — Exploit Public-Facing Application**: The primary technique addressed. The defensive middleware blocks attempts to exploit the GraphQL endpoint via injection, deep nesting, and batching.
*   **T1596.005 — Search Open Technical Databases (API Mapping)**: Addressed by blocking introspection queries (R01 rule), preventing attackers from mapping out the API schema.
*   **T1499.004 — Endpoint Denial of Service (Application or System Exploitation)**: Addressed by limiting query depth (R02 rule) and query complexity (R03 rule), mitigating DoS attacks via recursive queries.
*   **T1498 — Network Denial of Service**: Mitigated by rate limiting (R07 rule) and blocking array batching (R04 rule) to stop attackers from sending massive query arrays.

## How do you run it?

### Step 1: Start the Environment
All services (MongoDB, Vulnerable Target API, and Defensive Middleware) are orchestrated via Docker Compose.

```bash
# Start all services in the background
docker-compose up -d

# Verify everything is running:
# MongoDB: localhost:27017
# Target API (Vulnerable): http://localhost:4000/graphql
# Middleware (Protected): http://localhost:8080/graphql
```

### Step 2: Run the Offensive Probe (Without Defense)
Run the probe against the vulnerable API to see all attacks succeed.

```bash
# Navigate to the probe directory and install dependencies
cd probe
pip install -r requirements.txt

# Run the full attack suite against the unprotected target
python probe.py --target http://localhost:4000/graphql
```

### Step 3: Run the Offensive Probe (With Defense)
Run the exact same attack suite through the secure middleware to see attacks get blocked.

```bash
# Run against the middleware to verify protections
python probe.py --target http://localhost:8080/graphql
```

### Step 4: Monitor Live Blocks
Navigate to the live HTML dashboard in your browser to monitor the real-time blocking statistics:
*   **Dashboard**: `http://localhost:8080/stats/dashboard`

### Step 5: Cleanup
```bash
# Stop and remove the containers
docker-compose down
```

## What dependencies does it have?
The project uses standard containerization and lightweight Python frameworks:
*   **System Dependencies**: 
    *   Docker & Docker Compose
    *   Python 3.9+ (for running the probe tool locally)
*   **Target API (`target_api`)**:
    *   `strawberry-graphql[fastapi]`
    *   `fastapi`
    *   `uvicorn`
    *   `pymongo`
*   **Security Middleware (`middleware`)**:
    *   `fastapi`
    *   `uvicorn`
    *   `httpx`
*   **Probe Tool (`probe`)**:
    *   `requests`

## What are known limitations or gaps?
*   **Heuristic AST Parsing**: The query depth and complexity calculations in the middleware use fast heuristics (regex and brace-counting) rather than a full, standard GraphQL Abstract Syntax Tree (AST) parser. While performant and sufficient for demonstrations, clever query formatting using fragments might bypass these checks.
*   **In-Memory Rate Limiting & Stats**: The middleware rate limiter and block statistics are stored entirely in-memory. They will reset upon container restart. For production deployment, this state must be offloaded to an external cache like Redis.
*   **Signature-Based Injection Defense**: The `R05` injection detection uses signature-based regex patterns (`INJECTION_PATTERNS`). This can potentially be evaded by advanced encoding or obfuscation techniques, making it less robust than semantic database query parametrization.
*   **Unauthenticated Config Endpoint**: The middleware exposes a `/config` endpoint to easily toggle rules on/off for demonstration purposes. This endpoint lacks authentication and is not secure for production use as-is.
