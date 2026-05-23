# Setup Documentation & Deployment Brief

**Problem Statement:** #18 - GraphQL API Security Auditor (Introspection & Injection)
**Target Architecture:** Cloud-Native / Microservices (Application Layer)

Team 05:
Ananya Santosh- BL.EN.U4CSE23207
Anvita Arasavilli- BL.EN.U4CSE23208
Janhavi Nilesh Parate- BL.EN.U4CSE23224
Keerthi DA- BL.EN.U4CSE23233
Lakshmi Priya Subramanian- BL.EN.U4CSE23236


## 1. Prerequisites
To deploy and run this solution, the target environment must have the following installed:
* **Docker** & **Docker Compose**
* **Python 3.9+** (For running the offensive probe tool)

## 2. Deployment Steps
This solution is containerised, ensuring rapid and reproducible deployment across any cloud-native or local environment.

1. **Clone the repository and navigate to the project root:**
   ```bash
   cd GraphQL-API-Security-Auditor--Introspection-and-Injection
   ```

2. **Deploy the Infrastructure via Docker Compose:**
   ```bash
   docker-compose up -d
   ```
   This command spins up three isolated services on a custom bridge network:
   * **`mongodb`**: The persistent backend database (Port 27017).
   * **`target-api`**: The vulnerable GraphQL server (Port 4000).
   * **`middleware`**: The defensive reverse proxy (Port 8080).

3. **Verify the Deployment:**
   Wait a few seconds for the database to seed, then verify the health endpoint:
   ```bash
   curl http://localhost:8080/health
   ```
   You should receive a JSON response confirming the middleware is active and listing the current security configuration.

## 3. Configuration & Tuning
The middleware is designed to be tuned by operators based on their specific environmental needs.

**Runtime Configuration:**
Operators can tune security rules dynamically (without restarting the container) via the `/config` API endpoint. For example, to adjust the rate limit and maximum query depth:
```bash
curl -X POST http://localhost:8080/config \
  -H "Content-Type: application/json" \
  -d '{"max_depth": 10, "rate_limit": 120}'
```

**Hardcoded Defaults (Configured in `middleware/rules.py`):**
* `ALLOW_INTROSPECTION`: False
* `MAX_QUERY_DEPTH`: 5
* `MAX_QUERY_COMPLEXITY`: 100
* `ALLOW_BATCHING`: False
* `RATE_LIMIT_REQUESTS_PER_MINUTE`: 60

## 4. Observability
To ensure operators know the tool is working, the middleware provides real-time observability:
* **JSON Statistics API**: Available at `http://localhost:8080/stats`
* **Live HTML Dashboard**: Available at `http://localhost:8080/stats/dashboard`. This dashboard automatically refreshes every 3 seconds, showing a grid of total requests, block rates, and a real-time feed of the last 20 blocked malicious queries with their attacker IP and triggered rule.

## 5. Running the Offensive Probe
To test the environment, use the provided Python probe tool.

```bash
# Install dependencies
cd probe
pip install -r requirements.txt

# Attack the unprotected API (All attacks succeed)
python probe.py --target http://localhost:4000/graphql

# Attack the protected Middleware (All attacks blocked)
python probe.py --target http://localhost:8080/graphql
```
