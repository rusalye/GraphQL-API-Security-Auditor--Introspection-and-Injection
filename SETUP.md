# Complete Setup Guide — Step-by-Step

This guide walks you through setting up and running the GraphQL Security Auditor project from scratch.

---

## **TABLE OF CONTENTS**

1. [Prerequisites](#prerequisites)
2. [Setup Option A: Docker Compose (EASIEST)](#setup-option-a-docker-compose-easiest)
3. [Setup Option B: Manual Setup (Advanced)](#setup-option-b-manual-setup-advanced)
4. [Verify Installation](#verify-installation)
5. [Run the Probe Attacks](#run-the-probe-attacks)
6. [Run the Demo](#run-the-demo)

---

## **PREREQUISITES**

### **For Docker Compose (RECOMMENDED):**
- ✅ [Docker Desktop](https://www.docker.com/products/docker-desktop) (includes Docker + Docker Compose)
- ✅ Git (to clone the repository)
- ✅ ~2GB disk space

### **For Manual Setup:**
- ✅ Python 3.10+ installed
- ✅ MongoDB server running locally
- ✅ ~500MB disk space

---

## **SETUP OPTION A: DOCKER COMPOSE (EASIEST)**

### **STEP 1: Clone/Open the Repository**

```bash
# If you have Git:
git clone <repository-url>
cd GraphQL-API-Security-Auditor--Introspection-and-Injection

# Or navigate to the existing folder:
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection
```

### **STEP 2: Start All Services with Docker Compose**

```bash
docker-compose up
```

**Wait for these messages (takes ~30 seconds):**

```
mongodb     | [initandlisten] waiting for connections on port 27017
target-api  | INFO:     Uvicorn running on http://0.0.0.0:4000
middleware  | INFO:     Uvicorn running on http://0.0.0.0:8080
```

**Services now running:**
- 🟢 **MongoDB** — `localhost:27017` (database)
- 🟢 **Target API** — `http://localhost:4000/graphql` (vulnerable)
- 🟢 **Middleware** — `http://localhost:8080/graphql` (protected)

### **STEP 3: Open New Terminal(s) to Run Tests**

While Docker keeps running in Terminal 1, open new terminals:

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection
```

### **STEP 4: Verify Services Are Running**

```bash
# Test Target API
curl http://localhost:4000/

# Test Middleware Health
curl http://localhost:8080/health
```

**Expected output:**
```json
{
  "status": "ok",
  "middleware": "GraphQL Security Auditor",
  "target": "http://target-api:4000/graphql",
  "config": {
    "introspection_allowed": false,
    "max_depth": 5,
    "max_complexity": 100,
    "batching_allowed": false,
    "rate_limit": "60/min"
  }
}
```

### **STEP 5: Verify MongoDB Data**

**Option A: Using mongosh (recommended)**

```bash
# Install mongosh if you don't have it (one-time only):
# On Windows: Download from https://www.mongodb.com/try/download/shell
# Or use chocolatey: choco install mongosh

# Connect to MongoDB
mongosh localhost:27017/graphql_api

# Inside mongosh shell:
> show collections
# Output: posts, users

> db.users.find()
# Output: Shows alice and bob users with all their sensitive data

> db.posts.find()
# Output: Shows 2 test posts

> exit
```

**Option B: Using Docker (if mongosh not installed)**

```bash
docker-compose exec mongodb mongosh graphql_api

# Then same commands as above:
> db.users.find()
> db.posts.find()
> exit
```

✅ **If you see alice and bob, MongoDB is working correctly!**

---

### **STEP 6: Run the Probe Tool (Attack the API)**

Open a new terminal and run:

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\probe

# Install dependencies (one-time only)
pip install -r requirements.txt

# ═══════════════════════════════════════════════════════════
# ATTACK 1: VULNERABLE TARGET (no middleware protection)
# ═══════════════════════════════════════════════════════════

python probe.py --target http://localhost:4000/graphql

# Expected output: ALL ATTACKS SUCCEED ✗
# - [+] Introspection: Full schema exposed
# - [+] Sensitive Fields: password, token, ssn, api_key exposed
# - [+] Batching: 100 queries executed from 1 request
# - [+] Deep Nesting: 50-level query executed successfully
# - [+] SQL Injection: ' OR 1=1 -- returns all users
# - [+] NoSQL Injection: {"$gt": ""} bypasses filtering
```

Wait for the report to complete. You'll see:

```
════════════════════════════════════════════════════════════
  FINAL PROBE REPORT
════════════════════════════════════════════════════════════

  Target : http://localhost:4000/graphql
  Overall Risk: 🔴 CRITICAL

  ✗ Introspection exposed
  ✗ 5 HIGH sensitivity fields found
  ✗ Batching vulnerable
  ✗ Nesting vulnerable
  ✗ Injection vulnerable

  Summary: CRITICAL RISK — immediate remediation required
```

**A file `report.json` is created with full attack details.**

---

### **STEP 7: Attack Through Middleware (Protected)**

```bash
# ═══════════════════════════════════════════════════════════
# ATTACK 2: PROTECTED TARGET (through middleware)
# ═══════════════════════════════════════════════════════════

python probe.py --target http://localhost:8080/graphql --skip-dos

# Expected output: ATTACKS BLOCKED ✓
# - [+] Introspection: BLOCKED (R01 — introspection disabled)
# - [+] Deep Nesting: Skipped (--skip-dos flag)
# - [+] Injection: BLOCKED (R05 — injection pattern detected)
```

**Report shows:**

```
════════════════════════════════════════════════════════════
  FINAL PROBE REPORT
════════════════════════════════════════════════════════════

  Target : http://localhost:8080/graphql
  Overall Risk: 🟢 LOW

  ✓ Introspection blocked
  ✓ No sensitive fields accessed
  ✓ Batching blocked
  ✓ Nesting blocked
  ✓ Injection blocked
```

---

### **STEP 8: View Middleware Dashboard**

Open in your browser:

```
http://localhost:8080/stats/dashboard
```

You'll see a **live table** of all blocked attacks:
- Timestamp
- Which rule blocked it
- Client IP
- Query preview

---

### **STEP 9: Run the Full Integration Demo**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\tests

# Install probe dependencies (if not already done)
pip install -r ../probe/requirements.txt

# Run the demo (tests both attack and defense)
python integration_test.py
```

**Output:**

```
════════════════════════════════════════════════════════════
  INTEGRATION TEST — Attack vs Defence Demo
════════════════════════════════════════════════════════════

── Round 1: UNPROTECTED API (:4000) ──
  [✓ PASS] Introspection query: VULNERABLE
  [✓ PASS] Sensitive data access: VULNERABLE
  [✓ PASS] Batch attack: VULNERABLE
  [✓ PASS] SQL injection: VULNERABLE
  [✓ PASS] NoSQL injection: VULNERABLE
  [✓ PASS] Deep nesting: VULNERABLE

── Round 2: PROTECTED API (:8080) ──
  [✓ PASS] Introspection query: BLOCKED
  [✓ PASS] Sensitive data access: BLOCKED
  [✓ PASS] Batch attack: BLOCKED
  [✓ PASS] SQL injection: BLOCKED
  [✓ PASS] NoSQL injection: BLOCKED
  [✓ PASS] Deep nesting: BLOCKED

════════════════════════════════════════════════════════════
Overall: ✓ Defence Working Perfectly
════════════════════════════════════════════════════════════
```

---

### **STEP 10: Cleanup (When Done)**

```bash
# Stop all services
docker-compose down

# (Optional) Delete MongoDB data to start fresh next time
docker-compose down -v
```

---

## **SETUP OPTION B: MANUAL SETUP (ADVANCED)**

Use this if you don't have Docker or prefer running services manually.

### **STEP 1: Open 4 Terminals**

You'll need 4 terminals running in parallel:
1. Terminal for MongoDB
2. Terminal for Target API
3. Terminal for Middleware
4. Terminal for Probe Tool

### **STEP 2: Terminal 1 — Start MongoDB**

```bash
# Option A: If you have MongoDB installed locally
mongod

# Option B: If you have Docker but not MongoDB CLI
docker run -d -p 27017:27017 --name mongo-graphql mongo:latest

# Option C: If you installed MongoDB as a service
# On Windows, it may auto-start. Check:
net start MongoDB
```

**Expected:**
```
[initandlisten] waiting for connections on port 27017
```

### **STEP 3: Terminal 2 — Start Target API**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\target_api

# Install dependencies (one-time only)
pip install -r requirements.txt

# Start the API
uvicorn app:app --host 0.0.0.0 --port 4000 --reload
```

**Expected:**
```
[DATABASE] ✓ Connected to MongoDB
INFO:     Uvicorn running on http://0.0.0.0:4000
```

### **STEP 4: Terminal 3 — Start Middleware**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\middleware

# Install dependencies (one-time only)
pip install -r requirements.txt

# Set environment variable (Windows PowerShell)
$env:TARGET_GRAPHQL_URL="http://localhost:4000/graphql"

# Or in CMD:
set TARGET_GRAPHQL_URL=http://localhost:4000/graphql

# Start the middleware
uvicorn middleware:app --host 0.0.0.0 --port 8080 --reload
```

**Expected:**
```
INFO:     Uvicorn running on http://0.0.0.0:8080
```

### **STEP 5: Terminal 4 — Run the Probe Tool**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\probe

# Install dependencies (one-time only)
pip install -r requirements.txt

# Attack the vulnerable API (no middleware)
python probe.py --target http://localhost:4000/graphql

# Then attack through middleware
python probe.py --target http://localhost:8080/graphql --skip-dos
```

### **STEP 6: Verify Data**

```bash
# In a new terminal, connect to MongoDB
mongosh localhost:27017/graphql_api

# Check data
> db.users.find()
> db.posts.find()
> exit
```

### **STEP 7: Run Integration Test**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\tests
pip install -r ../probe/requirements.txt
python integration_test.py
```

### **STEP 8: Cleanup**

In each terminal, press `Ctrl+C` to stop the services.

```bash
# If you started MongoDB with Docker:
docker stop mongo-graphql
docker rm mongo-graphql
```

---

## **VERIFY INSTALLATION**

### **Quick Verification Checklist**

```bash
# 1. Check Docker is running (if using Docker Compose)
docker --version
docker-compose --version

# 2. Check all containers running
docker-compose ps
# All should show "Up"

# 3. Check Target API responds
curl http://localhost:4000/
# Should return JSON with "graphql_endpoint"

# 4. Check Middleware is healthy
curl http://localhost:8080/health
# Should return JSON with "status": "ok"

# 5. Check MongoDB has data
mongosh localhost:27017/graphql_api
> db.users.countDocuments()
# Should return: 2

# 6. Check stats endpoint
curl http://localhost:8080/stats
# Should return JSON with "total_requests", "blocked_requests"
```

---

## **RUN THE PROBE ATTACKS**

### **Attack the Vulnerable API (No Protection)**

```bash
cd probe
python probe.py --target http://localhost:4000/graphql
```

**Output shows:**
- ✗ Introspection successful
- ✗ Sensitive fields exposed
- ✗ Batching succeeded
- ✗ Deep nesting succeeded
- ✗ Injection succeeded
- **Result: CRITICAL RISK**

### **Attack the Protected API (With Middleware)**

```bash
cd probe
python probe.py --target http://localhost:8080/graphql --skip-dos
```

**Output shows:**
- ✓ Introspection blocked
- ✓ All attacks blocked
- **Result: LOW RISK**

### **Advanced Probe Options**

```bash
# Custom batch size
python probe.py --target http://localhost:4000/graphql --batch-size 500

# Custom nesting depths
python probe.py --target http://localhost:4000/graphql --depths 2 5 10 15 30

# Skip DoS tests (faster)
python probe.py --target http://localhost:8080/graphql --skip-dos

# Custom output filename
python probe.py --target http://localhost:4000/graphql --output attack_report.json

# Combine options
python probe.py \
  --target http://localhost:4000/graphql \
  --batch-size 300 \
  --depths 5 10 20 \
  --output my_report.json
```

---

## **RUN THE DEMO**

### **Full Integration Test**

```bash
cd tests
python integration_test.py
```

This runs 6 attack tests against both APIs:
1. **Unprotected API** — all succeed (vulnerable)
2. **Protected API** — all blocked (defended)

**Output is color-coded:**
- 🟢 GREEN: Test passed (expected result)
- 🔴 RED: Test failed (unexpected result)

---

## **COMMON ISSUES & FIXES**

### **Issue 1: Port Already in Use**

```
ERROR: Address already in use 0.0.0.0:4000
```

**Fix:**
```bash
# Find process using port 4000
netstat -ano | findstr :4000

# Kill it (replace <PID> with the number)
taskkill /PID <PID> /F

# Or change port in docker-compose.yml:
# Change "4000:4000" to "5000:4000"
```

### **Issue 2: MongoDB Connection Failed**

```
[DATABASE] ✗ Failed to connect to MongoDB
```

**Fix:**
```bash
# Check if MongoDB container is running
docker-compose ps

# If not, restart it
docker-compose restart mongodb

# Wait 10 seconds for it to be ready
docker-compose logs mongodb
```

### **Issue 3: Target API Crashes**

```
pymongo.errors.ServerSelectionTimeoutError
```

**Fix:**
```bash
# Ensure MongoDB started first
docker-compose logs mongodb

# Restart Target API after MongoDB is ready
docker-compose restart target-api
```

### **Issue 4: Middleware Returns 502**

```
"errors": [{"message": "Cannot reach backend API"}]
```

**Fix:**
```bash
# Ensure Target API is running
docker-compose ps

# Check logs
docker-compose logs target-api

# Restart both
docker-compose restart target-api middleware
```

### **Issue 5: Probe Tool Can't Connect**

```
[ERROR] Cannot reach target: Connection refused
```

**Fix:**
```bash
# Verify API is running
curl http://localhost:4000/

# Try with IP instead of localhost
python probe.py --target http://127.0.0.1:4000/graphql

# Check firewall isn't blocking ports
```

---

## **NEXT STEPS**

### **Explore the Codebase**

1. **Vulnerable API**: `target_api/app.py` — See what's intentionally vulnerable
2. **Offensive Tool**: `probe/probe.py` — See how attacks are orchestrated
3. **Defensive Middleware**: `middleware/middleware.py` & `middleware/rules.py` — See security rules
4. **Threat Model**: `report/threat_model.md` — MITRE ATT&CK mapping

### **Modify Rules**

Edit `middleware/rules.py` to change security policies:

```python
class Config:
    ALLOW_INTROSPECTION = False      # Toggle introspection
    MAX_QUERY_DEPTH = 5              # Adjust depth limit
    MAX_QUERY_COMPLEXITY = 100       # Adjust complexity
    ALLOW_BATCHING = False           # Toggle batching
    RATE_LIMIT_REQUESTS_PER_MINUTE = 60  # Adjust rate limit
```

Then restart:
```bash
docker-compose restart middleware
```

### **Add More Test Cases**

Edit `tests/integration_test.py` to add custom attack payloads.

---

## **TROUBLESHOOTING COMMANDS**

```bash
# See all container logs
docker-compose logs

# See specific service logs
docker-compose logs target-api
docker-compose logs middleware
docker-compose logs mongodb

# Restart services
docker-compose restart
docker-compose restart target-api

# Check resource usage
docker stats

# Remove everything and start fresh
docker-compose down -v
docker-compose up --build

# Debug mode: see query details
# Edit probe/probe.py and enable verbose logging
```

---

**You're now ready to run the GraphQL Security Auditor!** 🚀

Start with Docker Compose option and let me know if you hit any issues!
