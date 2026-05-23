# GraphQL Security Auditor

**FoSC 23CSE313 Cyber Security Hackathon | Problem #18**  
**Team | Amrita School of Computing, Bengaluru | 2026**

---

## What This Solves

A GraphQL API deployed without security controls exposes the entire data schema to any attacker,
allows resource exhaustion via nested/batched queries, and accepts injected payloads in resolver
arguments. This project builds:

1. **An offensive probe tool** that finds all these weaknesses automatically
2. **A defensive middleware** that sits in front of any GraphQL API and blocks them

MITRE ATT&CK: `T1190 — Exploit Public-Facing Application`  
Architecture: Cloud-Native

---

## Repository Structure

```
graphql-security-auditor/
├── target_api/          # Deliberately vulnerable GraphQL API (the attack target)
│   ├── app.py           # GraphQL server with MongoDB backend
│   ├── Dockerfile
│   └── requirements.txt
├── probe/               # Offensive tool — 4 attack modules
│   ├── probe.py         # Main orchestrator (run this)
│   ├── introspect.py    # Schema dumper
│   ├── scanner.py       # Sensitive field detector
│   ├── batch_attack.py  # DoS via batching + deep nesting
│   ├── injection.py     # SQLi / NoSQL injection tester
│   └── requirements.txt
├── middleware/          # Defensive middleware — FastAPI reverse proxy
│   ├── middleware.py    # Main proxy server
│   ├── rules.py         # Security rules engine
│   ├── Dockerfile
│   └── requirements.txt
├── tests/
│   └── integration_test.py  # Full demo script (attack vs defence)
├── docker-compose.yml   # Orchestrates all services (MongoDB + API + Middleware)
└── README.md
```

---

## Quick Start (RECOMMENDED: Docker Compose)

### Option 1: Docker Compose (Easiest) ✅

**Prerequisites:** Docker and Docker Compose installed

```bash
# Start all services at once (MongoDB + Target API + Middleware)
docker-compose up

# Wait for output:
# [DATABASE] ✓ Connected to MongoDB
# INFO:     Uvicorn running on http://0.0.0.0:4000
# INFO:     Uvicorn running on http://0.0.0.0:8080
```

**Services running:**
- ✅ **MongoDB** on `localhost:27017` (persistent in `mongo_data/` volume)
- ✅ **Target API** on `http://localhost:4000/graphql`
- ✅ **Middleware** on `http://localhost:8080/graphql`

**Verify services are running:**

```bash
# In another terminal:

# Check Target API
curl http://localhost:4000/

# Check Middleware health
curl http://localhost:8080/health

# Verify MongoDB (requires mongosh or mongo CLI)
mongosh localhost:27017/graphql_api
> db.users.find()
```

**Run the probe (in another terminal):**

```bash
cd probe
pip install -r requirements.txt

# Attack VULNERABLE target directly (port 4000)
python probe.py --target http://localhost:4000/graphql

# Attack PROTECTED target through middleware (port 8080)
python probe.py --target http://localhost:8080/graphql
```

**Stop all services:**

```bash
docker-compose down

# To also delete MongoDB data (WARNING: data loss):
docker-compose down -v
```

---

### Option 2: Manual Setup (3 Terminals)

If you prefer running without Docker:

**Terminal 1 — Start MongoDB:**

```bash
# Requires MongoDB server installed locally or via Docker
mongod                 # or: docker run -d -p 27017:27017 mongo:latest
```

**Terminal 2 — Start the Vulnerable Target API:**

```bash
cd target_api
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 4000 --reload
```

Verify: `curl http://localhost:4000/` → should return JSON

**Terminal 3 — Start the Security Middleware:**

```bash
cd middleware
pip install -r requirements.txt
export TARGET_GRAPHQL_URL=http://localhost:4000/graphql
uvicorn middleware:app --host 0.0.0.0 --port 8080 --reload
```

Verify: `curl http://localhost:8080/health` → shows active rule config

**Terminal 4 — Run the Probe Tool:**

```bash
cd probe
pip install -r requirements.txt

# Attack the VULNERABLE target directly (all attacks succeed)
python probe.py --target http://localhost:4000/graphql

# Attack THROUGH THE MIDDLEWARE (all attacks blocked)
python probe.py --target http://localhost:8080/graphql
```

---

## Database

### MongoDB Setup

**Auto-seeded data:**
- Database: `graphql_api`
- Collection: `users` (2 test users: alice, bob)
- Collection: `posts` (2 test posts)
- Connection string: `mongodb://localhost:27017`

**Collections are automatically created and seeded when the target API starts.**

To inspect the database:

```bash
# Connect via mongosh
mongosh localhost:27017/graphql_api

# List all collections
> show collections

# View users
> db.users.find()

# View posts
> db.posts.find()

# Count documents
> db.users.countDocuments()
```

### Persistent Data

Data is stored in a named Docker volume: `mongo_data:`

- **Survives container restarts** (`docker-compose down` then `docker-compose up`)
- **Deleted only with** `docker-compose down -v`

---

## Demo Script (Hackathon Presentation)

```bash
cd tests
pip install -r ../probe/requirements.txt  # Install dependencies
python integration_test.py
```

This runs **6 attack tests** twice:
- **Round 1** against the unprotected API → all succeed (vulnerable)
- **Round 2** through the middleware → all blocked (defended)

Output is colour-coded PASS/FAIL per test.

---

## What the Probe Tool Tests

| Module | Attack | What It Finds |
|--------|--------|---------------|
| `introspect.py` | Introspection query | Full schema dump, all types, all fields |
| `scanner.py` | Sensitive field analysis | `password`, `token`, `ssn`, `api_key`, `credit_card` exposure |
| `batch_attack.py` | Array batching | 100 queries in 1 HTTP request (rate limit bypass) |
| `batch_attack.py` | Deep nesting | 50-level recursive query (CPU exhaustion) |
| `injection.py` | SQL injection | `' OR 1=1 --`, UNION, time-based |
| `injection.py` | NoSQL injection | `$gt`, `$ne`, `$where` MongoDB operators |

---

## What the Middleware Blocks

| Rule | Policy | Blocks |
|------|--------|--------|
| R01 | Introspection disabled in production | `__schema`, `__type` queries |
| R02 | Max query depth: 5 | Nested queries beyond 5 levels |
| R03 | Max complexity: 100 fields | Expensive field-heavy queries |
| R04 | Array batching disabled | JSON array requests |
| R05 | Injection pattern detection | SQLi/NoSQLi patterns in args |
| R07 | Rate limit: 60 req/min per IP | Automated scanning tools |

---

## Live Dashboard

Once the middleware is running:

```
http://localhost:8080/stats/dashboard   ← Live block log (auto-refreshes)
http://localhost:8080/stats             ← JSON stats
http://localhost:8080/health            ← Current rule config
```

---

## Runtime Config (Toggle Rules Live for Demo)

```bash
# Edit middleware/rules.py Config class to change rules:

class Config:
    ALLOW_INTROSPECTION = False              # Set True to allow introspection in dev
    MAX_QUERY_DEPTH = 5                      # Increase to allow deeper queries
    MAX_QUERY_COMPLEXITY = 100               # Increase for more field selections
    ALLOW_BATCHING = False                   # Set True to allow batching
    RATE_LIMIT_REQUESTS_PER_MINUTE = 60      # Adjust rate limit
```

Then restart:
```bash
docker-compose restart middleware
```

Or manually:
```bash
cd middleware
uvicorn middleware:app --reload  # Auto-reloads on file changes
```

---

## Probe Tool Commands

Run attacks with different configurations:

```bash
cd probe

# Basic attack (100 queries in batch, depths 2-50)
python probe.py --target http://localhost:4000/graphql

# Custom batch size
python probe.py --target http://localhost:4000/graphql --batch-size 500

# Custom nesting depths
python probe.py --target http://localhost:4000/graphql --depths 2 5 10 15 30

# Skip DoS tests (useful when testing protected API)
python probe.py --target http://localhost:8080/graphql --skip-dos

# Custom output file
python probe.py --target http://localhost:4000/graphql --output my_report.json

# Combined options
python probe.py \
  --target http://localhost:8080/graphql \
  --batch-size 200 \
  --depths 5 10 20 \
  --skip-dos \
  --output middleware_attack_report.json
```

**Output files:**
- `report.json` — Machine-readable attack results
- Console output — Colored, human-readable results

---

## Troubleshooting

### MongoDB not connecting

```
Error: Cannot connect to mongodb://mongodb:27017
```

**Solution:**
```bash
# Ensure MongoDB container is running
docker-compose ps  # Check if mongodb service shows "Up"

# If not, restart
docker-compose restart mongodb

# Wait a few seconds for MongoDB to be ready
docker-compose logs mongodb
```

### Target API crashes on startup

```
pymongo.errors.ServerSelectionTimeoutError: No servers found yet
```

**Solution:**
```bash
# MongoDB might not be ready yet. Wait and retry:
docker-compose logs target-api

# Restart target-api after MongoDB is healthy
docker-compose restart target-api
```

### Middleware returns 502 (Bad Gateway)

```
"errors": [{"message": "Cannot reach backend API at http://target-api:4000/graphql"}]
```

**Solution:**
```bash
# Ensure target-api is running
docker-compose ps

# Check target-api logs
docker-compose logs target-api

# Restart both
docker-compose restart target-api middleware
```

### Port already in use (e.g., 4000 or 8080)

```
ERROR: Address already in use 0.0.0.0:4000
```

**Solution:**
```bash
# Option 1: Kill the process using that port
# On Windows:
netstat -ano | findstr :4000
taskkill /PID <PID> /F

# Option 2: Change the port in docker-compose.yml
# Edit: "4000:4000" to "5000:4000"
```

### Probe tool cannot connect to API

```
[ERROR] Cannot reach target: Connection refused
```

**Solution:**
```bash
# Ensure services are running
docker-compose ps

# Test connectivity manually
curl http://localhost:4000/
curl http://localhost:8080/health

# If using Windows, try 127.0.0.1 instead of localhost
python probe.py --target http://127.0.0.1:4000/graphql
```

### MongoDB data persists but I want to reset

```bash
# Delete the persistent volume (WARNING: deletes all data)
docker-compose down -v

# Restart with fresh data
docker-compose up
```

### How to verify everything is working

```bash
# 1. Check all containers are running
docker-compose ps

# 2. Check MongoDB has data
mongosh localhost:27017/graphql_api
> db.users.count()  # should show 2

# 3. Check Target API responds
curl http://localhost:4000/

# 4. Check Middleware is proxying
curl http://localhost:8080/health

# 5. Check Middleware blocks introspection
curl -X POST http://localhost:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
# Should return: "Introspection is disabled in production"

# 6. Run probe tool
cd probe && python probe.py --target http://localhost:4000/graphql
```

---

## Team Roles

| Person | Component | Files |
|--------|-----------|-------|
| Person 1 | Probe — Introspection + Schema Scanner | `probe/introspect.py`, `probe/scanner.py` |
| Person 2 | Probe — Batch + Injection attacks | `probe/batch_attack.py`, `probe/injection.py`, `probe/probe.py` |
| Person 3 | Vulnerable Target API | `target_api/app.py` |
| Person 4 | Defensive Middleware | `middleware/middleware.py`, `middleware/rules.py` |
| Person 5 | Integration tests + Documentation | `tests/integration_test.py`, `README.md`, `report/threat_model.md` |

---

## Known Limitations

- Depth/complexity calculation uses brace-counting, not full AST parsing (sufficient for demo)
- Rate limiter is in-memory only (resets on restart — use Redis for production)
- Injection detection is signature-based, not semantic (evadable with encoding)
- No authentication on the `/config` endpoint (demo only)

---

## Dependencies

```
# target_api
strawberry-graphql[fastapi], fastapi, uvicorn

# probe
requests

# middleware
fastapi, uvicorn, httpx
```
