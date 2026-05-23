# QUICK START — TL;DR

Copy-paste these commands in order. Takes ~2 minutes.

---

## **ONE-LINER SETUP** 

```bash
# 1. Navigate to project folder
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection

# 2. Start everything (Docker + MongoDB + API + Middleware)
docker-compose up

# WAIT for these 3 messages (takes ~30 seconds):
# mongodb  | [initandlisten] waiting for connections on port 27017
# target-api  | INFO:     Uvicorn running on http://0.0.0.0:4000
# middleware  | INFO:     Uvicorn running on http://0.0.0.0:8080
```

---

## **IN NEW TERMINAL(S):**

### **Option A: Attack Vulnerable API (NO protection)**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\probe
pip install -r requirements.txt
python probe.py --target http://localhost:4000/graphql
```

**Result:** ✗ ALL ATTACKS SUCCEED (CRITICAL RISK)

---

### **Option B: Attack Protected API (With middleware)**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\probe
pip install -r requirements.txt
python probe.py --target http://localhost:8080/graphql --skip-dos
```

**Result:** ✓ ALL ATTACKS BLOCKED (LOW RISK)

---

### **Option C: Run Full Demo (Attack vs Defense)**

```bash
cd c:\Users\anvit\Desktop\GraphQL-API-Security-Auditor--Introspection-and-Injection\tests
pip install -r ../probe/requirements.txt
python integration_test.py
```

**Result:** Side-by-side comparison of vulnerable vs protected

---

## **CHECK MONGODB DATA** (Optional)

```bash
mongosh localhost:27017/graphql_api
> db.users.find()
> db.posts.find()
> exit
```

---

## **CLEANUP**

```bash
# Back in Terminal 1 (where docker-compose is running)
# Press Ctrl+C to stop all services

docker-compose down
```

---

## **ALL AVAILABLE COMMANDS**

```bash
# View all attack options
python probe.py --help

# Custom batch size
python probe.py --target http://localhost:4000/graphql --batch-size 500

# Custom nesting depths
python probe.py --target http://localhost:4000/graphql --depths 2 5 10 15 30

# Skip slow DoS tests
python probe.py --target http://localhost:8080/graphql --skip-dos

# Custom output file
python probe.py --target http://localhost:4000/graphql --output my_report.json

# See all services
docker-compose ps

# See logs
docker-compose logs

# Restart specific service
docker-compose restart middleware

# Reset everything
docker-compose down -v
docker-compose up --build
```

---

## **EXPECTED OUTPUTS**

### **Attack on :4000 (Vulnerable)**
```
✗ Introspection exposed
✗ Sensitive fields: password, token, ssn, api_key exposed
✗ Batch attack: 100 queries executed
✗ Deep nesting: Exponential resolver calls
✗ Injection: ' OR 1=1 -- returns all users
🔴 OVERALL RISK: CRITICAL
```

### **Attack on :8080 (Protected)**
```
✓ Introspection blocked
✓ Deep nesting blocked
✓ Injection patterns blocked
🟢 OVERALL RISK: LOW
```

### **View Dashboard**
```
http://localhost:8080/stats/dashboard
```

---

**That's it! You're ready.** 🚀

For detailed help, see `SETUP.md`
