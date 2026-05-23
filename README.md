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
│   ├── app.py
│   └── requirements.txt
├── probe/               # Offensive tool — 4 attack modules
│   ├── probe.py         # Main orchestrator (run this)
│   ├── introspect.py    # Schema dumper
│   ├── scanner.py       # Sensitive field detector
│   ├── batch_attack.py  # DoS via batching + deep nesting
│   └── injection.py     # SQLi / NoSQLi tester
├── middleware/          # Defensive middleware — FastAPI reverse proxy
│   ├── middleware.py    # Main proxy server
│   └── rules.py        # Security rules engine
├── tests/
│   └── integration_test.py  # Full demo script (attack vs defence)
└── docker-compose.yml
```

---

## Quick Start (3 Terminals)

### Terminal 1 — Start the Vulnerable Target API

```bash
cd target_api
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 4000 --reload
```

Verify: `curl http://localhost:4000/` → should return JSON

### Terminal 2 — Start the Security Middleware

```bash
cd middleware
pip install -r requirements.txt
uvicorn middleware:app --host 0.0.0.0 --port 8080 --reload
```

Verify: `curl http://localhost:8080/health` → shows active rule config

### Terminal 3 — Run the Probe Tool

```bash
cd probe
pip install -r requirements.txt

# Attack the VULNERABLE target directly (all attacks succeed)
python probe.py --target http://localhost:4000/graphql

# Attack THROUGH THE MIDDLEWARE (all attacks blocked)
python probe.py --target http://localhost:8080/graphql
```

---

## Demo Script (Hackathon Presentation)

```bash
cd tests
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
# Enable introspection temporarily (dev mode)
curl -X POST http://localhost:8080/config \
  -H "Content-Type: application/json" \
  -d '{"allow_introspection": true}'

# Tighten depth limit
curl -X POST http://localhost:8080/config \
  -d '{"max_depth": 3}'

# Restore defaults
curl -X POST http://localhost:8080/config \
  -d '{"allow_introspection": false, "max_depth": 5}'
```

---

## OR: Run with Docker Compose

```bash
docker-compose up --build
```

- Target API: `http://localhost:4000/graphql`
- Middleware:  `http://localhost:8080/graphql`

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
