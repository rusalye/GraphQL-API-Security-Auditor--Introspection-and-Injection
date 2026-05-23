# Threat Model — GraphQL API Security Auditor

**Problem Statement #18 | FoSC 23CSE313 | Amrita School of Computing, Bengaluru**

---

## 1. Threat Scenario

A Cloud-Native organisation has deployed a GraphQL API (internal SaaS product) without security
controls. GraphQL's flexibility — a feature for developers — becomes a liability when misconfigured:

- The **schema** (full data model) is publicly discoverable via introspection
- **Sensitive fields** (passwords, tokens, PII) are included in types without field-level auth
- **Batching and deep nesting** allow a single HTTP request to trigger thousands of DB queries
- **Resolver arguments** accept raw user input without sanitisation

---

## 2. MITRE ATT&CK Mapping

| Phase | Technique | ID | How |
|-------|-----------|-----|-----|
| Reconnaissance | Gather Victim Application Info | T1590.005 | Introspection exposes full schema |
| Initial Access | Exploit Public-Facing Application | **T1190** | Injection via resolver args |
| Discovery | Data from Information Repositories | T1213 | Schema reveals data model |
| Exfiltration | Automated Exfiltration | T1020 | Batch queries dump entire DB |
| Impact | Endpoint Denial of Service | T1499 | Deep nesting causes CPU exhaustion |

**Primary Technique: T1190 — Exploit Public-Facing Application**

---

## 3. Attack Surface

```
Internet
   │
   ▼
[GraphQL API :4000/graphql]
   │
   ├─ POST {"query": "{ __schema { ... } }"}
   │         └─ Returns full data model to anyone
   │
   ├─ POST [{"query": "..."}, {"query": "..."}, ...]   (×100)
   │         └─ Server executes all 100 → resource exhaustion
   │
   ├─ POST {"query": "{ user { friend { friend { friend { ... } } } } }"}
   │         └─ Exponential resolver calls → CPU exhaustion
   │
   └─ POST {"query": "{ search(q: \"' OR 1=1 --\") { password token } }"}
             └─ Injection reaches DB → data breach
```

---

## 4. Vulnerabilities Demonstrated (Offensive Phase)

### V1 — Introspection Enabled (CRITICAL)
- **What**: `__schema` query dumps every type, field, argument, and relationship
- **Impact**: Attacker maps entire API in seconds, knows what to target
- **Demonstrated by**: `probe/introspect.py`

### V2 — Sensitive Fields in Schema (CRITICAL)
- **What**: `User` type exposes `password`, `token`, `ssn`, `api_key`, `credit_card`
- **Impact**: Any authenticated (or unauthenticated) client can query these fields
- **Demonstrated by**: `probe/scanner.py`

### V3 — Array Batching (HIGH)
- **What**: GraphQL spec allows sending `[{query1}, {query2}, ...]` as a JSON array
- **Impact**: Bypass rate limits; 100 requests become 1 HTTP call; DoS possible
- **Demonstrated by**: `probe/batch_attack.py`

### V4 — Unbounded Query Depth (HIGH)
- **What**: No limit on recursive field nesting
- **Impact**: `friend { friend { friend { ... }}}` × 50 saturates the server
- **Demonstrated by**: `probe/batch_attack.py`

### V5 — Injection via Resolver Arguments (HIGH)
- **What**: String arguments passed directly to business logic without sanitisation
- **Impact**: SQL/NoSQL injection, returns all users on `' OR 1=1 --`
- **Demonstrated by**: `probe/injection.py`

---

## 5. Defences Implemented (Defensive Phase)

### D1 — Introspection Disabled (mitigates V1)
- Block all queries containing `__schema`, `__type`
- Configurable via `POST /config {"allow_introspection": true}` for dev environments
- Industry standard: Apollo Server, Hasura, PostGraphile all support this

### D2 — Query Depth Limiting (mitigates V4)
- Count brace depth of incoming query body
- Reject queries exceeding depth 5 with HTTP 400 + structured error
- Configurable threshold

### D3 — Query Complexity Scoring (supports D2)
- Count total field selections as a complexity proxy
- Reject queries exceeding budget of 100 fields
- Prevents wide queries that avoid depth limits

### D4 — Batch Request Blocking (mitigates V3)
- Detect JSON array body at request parse time
- Reject with HTTP 400 before any query execution
- Allows enabling for trusted internal services via config

### D5 — Injection Pattern Detection (mitigates V5)
- Regex patterns against raw query body before forwarding
- Detects: SQLi (`OR 1=1`, `UNION SELECT`, `SLEEP()`), NoSQLi (`$gt`, `$where`), SSTI (`{{}}`)
- Not a replacement for parameterised resolvers — defence in depth

### D6 — Rate Limiting (defence in depth)
- Sliding window: 60 requests per IP per minute
- Returns HTTP 429 with Retry-After context
- In-memory for demo; production uses Redis

---

## 6. Architecture Fit (Cloud-Native)

The middleware deploys as a **sidecar container** or **API Gateway plugin** — no changes to the
existing GraphQL service required.

```
[Client]
   ↓
[Load Balancer]
   ↓
[Security Middleware — This Project] ← deployed as a container
   ↓
[GraphQL API]
   ↓
[Database]
```

Production deployment: Kubernetes sidecar in the same Pod as the GraphQL service, or as an
Envoy filter in a service mesh (Istio).

---

## 7. What a Full Production Version Would Add

- AST-based depth/complexity analysis (using `graphql-core` library) — more accurate than regex
- Field-level authorisation middleware (block `password` field unless `role == admin`)
- Persisted query allowlisting (only pre-registered query hashes accepted)
- Redis-backed rate limiter (survives restarts, works across multiple instances)
- OpenTelemetry metrics export to existing observability stack
- Automated schema change diffing (alert when new sensitive fields appear)

---

## 8. References

- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- HackTricks GraphQL: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
- MITRE T1190: https://attack.mitre.org/techniques/T1190/
- Apollo Security Best Practices: https://www.apollographql.com/docs/apollo-server/security/
