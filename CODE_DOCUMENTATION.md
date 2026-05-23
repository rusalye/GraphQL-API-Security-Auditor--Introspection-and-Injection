# Code Documentation & Structure

**Problem Statement:** #18 - GraphQL API Security Auditor (Introspection & Injection)
**Target Architecture:** Cloud-Native / Microservices (Application Layer)

Team 05:
Ananya Santosh- BL.EN.U4CSE23207
Anvita Arasavilli- BL.EN.U4CSE23208
Janhavi Nilesh Parate- BL.EN.U4CSE23224
Keerthi DA- BL.EN.U4CSE23233
Lakshmi Priya Subramanian- BL.EN.U4CSE23236


This document serves as a high-level overview of the codebase architecture, acting as an extension of the inline comments provided throughout the Python source files. The project is strictly scoped to the **Application / API Layer**, as per the hackathon's "Layer of Intervention" model.

## 1. Directory Structure

```text
graphql-security-auditor/
├── target_api/          # The vulnerable GraphQL target
│   └── app.py           
├── middleware/          # The defensive proxy
│   ├── middleware.py    
│   └── rules.py         
├── probe/               # The offensive testing tool
│   ├── probe.py         
│   ├── introspect.py    
│   ├── scanner.py       
│   ├── batch_attack.py  
│   └── injection.py     
├── tests/
│   └── integration_test.py
└── docker-compose.yml
```

## 2. Defensive Track: Middleware
The middleware acts as the primary layer of defence, intercepting and sanitising all incoming API traffic before it reaches the backend.

### `middleware/middleware.py`
* **Purpose**: This is the core FastAPI reverse-proxy server.
* **Key Mechanisms**:
    * **`graphql_proxy`**: The main POST route that receives all `/graphql` requests. It parses the JSON payload and passes it to the rules engine (`validate_request`). If flagged as malicious, it returns a `400 Bad Request` or `429 Too Many Requests`. Otherwise, it uses `httpx.AsyncClient` to asynchronously forward the request to the `TARGET_GRAPHQL_URL`.
    * **State Management**: Maintains an in-memory `stats` dictionary to track blocks per IP, blocks per rule, and a history of recent blocked requests for the `/stats/dashboard` HTML template.

### `middleware/rules.py`
* **Purpose**: The security rules engine.
* **Key Mechanisms**:
    * **`Config` class**: Centralised policy definitions (e.g., `ALLOW_INTROSPECTION`, `MAX_QUERY_DEPTH`).
    * **`RateLimiter` class**: Implements a sliding window rate limit using an in-memory dictionary tracking IP timestamps.
    * **`_calculate_depth` / `_calculate_complexity`**: Uses heuristic methods (brace-counting and regex selection counting) instead of a full AST parser for extremely rapid, low-latency evaluation.
    * **`validate_request`**: The master validation function that evaluates incoming queries against all active rules (`R01`-`R07`) sequentially and stops at the first failure.

## 3. Offensive Track: Probe
The probe is an automated threat emulation framework split into four attack modules.

### `probe/probe.py`
* **Purpose**: The master orchestrator. Uses `argparse` for CLI flags (`--target`, `--batch-size`, `--skip-dos`) and executes the four attack phases sequentially, aggregating their results into a final `report.json` and a terminal summary.

### `probe/introspect.py`
* **Purpose**: Executes `__schema` queries to dump the API.
* **Key Mechanisms**: Contains a heavily nested, industry-standard Introspection query string. The `parse_schema` function transforms the raw JSON response into a flat, readable dictionary mapping types to their respective fields and arguments.

### `probe/scanner.py`
* **Purpose**: Detects sensitive data exposure.
* **Key Mechanisms**: Iterates through the parsed schema from `introspect.py`. The `_classify_field` function uses regex and exact-string matching against predefined severity wordlists (`HIGH_SENSITIVITY`, `MEDIUM_SENSITIVITY`) to flag dangerous endpoints.

### `probe/batch_attack.py`
* **Purpose**: Tests for Denial of Service (DoS) vulnerabilities.
* **Key Mechanisms**:
    * **`run_batching_attack`**: Builds a massive JSON array payload to bypass rate limits.
    * **`run_nesting_attack`**: Uses a recursive loop generator `build_nested_query` to craft highly nested query strings, verifying server CPU exhaustion limits by capturing timeout exceptions.

### `probe/injection.py`
* **Purpose**: Automates vulnerability fuzzing on string arguments.
* **Key Mechanisms**: 
    * Contains dictionaries of known payloads for SQLi, NoSQLi, SSTI, and Path Traversal.
    * The `test_injection_on_field` runner compares the byte-size, response time, and error objects of a "baseline" clean request against the injected payload to heuristically flag potential vulnerabilities.

## 4. Vulnerable Target: `target_api/app.py`
* **Purpose**: A deliberately insecure GraphQL server built using `Strawberry`.
* **Key Mechanisms**:
    * Uses a direct MongoDB driver (`pymongo`). If a database instance is unavailable, it gracefully fails and simulates in-memory collections.
    * The `search_users` resolver explicitly takes a raw string and implements dangerous direct-string matching logic to actively simulate NoSQL/SQL injection behaviors (e.g., returning all users if `{"$gt": ""}` is passed).
    * Strawberry's `auto_camel_case` is disabled to ensure 1-to-1 payload mapping with the offensive probe testing suite.
