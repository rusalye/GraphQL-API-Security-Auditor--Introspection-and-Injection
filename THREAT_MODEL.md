# Threat Model & Architecture Mapping

**Problem Statement:** #18 - GraphQL API Security Auditor (Introspection & Injection)
**Target Architecture:** Cloud-Native / Microservices (Application Layer)

Team 05:
Ananya Santosh- BL.EN.U4CSE23207
Anvita Arasavilli- BL.EN.U4CSE23208
Janhavi Nilesh Parate- BL.EN.U4CSE23224
Keerthi DA- BL.EN.U4CSE23233
Lakshmi Priya Subramanian- BL.EN.U4CSE23236

## 1. Threat Description
Our solution addresses the critical threats facing modern GraphQL APIs deployed in cloud-native environments. Unlike traditional REST APIs which rely on multiple distinct endpoints, a GraphQL API exposes a single endpoint that acts as a powerful query engine over the entire database. If deployed without strict security controls, this architecture presents a massive attack surface.

The primary threats addressed by our defensive middleware include:
1. **Schema Introspection (API Mapping):** Attackers use the `__schema` query to dump the exact structure of the database, revealing undocumented functionality and sensitive fields (e.g., `ssn`, `password`).
2. **Denial of Service (DoS) via Query Exhaustion:** Attackers exploit the graph nature of the API by nesting queries recursively (e.g., `user -> friend -> user -> friend`) or by sending large JSON arrays of batched queries. This exhausts CPU and bypasses rate limits.
3. **Resolver Injection Attacks:** Because GraphQL resolvers often pass arguments directly into backend database queries (MongoDB or SQL), an attacker can inject malicious strings (`' OR 1=1 --` or `{"$gt": ""}`) into query parameters to bypass authentication or dump arbitrary data.

## 2. MITRE ATT&CK Mapping
Our solution detects and mitigates the following specific adversarial techniques:

| Technique ID | Tactic | Description | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **T1190** | Initial Access | **Exploit Public-Facing Application**: The primary vector for targeting the GraphQL endpoint with malformed payloads and injections. | `R05` blocks regex patterns common to SQLi, NoSQLi, and SSTI in all incoming GraphQL payloads. |
| **T1596.005** | Reconnaissance | **Search Open Technical Databases (API Mapping)**: Abusing the introspection feature to map out the entire application schema. | `R01` detects and outright blocks any query attempting to access `__schema` or `__type` meta-fields. |
| **T1499.004** | Impact | **Endpoint DoS (Application Exploitation)**: Sending recursively nested queries to exhaust the API server's CPU and memory. | `R02` (Max Depth) and `R03` (Max Complexity) limit the recursive depth and structural cost of queries. |
| **T1498** | Impact | **Network Denial of Service**: Sending massive volumes of queries via JSON array batching to overwhelm the backend database. | `R04` outright rejects array-batched JSON requests, and `R07` enforces strict IP-based rate limiting. |

## 3. Defensive Constraints & Architecture Fit
Because this solution operates in a **Cloud-Native** environment (deployed as a Dockerised microservice), it is designed as a stateless reverse proxy. 
* **Layer of Intervention:** Application / API Layer.
* **Constraints Managed:** It sits seamlessly between the API Gateway and the Target Application, scaling horizontally without state collision. It operates quickly in-memory to prevent adding latency to legitimate cloud traffic.
