# Project Knowledge & Hackathon Demo Guide

This document is your team's "cheat sheet" for the hackathon presentation. It outlines exactly what was required for Problem Statement #18, how we delivered it, and a strict 5-minute script for your final demonstration.

---

## 1. Expected vs. Delivered

| Requirement (Problem #18) | How We Delivered It | Status |
| :--- | :--- | :--- |
| **Track** | We built both the offensive probe and defensive middleware. | ✅ Done |
| **Architecture Fit** | Deployed via Docker containers (Cloud-Native architecture). | ✅ Done |
| **Offensive Tool: Introspection** | `probe/introspect.py` dumps the schema and parses it cleanly. | ✅ Done |
| **Offensive Tool: Sensitive Fields** | `probe/scanner.py` runs wordlist heuristics to find PII. | ✅ Done |
| **Offensive Tool: Batch/DoS** | `probe/batch_attack.py` executes array batching and recursive depth DoS. | ✅ Done |
| **Offensive Tool: Injection** | `probe/injection.py` systematically tests SQLi, NoSQLi, SSTI payloads against string arguments. | ✅ Done |
| **Defensive Tool: Middleware** | `middleware/middleware.py` sits in front of the target as a transparent proxy. | ✅ Done |
| **Defensive Rules** | `rules.py` enforces depth limits, complexity limits, disabled introspection, and regex injection blocking. | ✅ Done |
| **Deliverable format** | Containerised lab, version-controlled code, README, Threat Model, Architecture diagram. | ✅ Done |

---

## 2. The 5-Minute Demo Script

*The Hackathon Student Guide demands a strict 5-minute structure for the final presentation. Follow this exactly.*

### 0:00 – 1:00 | Context
**Speaker 1 (Lead Architect):**
"Good afternoon. We tackled Problem Statement #18: The GraphQL API Security Auditor. The primary threat here is the inherent nature of GraphQL—unlike REST, a single endpoint exposes the entire data schema and backend graph. If deployed without security, attackers can map the API, discover sensitive PII, exhaust resources through nested queries, and inject malicious payloads into resolvers. 
Because this is a Cloud-Native microservice environment, failure looks like this: a single compromised endpoint giving complete database access. We built a dual solution: an automated attack probe to find these holes, and a stateless middleware proxy to block them."

### 1:00 – 3:00 | Live Demo
**Speaker 2 (Primary Builder):**
"Let's look at the attack first. I’m running our Python probe tool against the unprotected target API."
*(Run the probe against Port 4000 in the terminal).*
"As you can see, the probe successfully uses introspection to map the API, flags the exposed `password` and `ssn` fields, successfully executes a 50-level deep nesting DoS attack, and confirms NoSQL injection on the `search_users` query."

"Now, we simulate our deployment. We drop our defensive middleware in front of the API."
*(Run the probe against Port 8080).*
"The exact same attacks fail. Introspection is blocked (Rule R01). The deep nesting attack is rejected for exceeding maximum depth (Rule R02). And the NoSQL injection payload is caught by our regex engine (Rule R05)."
*(Switch to the browser and refresh `http://localhost:8080/stats/dashboard`).*
"Simultaneously, our SOC team has full visibility. Here is the live dashboard showing every blocked attack, the attacker's IP, and the triggered security rule."

### 3:00 – 4:00 | Architecture Fit
**Speaker 1 (Lead Architect):**
"Our solution is strictly scoped to the Application Layer in a Cloud-Native architecture. 
If you hired us to deploy this tomorrow, the pre-requisite is minimal: we deploy our FastAPI middleware as a sidecar container or ingress proxy directly before your GraphQL server. 
It requires no agent installations on the host, no root access, and it scales horizontally. Configuration is declarative, and logs can be natively forwarded to an existing SIEM like Elastic or Splunk."

### 4:00 – 5:00 | Limitations and Next Steps
**Speaker 1 (Lead Architect):**
"To be intellectually honest, our 6-hour implementation has limitations. 
First, our depth and complexity calculations use fast regex heuristics rather than a full Abstract Syntax Tree (AST) parser. A determined attacker might bypass this with complex fragment usage. 
Second, our rate-limiting and dashboards are currently in-memory. 
Our next steps for production would be offloading state to a Redis cluster, implementing semantic AST parsing (like `graphql-core`), and replacing signature-based injection blocking with strict database parameterization at the target level."
