# Architecture Diagram

**Problem Statement:** #18 - GraphQL API Security Auditor (Introspection & Injection)
**Target Architecture:** Cloud-Native / Microservices (Application Layer)

Team 05:
Ananya Santosh- BL.EN.U4CSE23207
Anvita Arasavilli- BL.EN.U4CSE23208
Janhavi Nilesh Parate- BL.EN.U4CSE23224
Keerthi DA- BL.EN.U4CSE23233
Lakshmi Priya Subramanian- BL.EN.U4CSE23236

---

The diagram below illustrates the flow of traffic in the target cloud-native architecture. Our defensive solution (the Middleware Proxy) intercepts all traffic between external clients and the vulnerable internal microservices.

```mermaid
flowchart TD
    %% Define Styles
    classDef attacker fill:#f85149,stroke:#b31d28,stroke-width:2px,color:#fff
    classDef legitimate fill:#2ea043,stroke:#238636,stroke-width:2px,color:#fff
    classDef middleware fill:#1f6feb,stroke:#1158c7,stroke-width:2px,color:#fff
    classDef backend fill:#8b949e,stroke:#6e7681,stroke-width:2px,color:#fff
    classDef database fill:#d29922,stroke:#9e6a03,stroke-width:2px,color:#fff

    %% Nodes
    A1["Attacker (Probe Tool)"]:::attacker
    A2["Legitimate Client"]:::legitimate
    
    subgraph "Docker Bridge Network (graphql-net)"
        B["Defensive Middleware Proxy\nFastAPI (Port 8080)"]:::middleware
        C["Target API (Vulnerable)\nStrawberry + FastAPI (Port 4000)"]:::backend
        D[("MongoDB\nPersistent Storage (Port 27017)")]:::database
        
        %% Middleware Internal Flow
        subgraph "Middleware Security Engine"
            B1{"R07: Rate Limiter"}
            B2{"R04: Batching Blocker"}
            B3{"R01: Introspection Blocker"}
            B4{"R05: Injection Detection"}
            B5{"R02 & R03: Depth/Complexity"}
            B1 -->|Pass| B2 -->|Pass| B3 -->|Pass| B4 -->|Pass| B5
        end
    end

    %% External Connections
    A1 -- "Malicious Payloads\n(DoS, SQLi, Introspection)" --> B
    A2 -- "Normal GraphQL Queries" --> B

    %% Internal Connections
    B --> B1
    B5 -- "Proxy Forward\n(Clean Traffic)" --> C
    
    %% Blocked Paths
    B1 -. "Drop (429)" .-> Block1((Blocked))
    B2 -. "Drop (400)" .-> Block1
    B3 -. "Drop (400)" .-> Block1
    B4 -. "Drop (400)" .-> Block1
    B5 -. "Drop (400)" .-> Block1
    
    style Block1 fill:#f85149,stroke:#b31d28,stroke-width:2px,color:#fff
    
    %% Backend Connection
    C -- "PyMongo Driver" --> D
```

## How It Integrates
1. **Network Layer**: The entire system is deployed via Docker Compose. The `target-api` and `mongodb` do not expose their ports to the open internet in a production setting; they are only reachable via the Docker bridge network.
2. **Reverse Proxy**: The `middleware` exposes port 8080 to the public. It acts as the single ingress point.
3. **Stateless Enforcement**: The middleware holds no database connection itself. It relies entirely on in-memory heuristics and request parsing to rapidly validate payloads before forwarding them downstream.
4. **Resilience**: If the middleware were to go down, external traffic simply cannot reach the target API, meaning it fails securely (fail-closed) from an external perspective, protecting the vulnerable backend.
