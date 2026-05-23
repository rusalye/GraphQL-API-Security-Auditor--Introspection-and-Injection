"""
middleware/middleware.py
GraphQL Security Middleware — FastAPI Reverse Proxy

Sits between the attacker/client and the real GraphQL API.
Intercepts every /graphql request, runs security rules,
and either BLOCKS it (with a structured error) or FORWARDS it.

Architecture:
  [Client] → [This Middleware :8080/graphql] → [Target API :4000/graphql]

Endpoints:
  POST /graphql     — main proxy + security enforcement
  GET  /graphql     — GraphiQL passthrough
  GET  /health      — health check
  GET  /stats       — live enforcement statistics dashboard
  POST /config      — runtime rule configuration (toggle rules on/off)

Run with:
  uvicorn middleware:app --host 0.0.0.0 --port 8080 --reload
"""

import httpx
import json
import time
import os
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from rules import validate_request, Config

# ── App Setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="GraphQL Security Middleware",
    description="Defensive layer for GraphQL APIs — Problem #18",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Target backend URL ────────────────────────────────────────────────────────
TARGET_GRAPHQL_URL = os.getenv("TARGET_GRAPHQL_URL", "http://localhost:4000/graphql")

# ── Live Statistics ───────────────────────────────────────────────────────────

stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "forwarded_requests": 0,
    "blocks_by_rule": defaultdict(int),
    "blocks_by_ip": defaultdict(int),
    "recent_blocks": [],        # last 20 blocked requests
    "start_time": datetime.now(timezone.utc).isoformat(),
}


def record_block(rule_id: str, reason: str, client_ip: str, query_preview: str):
    stats["blocked_requests"] += 1
    stats["blocks_by_rule"][rule_id] += 1
    stats["blocks_by_ip"][client_ip] += 1
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_id": rule_id,
        "reason": reason,
        "client_ip": client_ip,
        "query_preview": query_preview[:120] + "..." if len(query_preview) > 120 else query_preview,
    }
    stats["recent_blocks"].insert(0, entry)
    stats["recent_blocks"] = stats["recent_blocks"][:20]  # keep last 20
    
    # Console log
    print(f"[MIDDLEWARE] 🚫 BLOCKED [{rule_id}] from {client_ip}: {reason}")


def record_forward(client_ip: str):
    stats["forwarded_requests"] += 1
    print(f"[MIDDLEWARE] ✅ FORWARDED from {client_ip}")


# ── Main Proxy Endpoint ───────────────────────────────────────────────────────

@app.post("/graphql")
async def graphql_proxy(request: Request):
    """
    Main security enforcement point.
    1. Parse incoming body
    2. Run all security rules
    3. Block with 400/403 OR forward to real API
    """
    stats["total_requests"] += 1
    
    client_ip = request.client.host if request.client else "unknown"
    
    # Parse request body
    try:
        raw_body = await request.body()
        body = json.loads(raw_body)
    except (json.JSONDecodeError, Exception) as e:
        return JSONResponse(
            status_code=400,
            content={"errors": [{"message": f"Invalid JSON body: {str(e)}"}]},
        )
    
    # Extract query preview for logging
    if isinstance(body, dict):
        query_preview = body.get("query", "")[:200]
    elif isinstance(body, list):
        query_preview = f"[BATCH: {len(body)} queries]"
    else:
        query_preview = str(body)[:200]
    
    # ── Run Security Rules ────────────────────────────────────────────────────
    is_blocked, blocking_rule, all_results = validate_request(body, client_ip)
    
    if is_blocked and blocking_rule:
        record_block(
            rule_id=blocking_rule.rule_id,
            reason=blocking_rule.reason,
            client_ip=client_ip,
            query_preview=query_preview,
        )
        
        http_status = 429 if blocking_rule.rule_id == "R07" else 400
        
        return JSONResponse(
            status_code=http_status,
            content={
                "errors": [
                    {
                        "message": blocking_rule.reason,
                        "extensions": {
                            "code": f"SECURITY_RULE_{blocking_rule.rule_id}",
                            "rule": blocking_rule.rule_id,
                            "severity": blocking_rule.severity,
                            "details": blocking_rule.details,
                        },
                    }
                ],
                "blocked": True,
                "rule": blocking_rule.rule_id,
            },
        )
    
    # ── Forward to Real API ───────────────────────────────────────────────────
    record_forward(client_ip)
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                TARGET_GRAPHQL_URL,
                content=raw_body,
                headers={
                    "Content-Type": "application/json",
                    "X-Forwarded-For": client_ip,
                    "X-Security-Middleware": "graphql-auditor-v1",
                },
            )
        
        return Response(
            content=response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "application/json"),
        )
    
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={
                "errors": [{"message": f"Cannot reach backend API at {TARGET_GRAPHQL_URL}"}]
            },
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"errors": [{"message": f"Proxy error: {str(e)}"}]},
        )


@app.get("/graphql")
async def graphql_get_passthrough(request: Request):
    """Pass-through GET requests (GraphiQL browser UI)."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(TARGET_GRAPHQL_URL)
        return Response(content=response.content, status_code=response.status_code,
                        media_type=response.headers.get("content-type", "text/html"))
    except Exception:
        return HTMLResponse("<h1>Backend unavailable</h1>", status_code=502)


# ── Health & Stats Endpoints ──────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "middleware": "GraphQL Security Auditor",
        "target": TARGET_GRAPHQL_URL,
        "uptime_since": stats["start_time"],
        "config": {
            "introspection_allowed": Config.ALLOW_INTROSPECTION,
            "max_depth": Config.MAX_QUERY_DEPTH,
            "max_complexity": Config.MAX_QUERY_COMPLEXITY,
            "batching_allowed": Config.ALLOW_BATCHING,
            "rate_limit": f"{Config.RATE_LIMIT_REQUESTS_PER_MINUTE}/min",
        },
    }


@app.get("/stats")
def get_stats():
    """Live enforcement statistics."""
    block_rate = (
        round(stats["blocked_requests"] / stats["total_requests"] * 100, 1)
        if stats["total_requests"] > 0 else 0
    )
    return {
        "total_requests": stats["total_requests"],
        "blocked_requests": stats["blocked_requests"],
        "forwarded_requests": stats["forwarded_requests"],
        "block_rate_percent": block_rate,
        "blocks_by_rule": dict(stats["blocks_by_rule"]),
        "blocks_by_ip": dict(stats["blocks_by_ip"]),
        "recent_blocks": stats["recent_blocks"],
    }


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GraphQL Security Auditor — SOC Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: rgba(22, 27, 34, 0.7);
            --border-color: rgba(48, 54, 61, 0.5);
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
        }
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
            min-height: 100vh;
            overflow-x: hidden;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }
        h1 {
            color: var(--accent-blue);
            margin: 0;
            font-weight: 800;
            letter-spacing: -0.5px;
            text-shadow: 0 0 10px rgba(88, 166, 255, 0.3);
        }
        .status-pulse {
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--accent-green);
            font-size: 0.9rem;
            font-weight: 600;
        }
        .dot {
            width: 10px;
            height: 10px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(63, 185, 80, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(63, 185, 80, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(63, 185, 80, 0); }
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }
        .stat-number {
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
        }
        .stat-label {
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .text-blue { color: var(--accent-blue); }
        .text-red { color: var(--accent-red); text-shadow: 0 0 15px rgba(248, 81, 73, 0.4); }
        .text-green { color: var(--accent-green); }
        .text-yellow { color: var(--accent-yellow); }
        
        .config-bar {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
            align-items: center;
        }
        .badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        .badge-red { background: rgba(248, 81, 73, 0.1); color: var(--accent-red); border: 1px solid rgba(248, 81, 73, 0.3); }
        .badge-green { background: rgba(63, 185, 80, 0.1); color: var(--accent-green); border: 1px solid rgba(63, 185, 80, 0.3); }
        .badge-yellow { background: rgba(210, 153, 34, 0.1); color: var(--accent-yellow); border: 1px solid rgba(210, 153, 34, 0.3); }

        .dashboard-layout {
            display: grid;
            grid-template-columns: 250px 1fr 1fr;
            gap: 1.5rem;
        }
        h2 {
            font-weight: 600;
            color: var(--text-main);
            margin-top: 0;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
            font-size: 1.1rem;
        }
        .panel {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            overflow: auto;
            max-height: 600px;
        }
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 0.8rem;
        }
        th {
            background: rgba(0,0,0,0.2);
            padding: 0.75rem;
            text-align: left;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        th:first-child { border-top-left-radius: 6px; border-bottom-left-radius: 6px; }
        th:last-child { border-top-right-radius: 6px; border-bottom-right-radius: 6px; }
        td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-color);
        }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.03); }
        code {
            background: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', Courier, monospace;
            color: #ff7b72;
            word-break: break-all;
        }
        .empty-state {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-style: italic;
        }
        .attack-tag {
            display: inline-block;
            margin-top: 4px;
            padding: 2px 6px;
            border-radius: 4px;
            background: rgba(248, 81, 73, 0.2);
            color: #ff7b72;
            font-size: 0.85em;
            font-weight: 600;
        }

        /* Simulator Styles */
        .sim-btn {
            display: block;
            width: 100%;
            background: var(--border-color);
            color: #fff;
            border: none;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: background 0.2s;
        }
        .sim-btn:hover {
            background: var(--accent-blue);
            color: #0d1117;
        }
        .sim-btn.danger { background: rgba(248, 81, 73, 0.2); color: #ff7b72; border: 1px solid rgba(248, 81, 73, 0.5); }
        .sim-btn.danger:hover { background: #f85149; color: #fff; }
        
        .target-select {
            width: 100%;
            padding: 10px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 15px;
            font-family: inherit;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡 SOC Middleware Console</h1>
            <div style="color: var(--text-muted); margin-top: 5px;">GraphQL API Security Auditor — Live Enforcement</div>
        </div>
        <div class="status-pulse">
            <div class="dot"></div>
            SYSTEM ACTIVE & MONITORING
        </div>
    </div>

    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-number text-blue" id="val-total">0</div>
            <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
            <div class="stat-number text-red" id="val-blocked">0</div>
            <div class="stat-label">Malicious Requests Blocked</div>
        </div>
        <div class="stat-card">
            <div class="stat-number text-green" id="val-forwarded">0</div>
            <div class="stat-label">Clean Traffic Forwarded</div>
        </div>
        <div class="stat-card">
            <div class="stat-number text-yellow"><span id="val-rate">0</span>%</div>
            <div class="stat-label">Block Rate</div>
        </div>
    </div>

    <div class="config-bar" id="config-badges">
        <strong style="color:var(--text-muted)">ACTIVE POLICIES:</strong>
        <!-- Dynamically populated -->
    </div>

    <div class="dashboard-layout">
        <!-- Panel 1: Attack Simulator -->
        <div class="panel">
            <h2>⚔️ Attack Simulator</h2>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
                Launch simulated attacks directly from the browser.
            </p>
            <label style="font-size: 0.8rem; font-weight: 600; display:block; margin-bottom:5px;">Target Endpoint:</label>
            <select id="target-select" class="target-select">
                <option value="http://localhost:8080/graphql">Middleware Proxy (Port 8080)</option>
                <option value="http://localhost:4000/graphql">Vulnerable Target (Port 4000)</option>
            </select>

            <button class="sim-btn" style="background: rgba(63, 185, 80, 0.2); color: #7ee787; border: 1px solid rgba(63, 185, 80, 0.5);" onclick="launchAttack('legitimate')">✅ Send Legitimate Query</button>
            <hr style="border-top: 1px dashed var(--border-color); border-bottom: none; margin: 15px 0;">
            
            <button class="sim-btn" onclick="launchAttack('introspection')">1. Schema Introspection</button>
            <button class="sim-btn" onclick="launchAttack('nesting')">2. DoS (Deep Nesting)</button>
            <button class="sim-btn" onclick="launchAttack('batching')">3. DoS (Array Batching)</button>
            <button class="sim-btn" onclick="launchAttack('sqli')">4. SQL Injection</button>
            <button class="sim-btn danger" style="margin-top: 15px;" onclick="launchSpam()">🔥 Launch All Attacks</button>
        </div>

        <!-- Panel 2: Middleware Feed -->
        <div class="panel">
            <h2>🛡️ Middleware Live Feed (Port 8080)</h2>
            <table>
                <thead>
                    <tr><th>Time</th><th>Rule Blocked</th><th>Query Preview</th></tr>
                </thead>
                <tbody id="feed-tbody">
                </tbody>
            </table>
        </div>

        <!-- Panel 3: Vulnerable Backend Feed -->
        <div class="panel">
            <h2>⚠️ Target API Feed (Port 4000)</h2>
            <p style="font-size:0.75rem; color:var(--text-muted); margin:0 0 10px 0;">Queries that successfully reached the backend.</p>
            <table>
                <thead>
                    <tr><th>Time</th><th>Client IP</th><th>Query Preview</th></tr>
                </thead>
                <tbody id="vuln-feed-tbody">
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const attackMap = {
            "R01": "Schema Introspection",
            "R02": "DoS: Deep Nesting",
            "R03": "DoS: High Complexity",
            "R04": "DoS: Array Batching",
            "R05": "Injection Attack",
            "R07": "Rate Limit Exceeded"
        };

        /* --- Attack Simulator Logic --- */
        async function sendAttack(payload) {
            const url = document.getElementById('target-select').value;
            try {
                await fetch(url, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                fetchStats(); // force immediate refresh
                fetchVulnStats();
            } catch (err) {
                console.error("Attack failed", err);
            }
        }

        function launchAttack(type) {
            if (type === 'legitimate') {
                sendAttack({query: `query { search_users(query: "alice") { ... on SearchResult { count } } }`});
            } else if (type === 'introspection') {
                sendAttack({query: `query { __schema { types { name } } }`});
            } else if (type === 'nesting') {
                sendAttack({query: `query { nested_user(id:1) { friend { friend { friend { friend { friend { friend { friend { friend { username } } } } } } } } } }`});
            } else if (type === 'sqli') {
                sendAttack({query: `query { search_users(query: "' OR 1=1 --") { ... on SearchResult { count } } }`});
            } else if (type === 'batching') {
                const payload = [];
                for(let i=0; i<50; i++) payload.push({query: `query { users { username } }`});
                sendAttack(payload);
            }
        }

        async function launchSpam() {
            launchAttack('introspection');
            setTimeout(() => launchAttack('sqli'), 100);
            setTimeout(() => launchAttack('nesting'), 200);
            setTimeout(() => launchAttack('batching'), 300);
        }

        /* --- Dashboard Polling Logic --- */
        async function fetchStats() {
            try {
                const response = await fetch('/stats');
                const data = await response.json();
                
                document.getElementById('val-total').textContent = data.total_requests;
                document.getElementById('val-blocked').textContent = data.blocked_requests;
                document.getElementById('val-forwarded').textContent = data.forwarded_requests;
                document.getElementById('val-rate').textContent = data.block_rate_percent;

                const feedTbody = document.getElementById('feed-tbody');
                feedTbody.innerHTML = '';
                if (data.recent_blocks.length === 0) {
                    feedTbody.innerHTML = '<tr><td colspan="3" class="empty-state">No malicious activity detected</td></tr>';
                } else {
                    data.recent_blocks.forEach(b => {
                        const tr = document.createElement('tr');
                        
                        const tdTime = document.createElement('td');
                        const date = new Date(b.timestamp);
                        tdTime.textContent = date.toLocaleTimeString();
                        
                        const tdRule = document.createElement('td');
                        tdRule.innerHTML = `<code>${b.rule_id}</code><br>`;
                        const attackName = attackMap[b.rule_id];
                        if (attackName) {
                            const spanTag = document.createElement('span');
                            spanTag.className = 'attack-tag';
                            spanTag.textContent = attackName;
                            tdRule.appendChild(spanTag);
                        }
                        
                        const tdQuery = document.createElement('td');
                        const codeQuery = document.createElement('code');
                        codeQuery.textContent = b.query_preview;
                        tdQuery.appendChild(codeQuery);

                        tr.appendChild(tdTime);
                        tr.appendChild(tdRule);
                        tr.appendChild(tdQuery);
                        feedTbody.appendChild(tr);
                    });
                }
            } catch (err) {
                console.error("Failed to fetch stats", err);
            }
        }
        
        async function fetchVulnStats() {
            try {
                const response = await fetch('http://localhost:4000/vuln_stats');
                const data = await response.json();
                
                const feedTbody = document.getElementById('vuln-feed-tbody');
                feedTbody.innerHTML = '';
                if (data.recent_requests.length === 0) {
                    feedTbody.innerHTML = '<tr><td colspan="3" class="empty-state">No requests received</td></tr>';
                } else {
                    data.recent_requests.forEach(b => {
                        const tr = document.createElement('tr');
                        
                        const tdTime = document.createElement('td');
                        const date = new Date(b.timestamp);
                        tdTime.textContent = date.toLocaleTimeString();
                        
                        const tdIp = document.createElement('td');
                        tdIp.textContent = b.client_ip;
                        
                        const tdQuery = document.createElement('td');
                        const codeQuery = document.createElement('code');
                        codeQuery.textContent = b.query_preview;
                        tdQuery.appendChild(codeQuery);

                        tr.appendChild(tdTime);
                        tr.appendChild(tdIp);
                        tr.appendChild(tdQuery);
                        feedTbody.appendChild(tr);
                    });
                }
            } catch (err) {
                // Ignore errors if target is unreachable
            }
        }

        async function fetchHealth() {
            try {
                const response = await fetch('/health');
                const data = await response.json();
                const cfg = data.config;
                
                const container = document.getElementById('config-badges');
                Array.from(container.children).forEach(c => {
                    if(c.tagName !== 'STRONG') container.removeChild(c);
                });

                function addBadge(text, isRed) {
                    const span = document.createElement('span');
                    span.className = 'badge ' + (isRed ? 'badge-red' : 'badge-green');
                    span.textContent = text;
                    container.appendChild(span);
                }

                addBadge(`R01 Introspection ${cfg.introspection_allowed ? 'ON' : 'OFF'}`, !cfg.introspection_allowed);
                addBadge(`R02 Max Depth: ${cfg.max_depth}`, true);
                addBadge(`R03 Max Complexity: ${cfg.max_complexity}`, true);
                addBadge(`R04 Batching ${cfg.batching_allowed ? 'ON' : 'OFF'}`, !cfg.batching_allowed);
                addBadge(`R05 Injection Detection`, true);
                addBadge(`R07 Rate Limit: ${cfg.rate_limit}`, true);

            } catch (err) {}
        }

        // Initialize
        fetchHealth();
        fetchStats();
        fetchVulnStats();
        
        // Poll every 2 seconds
        setInterval(() => {
            fetchStats();
            fetchVulnStats();
        }, 2000);
        setInterval(fetchHealth, 10000);
    </script>
</body>
</html>
"""

@app.get("/stats/dashboard", response_class=HTMLResponse)
def stats_dashboard():
    """Live HTML dashboard with JS polling and XSS prevention."""
    return HTMLResponse(content=DASHBOARD_HTML)


# ── Runtime Config Toggle ─────────────────────────────────────────────────────

@app.post("/config")
async def update_config(request: Request):
    """
    Toggle rules at runtime for live demo.
    Example: POST /config {"allow_introspection": true, "max_depth": 10}
    """
    body = await request.json()
    changes = []
    
    if "allow_introspection" in body:
        Config.ALLOW_INTROSPECTION = bool(body["allow_introspection"])
        changes.append(f"ALLOW_INTROSPECTION = {Config.ALLOW_INTROSPECTION}")
    
    if "max_depth" in body:
        Config.MAX_QUERY_DEPTH = int(body["max_depth"])
        changes.append(f"MAX_QUERY_DEPTH = {Config.MAX_QUERY_DEPTH}")
    
    if "max_complexity" in body:
        Config.MAX_QUERY_COMPLEXITY = int(body["max_complexity"])
        changes.append(f"MAX_QUERY_COMPLEXITY = {Config.MAX_QUERY_COMPLEXITY}")
    
    if "allow_batching" in body:
        Config.ALLOW_BATCHING = bool(body["allow_batching"])
        changes.append(f"ALLOW_BATCHING = {Config.ALLOW_BATCHING}")
    
    if "rate_limit" in body:
        Config.RATE_LIMIT_REQUESTS_PER_MINUTE = int(body["rate_limit"])
        changes.append(f"RATE_LIMIT = {Config.RATE_LIMIT_REQUESTS_PER_MINUTE}/min")
    
    print(f"[MIDDLEWARE] Config updated: {changes}")
    return {"updated": changes, "current_config": {
        "allow_introspection": Config.ALLOW_INTROSPECTION,
        "max_depth": Config.MAX_QUERY_DEPTH,
        "max_complexity": Config.MAX_QUERY_COMPLEXITY,
        "allow_batching": Config.ALLOW_BATCHING,
        "rate_limit_per_min": Config.RATE_LIMIT_REQUESTS_PER_MINUTE,
    }}


@app.get("/")
def root():
    return {
        "service": "GraphQL Security Middleware",
        "problem": "#18 — GraphQL API Security Auditor",
        "endpoints": {
            "POST /graphql": "Secured GraphQL proxy",
            "GET /health":   "Health check + current config",
            "GET /stats":    "JSON enforcement statistics",
            "GET /stats/dashboard": "Live HTML dashboard",
            "POST /config":  "Runtime rule configuration",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("middleware:app", host="0.0.0.0", port=8080, reload=True)
