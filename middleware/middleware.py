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
from datetime import datetime
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
TARGET_GRAPHQL_URL = "http://localhost:4000/graphql"

# ── Live Statistics ───────────────────────────────────────────────────────────

stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "forwarded_requests": 0,
    "blocks_by_rule": defaultdict(int),
    "blocks_by_ip": defaultdict(int),
    "recent_blocks": [],        # last 20 blocked requests
    "start_time": datetime.now().isoformat(),
}


def record_block(rule_id: str, reason: str, client_ip: str, query_preview: str):
    stats["blocked_requests"] += 1
    stats["blocks_by_rule"][rule_id] += 1
    stats["blocks_by_ip"][client_ip] += 1
    
    entry = {
        "timestamp": datetime.now().isoformat(),
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


@app.get("/stats/dashboard", response_class=HTMLResponse)
def stats_dashboard():
    """Simple HTML dashboard showing live stats."""
    s = get_stats()
    rows = "".join(
        f"<tr><td>{b['timestamp']}</td><td><code>{b['rule_id']}</code></td>"
        f"<td>{b['client_ip']}</td><td>{b['reason']}</td>"
        f"<td><small><code>{b['query_preview']}</code></small></td></tr>"
        for b in s["recent_blocks"]
    )
    rules_rows = "".join(
        f"<tr><td>{rule}</td><td>{count}</td></tr>"
        for rule, count in s["blocks_by_rule"].items()
    )
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>GraphQL Security Middleware — Live Dashboard</title>
      <meta http-equiv="refresh" content="3">
      <style>
        body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 2rem; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5rem; }}
        h2 {{ color: #7ee787; margin-top: 2rem; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1rem 0; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
        .stat-number {{ font-size: 2rem; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: .8rem; color: #8b949e; margin-top: .3rem; }}
        .blocked {{ color: #f85149 !important; }}
        .forwarded {{ color: #7ee787 !important; }}
        table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
        th {{ background: #21262d; padding: .5rem; text-align: left; border-bottom: 1px solid #30363d; color: #58a6ff; }}
        td {{ padding: .4rem .5rem; border-bottom: 1px solid #21262d; }}
        tr:hover {{ background: #161b22; }}
        code {{ background: #21262d; padding: 2px 4px; border-radius: 3px; font-size: .85em; }}
        .config {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: .75rem; }}
        .badge-red {{ background: #f8514933; color: #f85149; border: 1px solid #f85149; }}
        .badge-green {{ background: #7ee78733; color: #7ee787; border: 1px solid #7ee787; }}
      </style>
    </head>
    <body>
      <h1>🛡 GraphQL Security Middleware — Live Dashboard</h1>
      <small style="color:#8b949e">Auto-refreshes every 3 seconds | Target: {TARGET_GRAPHQL_URL}</small>

      <div class="stat-grid">
        <div class="stat-card">
          <div class="stat-number">{s['total_requests']}</div>
          <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
          <div class="stat-number blocked">{s['blocked_requests']}</div>
          <div class="stat-label">Blocked 🚫</div>
        </div>
        <div class="stat-card">
          <div class="stat-number forwarded">{s['forwarded_requests']}</div>
          <div class="stat-label">Forwarded ✅</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">{s['block_rate_percent']}%</div>
          <div class="stat-label">Block Rate</div>
        </div>
      </div>

      <div class="config">
        <strong>Active Rules:</strong>
        &nbsp;
        <span class="badge {'badge-red' if not Config.ALLOW_INTROSPECTION else 'badge-green'}">R01 Introspection {'OFF' if not Config.ALLOW_INTROSPECTION else 'ON'}</span>
        &nbsp;
        <span class="badge badge-red">R02 Max Depth: {Config.MAX_QUERY_DEPTH}</span>
        &nbsp;
        <span class="badge badge-red">R03 Max Complexity: {Config.MAX_QUERY_COMPLEXITY}</span>
        &nbsp;
        <span class="badge {'badge-red' if not Config.ALLOW_BATCHING else 'badge-green'}">R04 Batching {'OFF' if not Config.ALLOW_BATCHING else 'ON'}</span>
        &nbsp;
        <span class="badge badge-red">R05 Injection Detection</span>
        &nbsp;
        <span class="badge badge-red">R07 Rate Limit: {Config.RATE_LIMIT_REQUESTS_PER_MINUTE}/min</span>
      </div>

      <h2>Blocks by Rule</h2>
      <table>
        <tr><th>Rule</th><th>Count</th></tr>
        {rules_rows if rules_rows else '<tr><td colspan="2" style="color:#8b949e">No blocks yet</td></tr>'}
      </table>

      <h2>Recent Blocked Requests (last 20)</h2>
      <table>
        <tr><th>Timestamp</th><th>Rule</th><th>IP</th><th>Reason</th><th>Query Preview</th></tr>
        {rows if rows else '<tr><td colspan="5" style="color:#8b949e">No blocks recorded yet</td></tr>'}
      </table>
    </body>
    </html>
    """


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
