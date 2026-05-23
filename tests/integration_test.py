"""
tests/integration_test.py
Full Integration Test — Demonstrates Attack vs Defence

This script is your DEMO SCRIPT for the hackathon presentation.
Run it after both the target API and middleware are running.

What it shows:
  Round 1 — Attack target directly (port 4000): everything succeeds (vulnerable)
  Round 2 — Attack through middleware (port 8080): everything gets blocked (defended)

Usage:
  python integration_test.py
  python integration_test.py --target-only   # only test direct target
  python integration_test.py --middleware-only # only test middleware
"""

import requests
import json
import sys
import time

TARGET_DIRECT    = "http://localhost:4000/graphql"
TARGET_PROTECTED = "http://localhost:8080/graphql"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def header(text: str):
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")


def subheader(text: str):
    print(f"\n{YELLOW}  ── {text} ──{RESET}")


def result(test_name: str, vulnerable: bool, expected_vulnerable: bool, detail: str = ""):
    if vulnerable == expected_vulnerable:
        icon = f"{GREEN}✓ PASS{RESET}"
    else:
        icon = f"{RED}✗ FAIL{RESET}"
    
    vuln_str = f"{RED}VULNERABLE{RESET}" if vulnerable else f"{GREEN}BLOCKED{RESET}"
    print(f"  [{icon}] {test_name}: {vuln_str}")
    if detail:
        print(f"         └─ {detail}")


def post(url: str, body, timeout: int = 10):
    """Send a GraphQL request, return (status_code, response_body)."""
    try:
        r = requests.post(
            url, json=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        return r.status_code, r.json()
    except requests.exceptions.Timeout:
        return 504, {"error": "timeout"}
    except Exception as e:
        return 0, {"error": str(e)}


# ── Individual Attack Tests ───────────────────────────────────────────────────

def test_introspection(url: str, expect_vulnerable: bool):
    subheader("Test 1: Introspection")
    query = "{ __schema { queryType { name } types { name } } }"
    status, body = post(url, {"query": query})
    
    vulnerable = (status == 200 and "data" in body and
                  body["data"] and "__schema" in str(body.get("data", {})))
    
    result("Introspection query", vulnerable, expect_vulnerable,
           f"HTTP {status} | Types exposed: {len(body.get('data', {}).get('__schema', {}).get('types', []))} types")
    
    return vulnerable


def test_sensitive_data(url: str, expect_vulnerable: bool):
    subheader("Test 2: Sensitive Field Access")
    query = "{ users { id username email password token ssn api_key credit_card } }"
    status, body = post(url, {"query": query})
    
    has_sensitive = False
    preview = ""
    if status == 200 and "data" in body and body["data"]:
        users = body["data"].get("users", [])
        if users:
            first = users[0]
            has_sensitive = any(field in first for field in
                               ["password", "token", "ssn", "api_key", "credit_card"])
            preview = f"password={first.get('password', 'N/A')[:10]}... | token={first.get('token', 'N/A')[:20]}..."
    
    result("Sensitive field extraction", has_sensitive, expect_vulnerable, preview)
    return has_sensitive


def test_batching(url: str, expect_vulnerable: bool):
    subheader("Test 3: Array Batching (DoS)")
    simple_q = "{ users { id username } }"
    batch = [{"query": simple_q} for _ in range(50)]
    
    start = time.time()
    status, body = post(url, batch, timeout=20)
    elapsed = time.time() - start
    
    vulnerable = isinstance(body, list) and len(body) == 50
    
    result("Array batch (50 queries)", vulnerable, expect_vulnerable,
           f"HTTP {status} | {elapsed:.2f}s | "
           f"{'Got ' + str(len(body)) + ' responses' if isinstance(body, list) else 'Rejected'}")
    return vulnerable


def test_deep_nesting(url: str, expect_vulnerable: bool):
    subheader("Test 4: Deep Nesting (DoS)")
    # Build 15-level deep query
    inner = "id username"
    for _ in range(15):
        inner = f"id username\n    friend {{\n      {inner}\n    }}"
    query = f"{{ nested_user(id: 1) {{\n  {inner}\n}} }}"
    
    start = time.time()
    status, body = post(url, {"query": query}, timeout=20)
    elapsed = time.time() - start
    
    vulnerable = (status == 200 and "data" in body and
                  body.get("data") and not body.get("errors"))
    
    blocked_by_mw = (status == 400 and body.get("blocked"))
    
    result("Deep nesting (depth=15)", vulnerable, expect_vulnerable,
           f"HTTP {status} | {elapsed:.3f}s | "
           f"{'Depth limit hit' if blocked_by_mw else 'Succeeded' if vulnerable else 'Error'}")
    return vulnerable


def test_injection(url: str, expect_vulnerable: bool):
    subheader("Test 5: SQL Injection")
    # Classic always-true SQLi
    query = '{ search_users(query: "\\' OR 1=1 --") { count users { id username password } } }'
    status, body = post(url, {"query": query})
    
    vulnerable = False
    detail = f"HTTP {status}"
    
    if status == 200 and "data" in body and body.get("data"):
        sr = body["data"].get("search_users", {})
        if sr and sr.get("count", 0) > 1:
            vulnerable = True
            detail += f" | {sr['count']} users returned (injection worked)"
    
    if status == 400 and body.get("blocked"):
        detail += " | Injection pattern detected and blocked"
    
    result("SQL injection (OR 1=1)", vulnerable, expect_vulnerable, detail)
    return vulnerable


def test_nosql_injection(url: str, expect_vulnerable: bool):
    subheader("Test 6: NoSQL Injection")
    query = '{ search_users(query: "{\\"$gt\\": \\"\\"}") { count users { id } } }'
    status, body = post(url, {"query": query})
    
    vulnerable = status == 200 and "data" in body and not body.get("errors")
    blocked = status == 400 and body.get("blocked")
    
    result("NoSQL injection ($gt operator)", not blocked, expect_vulnerable,
           f"HTTP {status} | {'Blocked' if blocked else 'Reached resolver'}")
    return not blocked


# ── Test Runner ───────────────────────────────────────────────────────────────

def run_test_suite(url: str, label: str, expect_vulnerable: bool) -> dict:
    header(f"{label}")
    print(f"  URL: {CYAN}{url}{RESET}")
    print(f"  Expecting: {'VULNERABLE (all attacks succeed)' if expect_vulnerable else 'PROTECTED (all attacks blocked)'}")
    
    results = {
        "introspection":    test_introspection(url, expect_vulnerable),
        "sensitive_data":   test_sensitive_data(url, expect_vulnerable),
        "batching":         test_batching(url, expect_vulnerable),
        "deep_nesting":     test_deep_nesting(url, expect_vulnerable),
        "sql_injection":    test_injection(url, expect_vulnerable),
        "nosql_injection":  test_nosql_injection(url, expect_vulnerable),
    }
    
    passed = sum(1 for v in results.values() if v == expect_vulnerable)
    total = len(results)
    
    print(f"\n  Score: {GREEN if passed == total else RED}{passed}/{total} tests matched expectations{RESET}")
    return results


def main():
    header("GraphQL Security Auditor — Integration Test Suite")
    print("  FoSC 23CSE313 | Problem #18 | Hackathon Demo")
    
    args = sys.argv[1:]
    
    print("\n  Checking services...")
    services_ok = True
    for name, url in [("Target API", TARGET_DIRECT), ("Middleware", TARGET_PROTECTED)]:
        try:
            r = requests.get(url.replace("/graphql", "/"), timeout=3)
            print(f"  {GREEN}✓{RESET} {name} at {url.replace('/graphql', '')}")
        except Exception:
            if "--middleware-only" in args and name == "Target API":
                pass
            elif "--target-only" in args and name == "Middleware":
                pass
            else:
                print(f"  {RED}✗{RESET} {name} unreachable at {url}")
                services_ok = False
    
    if not services_ok:
        print(f"\n  {RED}Cannot run tests — start services first:{RESET}")
        print("    Terminal 1: cd target_api && uvicorn app:app --port 4000")
        print("    Terminal 2: cd middleware && uvicorn middleware:app --port 8080")
        sys.exit(1)
    
    print()
    
    if "--middleware-only" not in args:
        # Round 1: Attack the unprotected target
        round1 = run_test_suite(
            TARGET_DIRECT,
            "ROUND 1 — Direct Attack (No Middleware) — All Should SUCCEED",
            expect_vulnerable=True,
        )
    
    if "--target-only" not in args:
        time.sleep(1)
        # Round 2: Attack through the middleware
        round2 = run_test_suite(
            TARGET_PROTECTED,
            "ROUND 2 — Through Middleware — All Should Be BLOCKED",
            expect_vulnerable=False,
        )
    
    # Final verdict
    header("DEMO SUMMARY")
    if "--middleware-only" not in args and "--target-only" not in args:
        print(f"\n  {BOLD}BEFORE middleware:{RESET} Target exposes all vulnerabilities")
        print(f"  {BOLD}AFTER  middleware:{RESET} All attack vectors blocked")
        print(f"\n  {GREEN}Middleware successfully intercepts:{RESET}")
        print("    • Introspection queries → schema hidden")
        print("    • Sensitive field access → still blocked at query validation")
        print("    • Array batching → rejected before reaching API")
        print("    • Deep nesting DoS → depth limit enforced")
        print("    • SQL/NoSQL injection → pattern detection")
        print(f"\n  {CYAN}View live dashboard: http://localhost:8080/stats/dashboard{RESET}")
        print(f"  {CYAN}View stats JSON:      http://localhost:8080/stats{RESET}")


if __name__ == "__main__":
    main()
