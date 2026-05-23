"""
probe/probe.py
Main Orchestrator — GraphQL Security Probe Tool

Usage:
  python probe.py --target http://localhost:4000/graphql
  python probe.py --target http://localhost:4000/graphql --batch-size 50
  python probe.py --target http://localhost:8080/graphql  # against middleware

Runs all four modules in sequence:
  1. Introspection   — schema dump
  2. Field Scanner   — sensitive field detection
  3. Batch Attack    — array batching + deep nesting DoS
  4. Injection       — SQLi / NoSQLi tests

Outputs:
  - Live terminal output (coloured)
  - report.json — machine-readable full results
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import requests

from introspect import run_introspection, parse_schema, print_schema_summary
from scanner import scan_schema_for_sensitive_fields, print_scan_results
from batch_attack import run_batching_attack, run_nesting_attack, print_attack_summary
from injection import run_all_injection_tests, print_injection_results


BANNER = r"""
  ╔══════════════════════════════════════════════════════╗
  ║       GraphQL Security Probe — Hackathon Tool        ║
  ║   FoSC 23CSE313 | Problem #18 | Team Submission      ║
  ╚══════════════════════════════════════════════════════╝
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="GraphQL Security Auditor — Offensive Probe Tool"
    )
    parser.add_argument(
        "--target", "-t",
        default=os.getenv("GRAPHQL_TARGET", "http://localhost:4000/graphql"),
        help=f"Target GraphQL endpoint URL (default: {os.getenv('GRAPHQL_TARGET', 'http://localhost:4000/graphql')})",
    )
    parser.add_argument(
        "--dashboard-url",
        default=os.getenv("DASHBOARD_REPORT_URL"),
        help="Optional middleware dashboard report endpoint URL (e.g. http://localhost:8080/stats/report)",
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=100,
        help="Number of queries in batch DoS attack (default: 100)",
    )
    parser.add_argument(
        "--depths",
        nargs="+",
        type=int,
        default=[2, 5, 10, 20, 50],
        help="Nesting depths to test (default: 2 5 10 20 50)",
    )
    parser.add_argument(
        "--skip-dos",
        action="store_true",
        help="Skip DoS tests (useful when testing middleware only)",
    )
    parser.add_argument(
        "--output", "-o",
        default="report.json",
        help="Output file for JSON report (default: report.json)",
    )
    return parser.parse_args()


def _derive_dashboard_url(target_url: str) -> str | None:
    if "/graphql" in target_url:
        return target_url.replace("/graphql", "/stats/report")
    return None


def _send_report_to_dashboard(report: dict, dashboard_url: str | None):
    if not dashboard_url:
        return
    try:
        response = requests.post(dashboard_url, json=report, timeout=10)
        print(f"[+] Dashboard report sent to {dashboard_url} (status {response.status_code})")
    except Exception as exc:
        print(f"[!] Failed to send dashboard report to {dashboard_url}: {exc}")


def run_probe(target_url: str, batch_size: int, depths: list, skip_dos: bool) -> dict:
    """Run all probe modules and return consolidated results dict."""
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "introspection": {},
        "sensitive_fields": [],
        "dos_attacks": {},
        "injection": [],
        "summary": {},
    }

    # ── Phase 1: Introspection ────────────────────────────────────────────────
    print("\n" + "─"*60)
    print("  PHASE 1/4 — INTROSPECTION")
    print("─"*60)
    
    try:
        raw_schema = run_introspection(target_url)
    except Exception as e:
        print(f"[ERROR] Cannot reach target: {e}")
        print("Make sure the target API is running!")
        sys.exit(1)
    
    introspection_disabled = raw_schema.get("introspection_disabled", False)
    report["introspection"]["disabled"] = introspection_disabled
    
    parsed_schema = {}
    if not introspection_disabled:
        parsed_schema = parse_schema(raw_schema)
        print_schema_summary(parsed_schema)
        report["introspection"]["schema"] = parsed_schema
        report["introspection"]["query_count"] = len(parsed_schema.get("query_fields", []))
        report["introspection"]["type_count"] = len(parsed_schema.get("all_types", {}))
    else:
        print("[+] Introspection blocked — continuing with other tests using fallback data")

    # ── Phase 2: Sensitive Field Scan ─────────────────────────────────────────
    print("\n" + "─"*60)
    print("  PHASE 2/4 — SENSITIVE FIELD SCAN")
    print("─"*60)
    
    sensitive_findings = []
    if parsed_schema:
        sensitive_findings = scan_schema_for_sensitive_fields(parsed_schema)
        print_scan_results(sensitive_findings)
        report["sensitive_fields"] = sensitive_findings
    else:
        print("[+] Skipping field scan — schema unavailable (introspection blocked)")

    # ── Phase 3: DoS Attacks ──────────────────────────────────────────────────
    print("\n" + "─"*60)
    print("  PHASE 3/4 — DoS ATTACKS (BATCHING + NESTING)")
    print("─"*60)
    
    batch_result = {}
    nesting_results = []
    
    if skip_dos:
        print("[+] DoS tests skipped (--skip-dos flag)")
    else:
        batch_result = run_batching_attack(target_url, batch_size=batch_size)
        nesting_results = run_nesting_attack(target_url, depths=depths)
        print_attack_summary(batch_result, nesting_results)
        report["dos_attacks"] = {
            "batching": batch_result,
            "nesting": nesting_results,
        }

    # ── Phase 4: Injection ────────────────────────────────────────────────────
    print("\n" + "─"*60)
    print("  PHASE 4/4 — INJECTION TESTS")
    print("─"*60)
    
    injection_findings = run_all_injection_tests(target_url, parsed_schema)
    print_injection_results(injection_findings)
    report["injection"] = injection_findings

    # ── Final Summary ─────────────────────────────────────────────────────────
    high_sensitive = len([f for f in sensitive_findings if f.get("severity") == "HIGH"])
    batch_vuln = batch_result.get("vulnerable", False)
    nesting_vuln = any(not r.get("blocked", True) for r in nesting_results)
    injection_vuln = any(f.get("vulnerable") for f in injection_findings)
    
    report["summary"] = {
        "introspection_exposed": not introspection_disabled,
        "high_sensitivity_fields": high_sensitive,
        "total_sensitive_fields": len(sensitive_findings),
        "batching_vulnerable": batch_vuln,
        "nesting_vulnerable": nesting_vuln,
        "injection_vulnerable": injection_vuln,
        "overall_risk": _calculate_risk(
            not introspection_disabled, high_sensitive, batch_vuln, nesting_vuln, injection_vuln
        ),
    }
    
    return report


def _calculate_risk(introspection, high_fields, batching, nesting, injection) -> str:
    score = 0
    if introspection: score += 2
    if high_fields > 0: score += 3
    if batching: score += 2
    if nesting: score += 2
    if injection: score += 3
    
    if score >= 8:  return "CRITICAL"
    if score >= 5:  return "HIGH"
    if score >= 3:  return "MEDIUM"
    return "LOW"


def print_final_summary(report: dict):
    s = report["summary"]
    risk = s["overall_risk"]
    risk_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
    
    print("\n" + "="*60)
    print("  FINAL PROBE REPORT")
    print("="*60)
    print(f"\n  Target : {report['target']}")
    print(f"  Time   : {report['timestamp']}")
    print(f"\n  Overall Risk: {risk_icon} {risk}\n")
    print(f"  {'Finding':<35} {'Result':>10}")
    print("  " + "-"*47)
    print(f"  {'Introspection Exposed':<35} {'YES ✗' if s['introspection_exposed'] else 'NO ✓':>10}")
    print(f"  {'High-Sensitivity Fields':<35} {s['high_sensitivity_fields']:>10}")
    print(f"  {'Total Sensitive Fields':<35} {s['total_sensitive_fields']:>10}")
    print(f"  {'Array Batching Vulnerable':<35} {'YES ✗' if s['batching_vulnerable'] else 'NO ✓':>10}")
    print(f"  {'Deep Nesting Vulnerable':<35} {'YES ✗' if s['nesting_vulnerable'] else 'NO ✓':>10}")
    print(f"  {'Injection Vulnerable':<35} {'YES ✗' if s['injection_vulnerable'] else 'NO ✓':>10}")
    print("\n" + "="*60)


def main():
    print(BANNER)
    args = parse_args()
    
    print(f"  Target  : {args.target}")
    print(f"  Batch   : {args.batch_size} queries")
    print(f"  Depths  : {args.depths}")
    print(f"  Output  : {args.output}")
    
    report = run_probe(
        target_url=args.target,
        batch_size=args.batch_size,
        depths=args.depths,
        skip_dos=args.skip_dos,
    )
    
    print_final_summary(report)
    
    # Save JSON report
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Full JSON report saved to: {args.output}")

    dashboard_url = args.dashboard_url or _derive_dashboard_url(args.target)
    if dashboard_url:
        _send_report_to_dashboard(report, dashboard_url)


if __name__ == "__main__":
    main()
