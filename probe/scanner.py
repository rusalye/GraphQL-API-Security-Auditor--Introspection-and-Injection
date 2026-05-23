"""
probe/scanner.py
Module 2: Sensitive Field Scanner

Given a parsed schema, scans ALL field names across ALL types
against a comprehensive wordlist of sensitive terms.

Reports:
  - Exact matches (password, token, ssn)
  - Partial matches (api_key, secret_key, auth_token)
  - High / Medium / Low severity ratings
  - Which type + query exposes the field (attack path)
"""

import re
from typing import List, Dict

# ── Sensitivity Wordlists ──────────────────────────────────────────────────────

HIGH_SENSITIVITY = [
    "password", "passwd", "pwd", "secret",
    "token", "access_token", "refresh_token", "auth_token", "bearer",
    "api_key", "apikey", "api_secret",
    "ssn", "social_security",
    "credit_card", "card_number", "cvv", "ccv",
    "private_key", "private_pem", "rsa_key",
    "otp", "mfa_secret", "totp_secret",
    "session_id", "cookie",
]

MEDIUM_SENSITIVITY = [
    "email", "phone", "mobile", "dob", "date_of_birth",
    "address", "street", "zip", "postal",
    "salary", "income", "bank_account",
    "ip_address", "device_id",
    "role", "permission", "admin",
    "hash", "digest",
]

LOW_SENSITIVITY = [
    "name", "username", "user_id",
    "created_at", "updated_at",
    "internal", "hidden", "deprecated",
]


def _classify_field(field_name: str) -> tuple[str, str]:
    """
    Returns (severity, matched_term) for a field name.
    severity is one of: HIGH, MEDIUM, LOW, or None.
    """
    normalized = field_name.lower().replace("-", "_")
    
    for term in HIGH_SENSITIVITY:
        if term in normalized:
            return "HIGH", term
    for term in MEDIUM_SENSITIVITY:
        if term in normalized:
            return "MEDIUM", term
    for term in LOW_SENSITIVITY:
        if term in normalized:
            return "LOW", term
    return None, None


def scan_schema_for_sensitive_fields(parsed_schema: dict) -> List[Dict]:
    """
    Walk every type and every field in the schema.
    Returns list of findings sorted by severity.
    """
    findings = []
    
    for type_name, type_info in parsed_schema.get("all_types", {}).items():
        for field in type_info.get("fields", []):
            field_name = field["name"]
            severity, matched_term = _classify_field(field_name)
            
            if severity:
                # Find which queries expose this type
                exposing_queries = _find_exposing_queries(type_name, parsed_schema)
                
                findings.append({
                    "type_name": type_name,
                    "field_name": field_name,
                    "field_type": field.get("type", "Unknown"),
                    "severity": severity,
                    "matched_term": matched_term,
                    "exposing_queries": exposing_queries,
                    "attack_path": _build_attack_path(exposing_queries, type_name, field_name),
                })
    
    # Sort: HIGH first, then MEDIUM, then LOW
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: severity_order[x["severity"]])
    
    return findings


def _find_exposing_queries(type_name: str, parsed_schema: dict) -> List[str]:
    """Find all top-level queries that return (or transitively return) the given type."""
    exposing = []
    for field in parsed_schema.get("query_fields", []):
        field_type = field.get("type", "")
        # Strip list/non-null wrappers to get base type name
        base_type = re.sub(r"[\[\]!]", "", field_type)
        if base_type == type_name:
            exposing.append(field["name"])
    return exposing


def _build_attack_path(exposing_queries: List[str], type_name: str, field_name: str) -> str:
    """Build a sample GraphQL query that would extract this sensitive field."""
    if not exposing_queries:
        return f"# No direct query found for type {type_name}"
    
    query_name = exposing_queries[0]
    return (
        f"query ExfiltrateData {{\n"
        f"  {query_name} {{\n"
        f"    {field_name}\n"
        f"  }}\n"
        f"}}"
    )


def print_scan_results(findings: List[Dict]):
    """Pretty-print all sensitive field findings."""
    print("\n" + "="*60)
    print("  SENSITIVE FIELD SCAN RESULTS")
    print("="*60)
    
    if not findings:
        print("\n[+] No sensitive fields detected in schema.")
        return
    
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] += 1
    
    print(f"\n  Summary: {severity_counts['HIGH']} HIGH | "
          f"{severity_counts['MEDIUM']} MEDIUM | "
          f"{severity_counts['LOW']} LOW findings\n")
    
    current_severity = None
    for finding in findings:
        if finding["severity"] != current_severity:
            current_severity = finding["severity"]
            icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(current_severity, "")
            print(f"\n  {icon} [{current_severity} SEVERITY]")
            print("  " + "-"*40)
        
        print(f"\n  Field   : {finding['type_name']}.{finding['field_name']}")
        print(f"  Type    : {finding['field_type']}")
        print(f"  Matched : '{finding['matched_term']}'")
        print(f"  Exposed by queries: {finding['exposing_queries'] or ['(no direct query)']}")
        print(f"  Attack path:")
        for line in finding["attack_path"].split("\n"):
            print(f"    {line}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    # Test standalone with a mock schema
    mock_schema = {
        "query_fields": [
            {"name": "users", "type": "[User]", "args": []},
            {"name": "user", "type": "User", "args": [{"name": "id", "type": "Int"}]},
        ],
        "all_types": {
            "User": {
                "kind": "OBJECT",
                "fields": [
                    {"name": "id", "type": "Int"},
                    {"name": "email", "type": "String"},
                    {"name": "password", "type": "String"},
                    {"name": "token", "type": "String"},
                    {"name": "ssn", "type": "String"},
                    {"name": "api_key", "type": "String"},
                    {"name": "credit_card", "type": "String"},
                ],
            }
        },
    }
    results = scan_schema_for_sensitive_fields(mock_schema)
    print_scan_results(results)
