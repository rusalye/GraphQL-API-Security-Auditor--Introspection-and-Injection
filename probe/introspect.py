"""
probe/introspect.py
Module 1: GraphQL Introspection Schema Dumper

Sends the standard introspection query to the target and parses:
  - All types (Object, Input, Enum, Scalar)
  - All fields per type
  - All queries and mutations
  - Full field argument definitions
"""

import requests
import json
from typing import Optional

# Standard GraphQL full introspection query (industry standard payload)
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


def run_introspection(target_url: str, timeout: int = 10, token: str = None) -> dict:
    """
    Send introspection query to the target GraphQL endpoint.
    Returns parsed schema dict or raises on failure.
    """
    print(f"\n[INTROSPECT] Sending introspection query to {target_url}")
    
    try:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        response = requests.post(
            target_url,
            json={"query": INTROSPECTION_QUERY},
            headers=headers,
            timeout=timeout,
        )
        
        # Read body BEFORE raise_for_status so we can inspect middleware blocks.
        # Middleware returns 400 with {"blocked": true} — that is NOT a connection
        # failure, it means the security layer is working correctly.
        data = response.json()
        
        if "errors" in data:
            errors = data["errors"]
            # Check if introspection is disabled (middleware block or server-side)
            if data.get("blocked") or any(
                "introspection" in err.get("message", "").lower()
                or "disabled" in err.get("message", "").lower()
                for err in errors
            ):
                print("[INTROSPECT] ✗ INTROSPECTION IS DISABLED — server is hardened")
                return {"introspection_disabled": True, "errors": errors}
            print(f"[INTROSPECT] ✗ GraphQL errors: {errors}")
            return {"errors": errors}
        
        # Only raise for non-GraphQL HTTP errors (e.g. 500, 502)
        response.raise_for_status()
        
        print("[INTROSPECT] ✓ Introspection SUCCESSFUL — server is VULNERABLE")
        return data.get("data", {})
    
    except requests.exceptions.ConnectionError:
        print(f"[INTROSPECT] ✗ Cannot connect to {target_url}")
        raise
    except requests.exceptions.Timeout:
        print(f"[INTROSPECT] ✗ Request timed out")
        raise


def parse_schema(schema_data: dict) -> dict:
    """
    Parse raw introspection response into a clean summary:
      - query_fields: top-level queries available
      - mutation_fields: top-level mutations
      - all_types: every named type with their fields
    """
    result = {
        "query_type": None,
        "mutation_type": None,
        "query_fields": [],
        "mutation_fields": [],
        "all_types": {},
    }
    
    if not schema_data or "__schema" not in schema_data:
        return result
    
    schema = schema_data["__schema"]
    
    result["query_type"] = schema.get("queryType", {}).get("name") if schema.get("queryType") else None
    result["mutation_type"] = schema.get("mutationType", {}).get("name") if schema.get("mutationType") else None
    
    query_type_name = result["query_type"]
    mutation_type_name = result["mutation_type"]
    
    for gql_type in schema.get("types", []):
        type_name = gql_type.get("name", "")
        
        # Skip built-in introspection types
        if type_name.startswith("__") or type_name in ("String", "Int", "Float", "Boolean", "ID"):
            continue
        
        fields = []
        for field in (gql_type.get("fields") or []):
            field_info = {
                "name": field["name"],
                "description": field.get("description", ""),
                "args": [
                    {
                        "name": arg["name"],
                        "type": _resolve_type(arg.get("type", {})),
                    }
                    for arg in (field.get("args") or [])
                ],
                "type": _resolve_type(field.get("type", {})),
                "deprecated": field.get("isDeprecated", False),
            }
            fields.append(field_info)
        
        result["all_types"][type_name] = {
            "kind": gql_type.get("kind"),
            "fields": fields,
        }
        
        if type_name == query_type_name:
            result["query_fields"] = fields
        elif type_name == mutation_type_name:
            result["mutation_fields"] = fields
    
    return result


def _resolve_type(type_ref: dict, depth: int = 0) -> str:
    """Recursively resolve a GraphQL TypeRef to a human-readable string."""
    if depth > 10 or not type_ref:
        return "Unknown"
    name = type_ref.get("name")
    kind = type_ref.get("kind")
    of_type = type_ref.get("ofType")
    
    if name:
        if kind == "NON_NULL":
            return f"{name}!"
        return name
    if kind == "NON_NULL" and of_type:
        return f"{_resolve_type(of_type, depth+1)}!"
    if kind == "LIST" and of_type:
        return f"[{_resolve_type(of_type, depth+1)}]"
    return "Unknown"


def print_schema_summary(parsed: dict):
    """Pretty-print the parsed schema to terminal."""
    print("\n" + "="*60)
    print("  SCHEMA DUMP SUMMARY")
    print("="*60)
    
    print(f"\n[+] Query Type   : {parsed['query_type']}")
    print(f"[+] Mutation Type: {parsed['mutation_type']}")
    
    print(f"\n[+] Available Queries ({len(parsed['query_fields'])}):")
    for f in parsed["query_fields"]:
        args_str = ", ".join(f"{a['name']}: {a['type']}" for a in f["args"])
        print(f"    • {f['name']}({args_str}) → {f['type']}")
    
    if parsed["mutation_fields"]:
        print(f"\n[+] Available Mutations ({len(parsed['mutation_fields'])}):")
        for f in parsed["mutation_fields"]:
            args_str = ", ".join(f"{a['name']}: {a['type']}" for a in f["args"])
            print(f"    • {f['name']}({args_str}) → {f['type']}")
    
    print(f"\n[+] All Types ({len(parsed['all_types'])}):")
    for type_name, type_info in parsed["all_types"].items():
        fields = type_info["fields"]
        if fields:
            print(f"\n    [{type_info['kind']}] {type_name}")
            for field in fields:
                print(f"        - {field['name']} : {field['type']}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    # Quick standalone test
    TARGET = "http://localhost:4000/graphql"
    raw = run_introspection(TARGET)
    if raw and not raw.get("introspection_disabled"):
        parsed = parse_schema(raw)
        print_schema_summary(parsed)
        # Save raw dump
        with open("schema_dump.json", "w") as f:
            json.dump(raw, f, indent=2)
        print("\n[+] Raw schema saved to schema_dump.json")
