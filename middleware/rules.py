"""
middleware/rules.py
Security Rules Engine

Defines all GraphQL security policies and validation logic.
Each rule returns a RuleResult(blocked=True/False, reason="...", severity="...").

Rules implemented:
  R01 — Block Introspection in Production
  R02 — Query Depth Limit
  R03 — Query Complexity Limit
  R04 — Block Array Batching
  R05 — Block Suspicious Injection Patterns
  R06 — Field-Level Allowlist (optional)
  R07 — Query Rate Limit (per IP, per minute)
"""

import re
import time
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────

class Config:
    # R01
    ALLOW_INTROSPECTION: bool = False          # set True to allow in dev mode

    # R02
    MAX_QUERY_DEPTH: int = 5                   # reject queries deeper than this

    # R03
    MAX_QUERY_COMPLEXITY: int = 100            # field-count complexity budget

    # R04
    ALLOW_BATCHING: bool = False               # reject JSON array requests

    # R05 — regex patterns in query body that look like injection
    INJECTION_PATTERNS: list = [
        r"'\s*OR\s*'?1'?='?1",                 # SQLi: ' OR 1=1
        r"--\s*$",                              # SQLi: trailing comment
        r";\s*DROP\s+TABLE",                   # SQLi: drop table
        r"UNION\s+SELECT",                     # SQLi: UNION attack
        r"SLEEP\s*\(",                          # SQLi: time-based
        r"pg_sleep\s*\(",                       # PostgreSQL time-based
        r"\$where",                             # NoSQLi: MongoDB $where
        r"\$gt\b|\$ne\b|\$regex\b",            # NoSQLi: comparison operators
        r"\{\{.*\}\}",                          # SSTI: Jinja2 template injection
        r"\$\{.*\}",                            # SSTI: Mako/EL injection
        r"\.\./",                               # Path traversal
    ]

    # R07
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    RATE_LIMIT_WINDOW_SECONDS: int = 60


# ── Rule Result ───────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    blocked: bool
    rule_id: str
    reason: str
    severity: str = "MEDIUM"       # HIGH, MEDIUM, LOW
    details: dict = field(default_factory=dict)


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple in-memory sliding window rate limiter per IP."""
    
    def __init__(self):
        # ip -> list of request timestamps
        self._windows: dict = defaultdict(list)
    
    def is_allowed(self, ip: str) -> tuple[bool, int]:
        """Returns (allowed, requests_in_window)."""
        now = time.time()
        window_start = now - Config.RATE_LIMIT_WINDOW_SECONDS
        
        # Prune old timestamps
        self._windows[ip] = [t for t in self._windows[ip] if t > window_start]
        
        count = len(self._windows[ip])
        if count >= Config.RATE_LIMIT_REQUESTS_PER_MINUTE:
            return False, count
        
        self._windows[ip].append(now)
        return True, count + 1


# Global rate limiter instance
_rate_limiter = RateLimiter()


# ── Query Depth Calculator ────────────────────────────────────────────────────

def _calculate_depth(query_body: str) -> int:
    """
    Calculate the maximum nesting depth of a GraphQL query
    by counting opening braces.
    
    This is a lightweight approximation — good enough for hackathon.
    A production implementation would use a proper AST parser.
    """
    max_depth = 0
    current_depth = 0
    in_string = False
    in_block_comment = False
    
    i = 0
    while i < len(query_body):
        c = query_body[i]
        
        # Track block comments /* ... */
        if not in_string and i + 1 < len(query_body) and c == '/' and query_body[i+1] == '*':
            in_block_comment = True
            i += 2
            continue
        if in_block_comment and i + 1 < len(query_body) and c == '*' and query_body[i+1] == '/':
            in_block_comment = False
            i += 2
            continue
        if in_block_comment:
            i += 1
            continue
        
        # Track strings
        if c == '"' and not in_block_comment:
            in_string = not in_string
        
        if not in_string:
            if c == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif c == '}':
                current_depth = max(0, current_depth - 1)
        
        i += 1
    
    # Subtract 1 for the outer query wrapper brace
    return max(0, max_depth - 1)


# ── Query Complexity Calculator ───────────────────────────────────────────────

def _calculate_complexity(query_body: str) -> int:
    """
    Estimate query complexity by counting field selections.
    Each field selection costs 1 point.
    Fields inside lists cost extra (list fields are expensive).
    
    Again: lightweight approximation using regex, not AST.
    """
    # Count field selections (lines with word characters not starting with query/mutation/fragment)
    field_pattern = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[{(\s]?', re.MULTILINE)
    
    keywords = {'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null'}
    
    matches = field_pattern.findall(query_body)
    field_count = sum(1 for m in matches if m.lower() not in keywords)
    
    return field_count


# ── Individual Rule Implementations ──────────────────────────────────────────

def rule_r01_introspection(query_body: str) -> RuleResult:
    """R01: Block introspection queries if not in dev mode."""
    introspection_indicators = [
        "__schema",
        "__type",
        "__typename",
        "IntrospectionQuery",
    ]
    
    if Config.ALLOW_INTROSPECTION:
        return RuleResult(blocked=False, rule_id="R01", reason="Introspection allowed (dev mode)")
    
    for indicator in introspection_indicators:
        if indicator in query_body:
            return RuleResult(
                blocked=True,
                rule_id="R01",
                reason=f"Introspection is disabled in production (found: {indicator!r})",
                severity="HIGH",
                details={"indicator": indicator},
            )
    
    return RuleResult(blocked=False, rule_id="R01", reason="No introspection detected")


def rule_r02_depth(query_body: str) -> RuleResult:
    """R02: Reject queries exceeding maximum depth."""
    depth = _calculate_depth(query_body)
    
    if depth > Config.MAX_QUERY_DEPTH:
        return RuleResult(
            blocked=True,
            rule_id="R02",
            reason=f"Query depth {depth} exceeds maximum allowed depth of {Config.MAX_QUERY_DEPTH}",
            severity="HIGH",
            details={"depth": depth, "max_allowed": Config.MAX_QUERY_DEPTH},
        )
    
    return RuleResult(
        blocked=False,
        rule_id="R02",
        reason=f"Depth {depth} within limit ({Config.MAX_QUERY_DEPTH})",
        details={"depth": depth},
    )


def rule_r03_complexity(query_body: str) -> RuleResult:
    """R03: Reject queries with complexity score above budget."""
    complexity = _calculate_complexity(query_body)
    
    if complexity > Config.MAX_QUERY_COMPLEXITY:
        return RuleResult(
            blocked=True,
            rule_id="R03",
            reason=f"Query complexity {complexity} exceeds budget of {Config.MAX_QUERY_COMPLEXITY}",
            severity="MEDIUM",
            details={"complexity": complexity, "max_allowed": Config.MAX_QUERY_COMPLEXITY},
        )
    
    return RuleResult(
        blocked=False,
        rule_id="R03",
        reason=f"Complexity {complexity} within budget",
        details={"complexity": complexity},
    )


def rule_r04_batching(body_raw) -> RuleResult:
    """R04: Reject array-batched requests."""
    if not Config.ALLOW_BATCHING and isinstance(body_raw, list):
        return RuleResult(
            blocked=True,
            rule_id="R04",
            reason=f"Array batching is disabled. Request contained {len(body_raw)} queries.",
            severity="MEDIUM",
            details={"batch_size": len(body_raw)},
        )
    
    return RuleResult(blocked=False, rule_id="R04", reason="No batching detected")


def rule_r05_injection(query_body: str) -> RuleResult:
    """R05: Detect injection patterns in query arguments."""
    for pattern in Config.INJECTION_PATTERNS:
        match = re.search(pattern, query_body, re.IGNORECASE)
        if match:
            return RuleResult(
                blocked=True,
                rule_id="R05",
                reason=f"Injection pattern detected: {pattern!r}",
                severity="HIGH",
                details={"pattern": pattern, "matched": match.group(0)},
            )
    
    return RuleResult(blocked=False, rule_id="R05", reason="No injection patterns detected")


def rule_r07_rate_limit(client_ip: str) -> RuleResult:
    """R07: Rate limit by IP address."""
    allowed, count = _rate_limiter.is_allowed(client_ip)
    
    if not allowed:
        return RuleResult(
            blocked=True,
            rule_id="R07",
            reason=f"Rate limit exceeded: {count} requests in {Config.RATE_LIMIT_WINDOW_SECONDS}s window",
            severity="MEDIUM",
            details={"request_count": count, "limit": Config.RATE_LIMIT_REQUESTS_PER_MINUTE},
        )
    
    return RuleResult(
        blocked=False,
        rule_id="R07",
        reason=f"Rate OK ({count}/{Config.RATE_LIMIT_REQUESTS_PER_MINUTE} requests)",
    )


# ── Master Validator ───────────────────────────────────────────────────────────

def validate_request(body_raw, client_ip: str = "unknown") -> tuple[bool, Optional[RuleResult], list]:
    """
    Run all rules against the incoming request.
    Returns (is_blocked, blocking_rule_result, all_rule_results).
    Stops at first blocking rule.
    """
    all_results = []
    
    # R07: Rate limiting (before parsing body)
    r07 = rule_r07_rate_limit(client_ip)
    all_results.append(r07)
    if r07.blocked:
        return True, r07, all_results
    
    # R04: Batching check (on raw body)
    r04 = rule_r04_batching(body_raw)
    all_results.append(r04)
    if r04.blocked:
        return True, r04, all_results
    
    # Extract query string from body
    if isinstance(body_raw, dict):
        query_body = body_raw.get("query", "")
    elif isinstance(body_raw, list):
        query_body = " ".join(item.get("query", "") for item in body_raw if isinstance(item, dict))
    else:
        query_body = str(body_raw)
    
    # R01: Introspection
    r01 = rule_r01_introspection(query_body)
    all_results.append(r01)
    if r01.blocked:
        return True, r01, all_results
    
    # R05: Injection patterns
    r05 = rule_r05_injection(query_body)
    all_results.append(r05)
    if r05.blocked:
        return True, r05, all_results
    
    # R02: Depth
    r02 = rule_r02_depth(query_body)
    all_results.append(r02)
    if r02.blocked:
        return True, r02, all_results
    
    # R03: Complexity
    r03 = rule_r03_complexity(query_body)
    all_results.append(r03)
    if r03.blocked:
        return True, r03, all_results
    
    return False, None, all_results
