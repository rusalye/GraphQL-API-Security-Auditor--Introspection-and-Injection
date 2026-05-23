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
  R06 — Fragment Abuse Detection (excessive/recursive fragments)
  R07 — Query Rate Limit (per IP, per minute)
  R08 — Directive Validation (suspicious/unknown directives)
"""

import re
import time
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional
from urllib.parse import unquote

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

    # R06 — Fragment abuse detection
    MAX_FRAGMENTS: int = 10                    # reject queries with more than this many fragments
    
    # R08 — Directive validation
    ALLOWED_DIRECTIVES: list = ["skip", "include"]  # whitelisted standard GraphQL directives
    
    # R05 — regex patterns in query body that look like injection
    INJECTION_PATTERNS: list = [
        # SQL Injection — common patterns
        r"'\s*OR\s*'?1'?='?1",                 # ' OR 1=1
        r"'\s*OR\s*'?true'?",                  # ' OR TRUE
        r"'\s*OR\s*'?\d+'\s*=\s*'?\d+",        # ' OR 1=1
        r"--\s*$",                              # SQL comment --
        r"#.*$",                                # SQL comment #
        r";\s*DROP\s+",                         # ; DROP
        r";\s*DELETE\s+",                       # ; DELETE
        r";\s*UPDATE\s+",                       # ; UPDATE
        r"UNION\s+SELECT",                      # UNION SELECT
        r"UNION\s+ALL",                         # UNION ALL
        r"UNION.*FROM",                         # UNION FROM
        r"SLEEP\s*\(",                          # SLEEP()
        r"BENCHMARK\s*\(",                      # BENCHMARK()
        r"WAITFOR\s+DELAY",                     # WAITFOR (MSSQL)
        r"pg_sleep",                            # PostgreSQL sleep
        r"dbms_lock\.sleep",                    # Oracle sleep
        
        # SQL Injection — encoding bypasses
        r"0x[0-9a-f]{2,}",                      # Hex encoding (e.g., 0x27 for ')
        r"\\x[0-9a-f]{2,}",                     # Hex escape sequences
        r"char\s*\(",                           # CHAR() function
        r"chr\s*\(",                            # CHR() function
        r"concat\s*\(",                         # CONCAT() function (multiple args)
        
        # NoSQL Injection
        r"\$where",                             # MongoDB $where
        r"\$ne\b",                              # $ne operator
        r"\$gt\b",                              # $gt operator
        r"\$lt\b",                              # $lt operator
        r"\$regex\b",                           # $regex operator
        r"\$or\b",                              # $or operator
        r"\$and\b",                             # $and operator
        r"\$in\b",                              # $in operator
        r"\$nin\b",                             # $nin operator
        r"\}\s*,\s*\{.*\$",                     # Pattern injection (},...{ $
        
        # Server-Side Template Injection (SSTI)
        r"\{\{.*\}\}",                          # Jinja2/Twig templates
        r"\{\%.*\%\}",                          # Jinja2/Twig blocks
        r"\$\{.*\}",                            # Mako/EL/Velocity injection
        r"\[\[.*\]\]",                          # FreeMarker
        r"<%.*%>",                              # JSP/ASP tags
        r"<\?.*\?>",                            # PHP tags
        
        # Path Traversal
        r"\.\./",                               # ../ path traversal
        r"\.\.",                                # .. sequences (with context)
        r"%2e%2e",                              # URL encoded ../
        r"\.\.\\",                              # Windows path traversal
        
        # Command Injection
        r";\s*cat\s+",                          # cat command
        r";\s*ls\s+",                           # ls command
        r";\s*bash\s+",                         # bash execution
        r";\s*sh\s+",                           # sh execution
        r";\s*exec\s*\(",                       # exec() call
        r";\s*system\s*\(",                     # system() call
        r"`.*`",                                # Backtick execution
        r"\|\s*cat\b",                          # Pipe to cat
        r"\|\s*nc\b",                           # Pipe to nc
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


# ── Query Complexity Calculator (Improved) ────────────────────────────────────

# Fields that typically return lists (expensive to fetch)
_EXPENSIVE_LIST_FIELDS = {
    'users', 'posts', 'comments', 'messages', 'notifications',
    'items', 'products', 'orders', 'transactions', 'events',
    'nested_user', 'friend', 'friends', 'followers',  # recursive/deep
    'edges', 'connections', 'results',  # pagination/connection wrappers
}

# Arguments that indicate fetching large amounts of data
_EXPENSIVE_ARGUMENT_PATTERNS = [
    r'(?:limit|first|take|fetchSize)\s*:\s*(\d+)',     # limit/first/take: 10000
    r'(?:offset|skip)\s*:\s*(\d+)',                      # offset/skip: 100000
    r'(?:max|maximum|batch_size)\s*:\s*(\d+)',           # max/maximum: 50000
]

def _detect_expensive_arguments(query_body: str) -> dict:
    """
    Detect expensive arguments like limit: 10000 or first: 5000.
    
    Returns:
        {
            'has_expensive_args': bool,
            'max_limit': int,
            'suspicious_offsets': bool,
        }
    """
    details = {
        'has_expensive_args': False,
        'max_limit': 0,
        'suspicious_offsets': False,
    }
    
    # Check for large limits/first/take arguments (threshold: 1000+)
    for pattern in _EXPENSIVE_ARGUMENT_PATTERNS:
        for match in re.finditer(pattern, query_body, re.IGNORECASE):
            try:
                value = int(match.group(1))
                
                # Detect suspicious limits
                if 'offset' in match.group(0).lower() or 'skip' in match.group(0).lower():
                    if value > 10000:
                        details['suspicious_offsets'] = True
                else:
                    details['has_expensive_args'] = True
                    details['max_limit'] = max(details['max_limit'], value)
            except (ValueError, IndexError):
                pass
    
    return details


def _calculate_complexity_improved(query_body: str) -> dict:
    """
    Improved complexity calculation with depth awareness, list multipliers, and argument detection.
    
    Factors:
    - Base field count (1 point per field)
    - Depth multiplier (depth 3+ multiplies cost)
    - List field multiplier (users, posts, comments cost 5 points each)
    - Recursive field penalty (friend recursion is expensive)
    - Operation count (multiple operations increase cost)
    - Expensive arguments (limit: 10000 increases cost)
    - Fragment expansion (fragments add to total)
    
    Returns:
        {
            'score': float,
            'depth': int,
            'operation_count': int,
            'list_field_count': int,
            'expensive_args': dict,
            'recursive_detected': bool,
            'breakdowns': {field_cost, depth_cost, list_cost, arg_cost},
        }
    """
    
    # Extract all fields and their depths
    fields_by_depth = defaultdict(lambda: {'total': 0, 'lists': 0, 'recursive': []})
    
    # Remove comments for cleaner analysis
    query_clean = re.sub(r'#.*?$', '', query_body, flags=re.MULTILINE)
    query_clean = re.sub(r'/\*.*?\*/', '', query_clean, flags=re.DOTALL)
    
    # Count operations (query, mutation, subscription)
    operation_pattern = r'\b(query|mutation|subscription)\s+([a-zA-Z_][a-zA-Z0-9_]*)?\s*(?:\(|{)'
    operations = re.findall(operation_pattern, query_clean, re.IGNORECASE)
    operation_count = len(operations) if operations else 1  # at least 1 implicit
    
    # Extract fragments
    fragment_pattern = r'fragment\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+on\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\{'
    fragments = re.findall(fragment_pattern, query_clean, re.IGNORECASE)
    fragment_count = len(fragments)
    
    # Analyze fields at different depths
    field_by_depth_pattern = r'(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(.*?\))?\s*\{'
    
    current_depth = 0
    field_positions = []
    
    for match in re.finditer(r'\{|\}', query_clean):
        pos = match.start()
        if match.group() == '{':
            current_depth += 1
            # Look backwards for field name
            before_brace = query_clean[max(0, pos-50):pos].strip()
            field_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(.*?\))?\s*$', before_brace)
            if field_match:
                field_name = field_match.group(1)
                if field_name.lower() not in {'query', 'mutation', 'subscription', 'fragment', 'on'}:
                    fields_by_depth[current_depth]['total'] += 1
                    
                    # Check if it's a list field
                    if field_name.lower() in _EXPENSIVE_LIST_FIELDS:
                        fields_by_depth[current_depth]['lists'] += 1
        else:  # }
            current_depth = max(0, current_depth - 1)
    
    # Count total unique fields
    total_fields = sum(d['total'] for d in fields_by_depth.values())
    total_list_fields = sum(d['lists'] for d in fields_by_depth.values())
    
    # Calculate base score
    field_cost = total_fields  # 1 point per field
    
    # Depth cost: fields at depth 3+ cost more
    depth_cost = 0
    max_depth_found = max(fields_by_depth.keys()) if fields_by_depth else 0
    for depth, field_info in fields_by_depth.items():
        if depth >= 3:
            depth_multiplier = 1.5 ** (depth - 2)  # exponential cost for deep nesting
            depth_cost += field_info['total'] * depth_multiplier
    
    # List field cost: expensive list fields cost 5 points each
    list_cost = total_list_fields * 5
    
    # Detect recursive patterns (e.g., friend { friend { friend }})
    recursive_detected = bool(re.search(r'(friend|nested_user)\s*\{[^}]*\1', query_clean, re.IGNORECASE))
    recursive_penalty = 20 if recursive_detected else 0
    
    # Argument-based cost
    arg_details = _detect_expensive_arguments(query_body)
    arg_cost = 0
    if arg_details['has_expensive_args']:
        # Large limits (>1000) increase cost significantly
        if arg_details['max_limit'] > 1000:
            arg_cost = min(50, (arg_details['max_limit'] / 1000) * 10)  # scales up to 50
    if arg_details['suspicious_offsets']:
        arg_cost += 30  # Large offsets are suspicious
    
    # Fragment expansion cost (each fragment reference adds complexity)
    fragment_cost = fragment_count * 5  # each fragment definition adds 5
    fragment_references = len(re.findall(r'\.\.\.([a-zA-Z_][a-zA-Z0-9_]*)', query_clean))
    fragment_expansion_cost = fragment_references * 3  # each fragment usage adds 3
    
    # Operation multiplier (multiple operations compound cost)
    operation_multiplier = operation_count
    
    # Total score
    total_score = (
        field_cost +
        depth_cost +
        list_cost +
        recursive_penalty +
        arg_cost +
        fragment_cost +
        fragment_expansion_cost
    ) * operation_multiplier
    
    return {
        'score': total_score,
        'depth': max_depth_found,
        'operation_count': operation_count,
        'field_count': total_fields,
        'list_field_count': total_list_fields,
        'fragment_count': fragment_count,
        'fragment_references': fragment_references,
        'recursive_detected': recursive_detected,
        'expensive_args': arg_details,
        'breakdown': {
            'field_cost': field_cost,
            'depth_cost': depth_cost,
            'list_cost': list_cost,
            'recursive_penalty': recursive_penalty,
            'arg_cost': arg_cost,
            'fragment_cost': fragment_cost,
            'fragment_expansion_cost': fragment_expansion_cost,
        },
    }


def _calculate_complexity(query_body: str) -> int:
    """
    Legacy wrapper for backward compatibility.
    Returns only the complexity score.
    """
    result = _calculate_complexity_improved(query_body)
    return int(result['score'])


# ── Individual Rule Implementations ──────────────────────────────────────────

def rule_r01_introspection(query_body: str, user_role: Optional[str] = None) -> RuleResult:
    """
    R01: Block introspection queries based on user role.
    
    Role-based access control:
    - admin: Always allow introspection queries
    - public/anonymous: Block __schema and __type queries
    
    Args:
        query_body: GraphQL query string
        user_role: User role ("admin", "public", or None for anonymous)
    
    Returns:
        RuleResult with blocked status
    """
    introspection_indicators = [
        "__schema",
        "__type",
    ]
    
    # ── Admin bypass ──────────────────────────────────────────────────────────
    # Admins can always use introspection queries
    if user_role == "admin":
        # Still detect for logging, but don't block
        for indicator in introspection_indicators:
            if indicator in query_body:
                return RuleResult(
                    blocked=False,
                    rule_id="R01",
                    reason=f"Introspection allowed for admin user (found: {indicator!r})",
                    details={"indicator": indicator, "user_role": "admin"},
                )
        return RuleResult(blocked=False, rule_id="R01", reason="No introspection detected")
    
    # ── Global config override (legacy dev mode) ──────────────────────────────
    if Config.ALLOW_INTROSPECTION:
        return RuleResult(blocked=False, rule_id="R01", reason="Introspection allowed (dev mode)")
    
    # ── Block introspection for non-admin users ────────────────────────────────
    # Public and anonymous users cannot query __schema or __type
    for indicator in introspection_indicators:
        if indicator in query_body:
            return RuleResult(
                blocked=True,
                rule_id="R01",
                reason=f"Introspection is disabled for {user_role or 'anonymous'} users (found: {indicator!r})",
                severity="HIGH",
                details={"indicator": indicator, "user_role": user_role or "anonymous"},
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
    """R03: Reject queries with complexity score above budget.
    
    Improved scoring considers:
    - Field count (1 pt each)
    - Depth-aware cost (exponential for depth 3+)
    - List field multipliers (users, posts, comments = 5 pts each)
    - Recursive patterns (friend chains = 20 pt penalty)
    - Argument analysis (limit: 10000 = 10-50 pts)
    - Fragment expansion (definitions + references)
    - Multiple operations (multiplicative)
    """
    complexity_result = _calculate_complexity_improved(query_body)
    score = int(complexity_result['score'])
    
    # Build detailed reason
    reason_parts = [f"Query complexity {score} exceeds budget of {Config.MAX_QUERY_COMPLEXITY}"]
    breakdown = complexity_result['breakdown']
    
    if breakdown['field_cost'] > 0:
        reason_parts.append(f"Fields: {complexity_result['field_count']} × 1 = {breakdown['field_cost']}")
    if breakdown['depth_cost'] > 0:
        reason_parts.append(f"Depth penalty (depth {complexity_result['depth']}): +{int(breakdown['depth_cost'])}")
    if breakdown['list_cost'] > 0:
        reason_parts.append(f"List fields (users/posts/etc): {complexity_result['list_field_count']} × 5 = {breakdown['list_cost']}")
    if breakdown['recursive_penalty'] > 0:
        reason_parts.append(f"Recursive pattern (friend/nested_user chains): +{breakdown['recursive_penalty']}")
    if breakdown['arg_cost'] > 0:
        reason_parts.append(f"Expensive arguments (limit/offset): +{int(breakdown['arg_cost'])}")
    if breakdown['fragment_cost'] > 0 or breakdown['fragment_expansion_cost'] > 0:
        frag_total = breakdown['fragment_cost'] + breakdown['fragment_expansion_cost']
        reason_parts.append(f"Fragment expansion: +{int(frag_total)}")
    if complexity_result['operation_count'] > 1:
        reason_parts.append(f"Multiple operations: {complexity_result['operation_count']}× multiplier")
    
    full_reason = " | ".join(reason_parts[:3])  # Limit to 3 main factors for clarity
    
    if score > Config.MAX_QUERY_COMPLEXITY:
        return RuleResult(
            blocked=True,
            rule_id="R03",
            reason=full_reason,
            severity="MEDIUM",
            details={
                "score": score,
                "max_allowed": Config.MAX_QUERY_COMPLEXITY,
                "field_count": complexity_result['field_count'],
                "depth": complexity_result['depth'],
                "list_fields": complexity_result['list_field_count'],
                "operations": complexity_result['operation_count'],
                "recursive_detected": complexity_result['recursive_detected'],
                "has_expensive_args": complexity_result['expensive_args']['has_expensive_args'],
                "breakdown": breakdown,
            },
        )
    
    return RuleResult(
        blocked=False,
        rule_id="R03",
        reason=f"Complexity {score}/{Config.MAX_QUERY_COMPLEXITY} | Fields: {complexity_result['field_count']}, Depth: {complexity_result['depth']}, Lists: {complexity_result['list_field_count']}",
        details={
            "score": score,
            "max_allowed": Config.MAX_QUERY_COMPLEXITY,
            "field_count": complexity_result['field_count'],
            "depth": complexity_result['depth'],
            "breakdown": breakdown,
        },
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


def rule_r05_injection(query_and_variables: str) -> RuleResult:
    """
    R05: Detect injection patterns in query arguments AND variables.
    
    Scans both the GraphQL query string and variable values for injection attempts.
    Normalizes input before pattern matching to catch encoding bypasses:
    - URL decoding (multiple iterations for double encoding)
    - Lowercase conversion for case-insensitive matching
    - Whitespace normalization to defeat spacing-based bypasses
    """
    if not isinstance(query_and_variables, str):
        return RuleResult(blocked=False, rule_id="R05", reason="No injection patterns detected")
    
    # Normalize query to catch encoding bypasses
    normalized = query_and_variables
    
    # URL decode (multiple times to catch double encoding)
    for _ in range(2):
        try:
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded
        except Exception:
            break
    
    # Normalize whitespace: collapse multiple spaces, remove newlines, tabs
    normalized = re.sub(r'\s+', ' ', normalized)
    
    # Convert to lowercase for case-insensitive detection
    normalized_lower = normalized.lower()
    
    # Check both original and normalized versions
    test_strings = [query_and_variables, normalized, normalized_lower]
    
    for test_string in test_strings:
        for pattern in Config.INJECTION_PATTERNS:
            match = re.search(pattern, test_string, re.IGNORECASE)
            if match:
                return RuleResult(
                    blocked=True,
                    rule_id="R05",
                    reason=f"Injection pattern detected",
                    severity="HIGH",
                    details={"pattern": pattern, "matched": match.group(0)},
                )
    
    return RuleResult(blocked=False, rule_id="R05", reason="No injection patterns detected")


def rule_r06_fragment_abuse(query_body: str) -> RuleResult:
    """
    R06: Detect fragment abuse patterns.
    
    Detects:
    - Excessive fragment definitions (count > threshold)
    - Obvious recursive fragments (fragment references itself)
    
    Fragment abuse can be used for DoS attacks by forcing the GraphQL server
    to expand deeply nested fragments or process an excessive number of them.
    
    Args:
        query_body: GraphQL query string
    
    Returns:
        RuleResult with blocked status
    """
    if not isinstance(query_body, str):
        return RuleResult(blocked=False, rule_id="R06", reason="No fragments detected")
    
    # Count fragment definitions: "fragment FragmentName on Type"
    # Pattern: fragment followed by whitespace, identifier, on, and another identifier
    fragment_pattern = r"fragment\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+on\s+[a-zA-Z_][a-zA-Z0-9_]*"
    fragment_matches = re.findall(fragment_pattern, query_body, re.IGNORECASE)
    fragment_count = len(fragment_matches)
    
    # Check if fragment count exceeds threshold
    if fragment_count > Config.MAX_FRAGMENTS:
        return RuleResult(
            blocked=True,
            rule_id="R06",
            reason=f"Excessive fragments detected: {fragment_count} fragments exceed limit of {Config.MAX_FRAGMENTS}",
            severity="MEDIUM",
            details={"fragment_count": fragment_count, "max_allowed": Config.MAX_FRAGMENTS},
        )
    
    # Check for obvious recursive fragments (a fragment name appears within its own definition)
    # Split query into fragment definitions
    # Simple heuristic: find each "fragment Name on Type { ... }" block
    # and check if the fragment name appears inside its definition (excluding the opening)
    for fragment_name in fragment_matches:
        # Build a pattern to find this fragment's definition: fragment Name on Type { ... }
        # Then look for the fragment name inside the braces
        fragment_def_pattern = rf"fragment\s+{re.escape(fragment_name)}\s+on\s+\w+\s*\{{([^}}]*(?:\{{[^}}]*\}}[^}}]*)*)\}}"
        match = re.search(fragment_def_pattern, query_body, re.IGNORECASE | re.DOTALL)
        
        if match:
            fragment_body = match.group(1)
            # Check if the fragment name appears in its own body (recursive reference)
            # Look for "...FragmentName" spread syntax or direct reference
            recursive_pattern = rf"(?:\.\.\.{re.escape(fragment_name)}|{re.escape(fragment_name)}\s*\{{)"
            if re.search(recursive_pattern, fragment_body, re.IGNORECASE):
                return RuleResult(
                    blocked=True,
                    rule_id="R06",
                    reason=f"Recursive fragment detected: fragment '{fragment_name}' references itself",
                    severity="HIGH",
                    details={"recursive_fragment": fragment_name},
                )
    
    return RuleResult(blocked=False, rule_id="R06", reason=f"Fragment usage OK ({fragment_count} fragments)")


def rule_r08_directives(query_body: str) -> RuleResult:
    """
    R08: Validate GraphQL directives.
    
    Detects and blocks:
    - Unknown/custom directives (not in whitelist)
    - Suspicious built-in directives (@skip, @include if not whitelisted)
    
    GraphQL directives can be abused to:
    - Conditionally hide/show fields to bypass security checks
    - Custom directives may execute arbitrary logic
    
    Whitelisted directives: skip, include
    
    Args:
        query_body: GraphQL query string
    
    Returns:
        RuleResult with blocked status
    """
    if not isinstance(query_body, str):
        return RuleResult(blocked=False, rule_id="R08", reason="No directives detected")
    
    # Find all directive usages: @directiveName
    # Pattern: @ followed by identifier (lowercase alphanumeric and underscore)
    directive_pattern = r"@([a-zA-Z_][a-zA-Z0-9_]*)"
    found_directives = re.findall(directive_pattern, query_body)
    
    if not found_directives:
        return RuleResult(blocked=False, rule_id="R08", reason="No directives detected")
    
    # Normalize to lowercase for comparison
    allowed_directives_lower = [d.lower() for d in Config.ALLOWED_DIRECTIVES]
    
    # Check each found directive
    for directive in found_directives:
        directive_lower = directive.lower()
        
        # Block if not in whitelist
        if directive_lower not in allowed_directives_lower:
            return RuleResult(
                blocked=True,
                rule_id="R08",
                reason=f"Directive '@{directive}' is not whitelisted",
                severity="MEDIUM",
                details={"directive": directive, "allowed": Config.ALLOWED_DIRECTIVES},
            )
    
    return RuleResult(blocked=False, rule_id="R08", reason=f"Directives OK ({len(set(found_directives))} unique directives)")


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

def validate_request(body_raw, client_ip: str = "unknown", user_role: Optional[str] = None) -> tuple[bool, Optional[RuleResult], list]:
    """
    Run all rules against the incoming request.
    
    Args:
        body_raw: Raw request body (dict, list, or string)
        client_ip: Client IP address for rate limiting
        user_role: User role for role-based access control ("admin", "public", or None)
    
    Returns:
        (is_blocked, blocking_rule_result, all_rule_results)
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
        variables = body_raw.get("variables", {})
    elif isinstance(body_raw, list):
        query_body = " ".join(item.get("query", "") for item in body_raw if isinstance(item, dict))
        variables = {}
    else:
        query_body = str(body_raw)
        variables = {}
    
    # Combine query and variables for injection checking
    # Variables are JSON-stringified to check for injection in their values
    variables_str = ""
    if variables:
        try:
            import json
            variables_str = json.dumps(variables)
        except Exception:
            variables_str = str(variables)
    
    query_and_variables = query_body + " " + variables_str
    
    # R01: Introspection (with role-based access control)
    r01 = rule_r01_introspection(query_body, user_role=user_role)
    all_results.append(r01)
    if r01.blocked:
        return True, r01, all_results
    
    # R05: Injection patterns (checks both query and variables)
    r05 = rule_r05_injection(query_and_variables)
    all_results.append(r05)
    if r05.blocked:
        return True, r05, all_results
    
    # R06: Fragment abuse detection
    r06 = rule_r06_fragment_abuse(query_body)
    all_results.append(r06)
    if r06.blocked:
        return True, r06, all_results
    
    # R08: Directive validation
    r08 = rule_r08_directives(query_body)
    all_results.append(r08)
    if r08.blocked:
        return True, r08, all_results
    
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
