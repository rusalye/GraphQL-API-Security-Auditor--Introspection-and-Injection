"""
target_api/app.py
Deliberately VULNERABLE GraphQL API — Hackathon Target
DO NOT deploy this in production.

Vulnerabilities baked in:
  - Introspection ON (exposes full schema)
  - Sensitive fields exposed (password, token, ssn)
  - Injectable resolver arguments (no sanitisation)
  - No query depth or complexity limits
  - No batching protection
"""

import strawberry
from strawberry.fastapi import GraphQLRouter
from fastapi import FastAPI
from typing import Optional, List
import uvicorn

# ── Fake in-memory "database" ──────────────────────────────────────────────────

USERS = [
    {
        "id": 1,
        "username": "alice",
        "email": "alice@corp.com",
        "password": "hunter2",          # plaintext — intentional vuln
        "token": "eyJhbGciOiJIUzI1NiJ9.secret_admin_token",
        "ssn": "123-45-6789",
        "role": "admin",
        "credit_card": "4111-1111-1111-1111",
        "api_key": "sk-prod-abc123xyz",
    },
    {
        "id": 2,
        "username": "bob",
        "email": "bob@corp.com",
        "password": "password123",
        "token": "eyJhbGciOiJIUzI1NiJ9.user_token_bob",
        "ssn": "987-65-4321",
        "role": "user",
        "credit_card": "4222-2222-2222-2222",
        "api_key": "sk-dev-def456uvw",
    },
]

POSTS = [
    {"id": 1, "title": "Hello World", "body": "First post", "author_id": 1},
    {"id": 2, "title": "GraphQL is great", "body": "Second post", "author_id": 2},
]

# ── Strawberry Types ───────────────────────────────────────────────────────────

@strawberry.type
class User:
    id: int
    username: str
    email: str
    password: str          # SENSITIVE — exposed intentionally
    token: str             # SENSITIVE — exposed intentionally
    ssn: str               # SENSITIVE — exposed intentionally
    role: str
    credit_card: str       # SENSITIVE — exposed intentionally
    api_key: str           # SENSITIVE — exposed intentionally

@strawberry.type
class Post:
    id: int
    title: str
    body: str
    author_id: int

@strawberry.type
class SearchResult:
    users: List[User]
    count: int

# ── Resolvers ──────────────────────────────────────────────────────────────────

@strawberry.type
class Query:

    @strawberry.field
    def user(self, id: int) -> Optional[User]:
        """Get a single user by ID."""
        for u in USERS:
            if u["id"] == id:
                return User(**u)
        return None

    @strawberry.field
    def users(self) -> List[User]:
        """Return all users — no auth required."""
        return [User(**u) for u in USERS]

    @strawberry.field
    def search_users(self, query: str) -> SearchResult:
        """
        VULNERABLE: simulates SQL-like filtering with no sanitisation.
        In a real app this might be f"SELECT * FROM users WHERE username = '{query}'"
        We log the raw query to show injection is reaching the resolver.
        """
        print(f"[TARGET] Raw resolver argument received: {query!r}")  # shows injection
        results = [
            User(**u) for u in USERS
            if query.lower() in u["username"].lower() or query == "' OR 1=1 --"
        ]
        # Simulate ALL users returned on injection
        if "OR 1=1" in query or "' OR" in query.upper():
            results = [User(**u) for u in USERS]
        return SearchResult(users=results, count=len(results))

    @strawberry.field
    def post(self, id: int) -> Optional[Post]:
        for p in POSTS:
            if p["id"] == id:
                return Post(**p)
        return None

    @strawberry.field
    def posts(self) -> List[Post]:
        return [Post(**p) for p in POSTS]

    @strawberry.field
    def nested_user(self, id: int) -> Optional["NestedUser"]:
        """Deeply nestable type — for depth attack testing."""
        for u in USERS:
            if u["id"] == id:
                return NestedUser(id=u["id"], username=u["username"])
        return None

@strawberry.type
class NestedUser:
    """Recursive-style type to allow deep nesting attacks."""
    id: int
    username: str

    @strawberry.field
    def friend(self) -> Optional["NestedUser"]:
        return NestedUser(id=self.id, username=self.username)

# ── App Setup ─────────────────────────────────────────────────────────────────

schema = strawberry.Schema(
    query=Query,
    # introspection_rules=[] means introspection is ON by default — VULNERABLE
)

graphql_app = GraphQLRouter(schema)

app = FastAPI(title="Vulnerable GraphQL API — Hackathon Target")
app.include_router(graphql_app, prefix="/graphql")

@app.get("/")
def root():
    return {
        "message": "Vulnerable GraphQL API running",
        "graphql_endpoint": "/graphql",
        "graphiql": "/graphql (browser)",
        "warning": "THIS IS INTENTIONALLY INSECURE — hackathon use only",
    }

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=4000, reload=True)
