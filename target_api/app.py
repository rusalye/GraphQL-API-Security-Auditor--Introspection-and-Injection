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

Database: MongoDB (persistent storage)
Connection: mongodb://mongodb:27017/graphql_api
"""

import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.schema.config import StrawberryConfig
from fastapi import FastAPI
from typing import Optional, List
import uvicorn
from pymongo import MongoClient
import os

# ── MongoDB Connection ─────────────────────────────────────────────────────────

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = "graphql_api"

try:
    mongo_client = MongoClient(MONGO_URL)
    db = mongo_client[DB_NAME]
    users_collection = db["users"]
    posts_collection = db["posts"]
    
    # Initialize with seed data if collections are empty
    if users_collection.count_documents({}) == 0:
        SEED_USERS = [
            {
                "_id": 1,
                "id": 1,
                "username": "alice",
                "email": "alice@corp.com",
                "password": "hunter2",
                "token": "eyJhbGciOiJIUzI1NiJ9.secret_admin_token",
                "ssn": "123-45-6789",
                "role": "admin",
                "credit_card": "4111-1111-1111-1111",
                "api_key": "sk-prod-abc123xyz",
            },
            {
                "_id": 2,
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
        users_collection.insert_many(SEED_USERS)
    
    if posts_collection.count_documents({}) == 0:
        SEED_POSTS = [
            {"_id": 1, "id": 1, "title": "Hello World", "body": "First post", "author_id": 1},
            {"_id": 2, "id": 2, "title": "GraphQL is great", "body": "Second post", "author_id": 2},
        ]
        posts_collection.insert_many(SEED_POSTS)
    
    print("[DATABASE] ✓ Connected to MongoDB")
except Exception as e:
    print(f"[DATABASE] ✗ Failed to connect to MongoDB: {e}")
    print("[DATABASE] → Falling back to in-memory data")

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
        try:
            u = users_collection.find_one({"id": id})
            if u:
                # Remove MongoDB's _id field
                u.pop("_id", None)
                return User(**u)
        except Exception as e:
            print(f"[TARGET] DB Error: {e}")
        return None

    @strawberry.field
    def users(self) -> List[User]:
        """Return all users — no auth required."""
        try:
            all_users = list(users_collection.find({}))
            return [User(**{k: v for k, v in u.items() if k != "_id"}) for u in all_users]
        except Exception as e:
            print(f"[TARGET] DB Error: {e}")
            return []

    @strawberry.field
    def search_users(self, query: str) -> SearchResult:
        """
        VULNERABLE: MongoDB query with no sanitisation.
        Demonstrates NoSQL injection vulnerability.
        
        Real MongoDB query would be: db.users.find({"username": query})
        Attacker can inject: {"$gt": ""} to bypass authentication
        """
        print(f"[TARGET] Raw resolver argument received: {query!r}")  # shows injection
        
        try:
            # VULNERABLE: Direct string matching (simulates unsafe query building)
            if query == "' OR 1=1 --" or "OR 1=1" in query:
                # Simulate SQL injection success — return all users
                results = list(users_collection.find({}))
            elif query.startswith('{"$'):
                # Simulate NoSQL injection — MongoDB operator injection
                print(f"[TARGET] ⚠️  Detected MongoDB operator injection: {query}")
                results = list(users_collection.find({}))  # Return all users on injection
            else:
                # Normal query
                results = list(users_collection.find({"username": {"$regex": query, "$options": "i"}}))
            
            clean_results = [User(**{k: v for k, v in u.items() if k != "_id"}) for u in results]
            return SearchResult(users=clean_results, count=len(clean_results))
        except Exception as e:
            print(f"[TARGET] DB Error: {e}")
            return SearchResult(users=[], count=0)

    @strawberry.field
    def post(self, id: int) -> Optional[Post]:
        try:
            p = posts_collection.find_one({"id": id})
            if p:
                p.pop("_id", None)
                return Post(**p)
        except Exception as e:
            print(f"[TARGET] DB Error: {e}")
        return None

    @strawberry.field
    def posts(self) -> List[Post]:
        try:
            all_posts = list(posts_collection.find({}))
            return [Post(**{k: v for k, v in p.items() if k != "_id"}) for p in all_posts]
        except Exception as e:
            print(f"[TARGET] DB Error: {e}")
            return []

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

# Disable automatic GraphQL camelCase conversion so field names stay snake_case.
# This keeps the API behavior consistent with the probe and integration tests.
strawberry.auto_camel_case = False

schema = strawberry.Schema(
    query=Query,
    config=StrawberryConfig(
        auto_camel_case=False,
        batching_config={"max_operations": 100},
    ),
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
