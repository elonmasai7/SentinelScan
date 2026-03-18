from fastapi import APIRouter, Response

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/users/{user_id}")
async def demo_user(user_id: int) -> dict:
    return {
        "id": user_id,
        "name": f"User {user_id}",
        "email": f"user{user_id}@example.com",
        "api_key": "demo-live-key-123",
        "role": "user",
    }


@router.get("/private")
async def demo_private() -> dict:
    return {"message": "Sensitive data without auth", "token": "demo-token"}


@router.get("/search")
async def demo_search(q: str = "") -> dict:
    if "'" in q or "--" in q:
        return {"error": "SQL syntax error near '"}
    return {"results": [f"match:{q}"]}


@router.get("/ssrf")
async def demo_ssrf(url: str = "") -> dict:
    if "169.254.169.254" in url:
        return {"metadata": "ami-id=demo"}
    return {"fetched": url}


@router.get("/health")
async def demo_health(response: Response) -> dict:
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return {"status": "ok"}
