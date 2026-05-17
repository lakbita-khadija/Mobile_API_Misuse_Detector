from fastapi import FastAPI
from pydantic import BaseModel
import redis

from app.response.ratelimit import token_bucket_check

app = FastAPI(title="Mobile API Misuse Detector")

r = redis.Redis(host='redis', port=6379, decode_responses=True)

class LogEntry(BaseModel):
    ip: str
    method: str
    endpoint: str
    status: int
    latency_ms: int
    user_agent: str


@app.get("/")
def root():
    return {"message": "API running"}


@app.post("/api/v1/analyze")
async def analyze(entry: LogEntry):

    score = 20

    # simple bruteforce detection
    if entry.status in [401, 403]:
        score += 40

    # simple suspicious user-agent
    if "python-requests" in entry.user_agent.lower():
        score += 30

    action = "allow"

    if score >= 60:
        allowed, remaining = token_bucket_check(
            entry.ip,
            20,
            60,
            r
        )

        if not allowed:
            action = "blocked"

    return {
        "ip": entry.ip,
        "score": score,
        "action": action
    }


@app.get("/api/v1/status/{ip}")
async def status(ip: str):
    return {
        "ip": ip,
        "blocked": bool(r.exists(f"block:{ip}"))
    }
