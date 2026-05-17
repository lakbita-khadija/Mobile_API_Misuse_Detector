from fastapi import FastAPI
from pydantic import BaseModel
import redis
import httpx
from datetime import datetime
from app.response.ratelimit import token_bucket_check

ES_URL = "http://elasticsearch:9200"

app = FastAPI(title="Mobile API Misuse Detector")
r = redis.Redis(host='redis', port=6379, decode_responses=True)

class LogEntry(BaseModel):
    ip: str
    method: str
    endpoint: str
    status: int
    latency_ms: int
    user_agent: str
    is_mobile: bool = True
    platform: str = "unknown"

@app.get("/")
def root():
    return {"message": "API running"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/analyze")
async def analyze(entry: LogEntry):
    score = 20

    # Bruteforce detection
    if entry.status in [401, 403]:
        score += 40

    # Suspicious user-agent
    if "python-requests" in entry.user_agent.lower():
        score += 30

    # Enumeration detection
    suspicious_endpoints = ["/admin", "/config", "/debug", "/env", "/.env"]
    if any(e in entry.endpoint for e in suspicious_endpoints):
        score += 20

    score = min(score, 100)

    action = get_action(score)
    risk_level = get_risk_level(score)

    # Rate limiting si score >= 60
    if score >= 60:
        limit = 20 if score < 90 else 5
        allowed, remaining = token_bucket_check(entry.ip, limit, 60, r)
        if not allowed:
            action = "blocked"
            r.setex(f"block:{entry.ip}", 900, 1)

    # Sauvegarder le score dans Redis
    r.set(f"score:{entry.ip}", score)

    # Alerte si score critique
    if score >= 90:
        r.lpush("alerts", f"{entry.ip}|{score}|{entry.endpoint}")

    # Indexer automatiquement dans Elasticsearch
    log_doc = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": entry.ip,
        "endpoint": entry.endpoint,
        "status": entry.status,
        "risk_score": score,
        "risk_level": risk_level,
        "attack_type": "bruteforce" if entry.status == 401 else "enumeration" if score >= 90 else "none"
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ES_URL}/mobile-api-logs-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc",
                json=log_doc,
                timeout=3
            )
    except Exception as e:
        print(f"[ES WARNING] Could not index: {e}")

    return {
        "ip": entry.ip,
        "score": score,
        "risk_level": risk_level,
        "action": action
    }

@app.get("/api/v1/status/{ip}")
async def status(ip: str):
    return {
        "ip": ip,
        "blocked": bool(r.exists(f"block:{ip}")),
        "block_ttl": r.ttl(f"block:{ip}"),
        "score": int(r.get(f"score:{ip}") or 0)
    }

@app.delete("/api/v1/block/{ip}")
async def unblock(ip: str):
    r.delete(f"block:{ip}")
    return {"status": "unblocked", "ip": ip}

@app.get("/api/v1/top-threats")
async def top_threats(limit: int = 10):
    keys = r.keys("score:*")
    threats = [
        {"ip": k.split(":")[1], "score": int(r.get(k) or 0)}
        for k in keys
    ]
    return sorted(threats, key=lambda x: x["score"], reverse=True)[:limit]

def get_risk_level(score: int) -> str:
    if score < 40: return "normal"
    if score < 60: return "suspect"
    if score < 75: return "high"
    if score < 90: return "critical"
    return "attack"

def get_action(score: int) -> str:
    if score < 40: return "log_only"
    if score < 60: return "rate_limit_soft"
    if score < 75: return "rate_limit_strict"
    if score < 90: return "captcha_required"
    return "block_and_alert"
