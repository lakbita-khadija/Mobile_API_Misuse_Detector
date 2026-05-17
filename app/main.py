from fastapi import FastAPI
from pydantic import BaseModel
import redis
import httpx
import os
import pandas as pd
from datetime import datetime
from app.response.ratelimit import token_bucket_check

ES_URL = "http://elasticsearch:9200"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")

app = FastAPI(title="Mobile API Misuse Detector")
r = redis.Redis(host='redis', port=6379, decode_responses=True)

# Charger les scores IA au démarrage
try:
    ai_scores_df = pd.read_csv("/app/data/processed/final_risk_scores.csv")
    ai_scores = dict(zip(ai_scores_df['ip'], ai_scores_df['risk_score']))
    ai_levels = dict(zip(ai_scores_df['ip'], ai_scores_df['risk_level']))
    ai_iso = dict(zip(ai_scores_df['ip'], ai_scores_df['iso_anomaly_score']))
    ai_dbscan = dict(zip(ai_scores_df['ip'], ai_scores_df['dbscan_anomaly_score']))
    ai_ae = dict(zip(ai_scores_df['ip'], ai_scores_df['ae_anomaly_score']))
    print(f"[AI] Loaded {len(ai_scores)} IP scores")
except Exception as e:
    print(f"[AI WARNING] Could not load scores: {e}")
    ai_scores = {}
    ai_levels = {}
    ai_iso = {}
    ai_dbscan = {}
    ai_ae = {}

class LogEntry(BaseModel):
    ip: str
    method: str
    endpoint: str
    status: int
    latency_ms: int
    user_agent: str
    is_mobile: bool = True
    platform: str = "unknown"
    country: str = "unknown"
    device_model: str = "unknown"
    device_type: str = "unknown"
    failed_attempts: int = 0

@app.get("/")
def root():
    return {"message": "API running"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/analyze")
async def analyze(entry: LogEntry):
    score = 20

    if entry.status in [401, 403]:
        score += 40

    if entry.failed_attempts >= 3:
        score += 20

    if "python-requests" in entry.user_agent.lower():
        score += 30

    suspicious_endpoints = ["/admin", "/config", "/debug", "/env", "/.env"]
    if any(e in entry.endpoint for e in suspicious_endpoints):
        score += 20

    sql_patterns = ["UNION", "SELECT", "DROP", "INSERT", "passwd", "etc/passwd"]
    if any(p.lower() in entry.endpoint.lower() for p in sql_patterns):
        score += 30

    score = min(score, 100)

    ai_score = ai_scores.get(entry.ip, 0)
    ai_level = ai_levels.get(entry.ip, "unknown")
    iso_score = ai_iso.get(entry.ip, 0)
    dbscan_score = ai_dbscan.get(entry.ip, 0)
    ae_score = ai_ae.get(entry.ip, 0)

    if ai_score > 0:
        final_score = int((score * 0.6) + (ai_score * 100 * 0.4))
        final_score = min(final_score, 100)
    else:
        final_score = score

    action = get_action(final_score)
    risk_level = get_risk_level(final_score)

    if final_score >= 60:
        limit = 20 if final_score < 90 else 5
        allowed, remaining = token_bucket_check(entry.ip, limit, 60, r)
        if not allowed:
            action = "blocked"
            r.setex(f"block:{entry.ip}", 900, 1)

    r.set(f"score:{entry.ip}", final_score)

    if entry.failed_attempts >= 3 or (entry.status == 401 and "python-requests" in entry.user_agent.lower()):
        attack_type = "bruteforce"
    elif any(e in entry.endpoint for e in suspicious_endpoints):
        attack_type = "enumeration"
    elif any(p.lower() in entry.endpoint.lower() for p in sql_patterns):
        attack_type = "sql_injection"
    elif entry.status in [401, 403]:
        attack_type = "bruteforce"
    else:
        attack_type = "none"

    if final_score >= 90:
        r.lpush("alerts", f"{entry.ip}|{final_score}|{entry.endpoint}")

        # Cooldown 15 min — une seule alerte par IP
        alert_key = f"alerted:{entry.ip}"
        if not r.exists(alert_key) and SLACK_WEBHOOK:
            r.setex(alert_key, 900, 1)

            slack_msg = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "SECURITY ALERT — Mobile API Misuse Detector"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*IP Address:*\n`{entry.ip}`"},
                            {"type": "mrkdwn", "text": f"*Country:*\n`{entry.country}`"}
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n`{final_score}/100` — {risk_level.upper()}"},
                            {"type": "mrkdwn", "text": f"*Attack Type:*\n`{attack_type}`"}
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Endpoint:*\n`{entry.endpoint}`"},
                            {"type": "mrkdwn", "text": f"*Method:*\n`{entry.method}`"}
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Device:*\n`{entry.device_model}`"},
                            {"type": "mrkdwn", "text": f"*User Agent:*\n`{entry.user_agent[:40]}`"}
                        ]
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Action:* `block_and_alert` — IP blocked for 15 minutes"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Mobile API Misuse Detector"
                            }
                        ]
                    }
                ]
            }
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(SLACK_WEBHOOK, json=slack_msg, timeout=3)
                    print(f"[SLACK] Alert sent for {entry.ip}")
            except Exception as e:
                print(f"[SLACK WARNING] {e}")

    log_doc = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": entry.ip,
        "endpoint": entry.endpoint,
        "method": entry.method,
        "status": entry.status,
        "latency_ms": entry.latency_ms,
        "user_agent": entry.user_agent,
        "risk_score": final_score,
        "rule_score": score,
        "ai_score": ai_score,
        "ai_level": ai_level,
        "iso_forest_score": iso_score,
        "dbscan_score": dbscan_score,
        "autoencoder_score": ae_score,
        "risk_level": risk_level,
        "attack_type": attack_type,
        "country": entry.country,
        "device_model": entry.device_model,
        "device_type": entry.device_type,
        "failed_attempts": entry.failed_attempts,
        "is_mobile": entry.is_mobile,
        "platform": entry.platform,
        "blocked": final_score >= 90
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
        "score": final_score,
        "risk_level": risk_level,
        "action": action,
        "attack_type": attack_type
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
    if score < 90: return "rate_limit_strict"
    return "block_and_alert"
