from fastapi import FastAPI
from pydantic import BaseModel
import redis
import httpx
import os
import pandas as pd
from datetime import datetime
from app.response.ratelimit import token_bucket_check
from groq import Groq

ES_URL = "http://elasticsearch:9200"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

app = FastAPI(title="Mobile API Misuse Detector")

r = redis.Redis(host="redis", port=6379, decode_responses=True)

# =========================
# INITIALISATION GROQ LLM
# =========================

groq_client = None

if GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("[LLM] Groq client initialized successfully")
    except Exception as e:
        print(f"[LLM] Groq init failed: {e}")
else:
    print("[LLM] No GROQ_API_KEY found")


# =========================
# CHARGEMENT DES SCORES IA
# =========================

try:
    ai_scores_df = pd.read_csv("/app/data/processed/final_risk_scores.csv")

    ai_scores = dict(zip(ai_scores_df["ip"], ai_scores_df["risk_score"]))
    ai_levels = dict(zip(ai_scores_df["ip"], ai_scores_df["risk_level"]))
    ai_iso = dict(zip(ai_scores_df["ip"], ai_scores_df["iso_anomaly_score"]))
    ai_dbscan = dict(zip(ai_scores_df["ip"], ai_scores_df["dbscan_anomaly_score"]))
    ai_ae = dict(zip(ai_scores_df["ip"], ai_scores_df["ae_anomaly_score"]))

    print(f"[AI] Loaded {len(ai_scores)} IP scores")

except Exception as e:
    print(f"[AI WARNING] Could not load scores: {e}")

    ai_scores = {}
    ai_levels = {}
    ai_iso = {}
    ai_dbscan = {}
    ai_ae = {}


# =========================
# MODELE LOG
# =========================

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


# =========================
# FONCTION LLM
# =========================

async def get_llm_recommendation(
    ip: str,
    score: int,
    risk_level: str,
    attack_type: str,
    endpoint: str
) -> tuple:
    """
    Génère une recommandation cybersécurité via Groq LLM.
    """

    prompt = f"""
You are a senior cybersecurity analyst working in a SOC.

A malicious API activity has been detected.

SECURITY EVENT:
- IP Address: {ip}
- Endpoint: {endpoint}
- Risk Score: {score}/100
- Risk Level: {risk_level.upper()}
- Attack Type: {attack_type.upper()}

Provide a professional cybersecurity recommendation with exactly these sections:

[IMMEDIATE ACTION]
Explain what should be done immediately.

[INVESTIGATION]
Explain what logs, indicators, and patterns should be checked.

[STRATEGIC MITIGATION]
Explain long-term protections to reduce this risk.

Be concise, clear, and professional.
Never say that the traffic is safe.
"""

    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert analyzing real attacks. "
                            "Give actionable SOC recommendations."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=500
            )

            recommendation = response.choices[0].message.content.strip()
            print(f"[LLM] Recommendation generated for {ip}")
            return recommendation, "Groq - Llama 3.3 70B"

        except Exception as e:
            print(f"[LLM ERROR] {e}")

    fallback = (
        "BLOCK THIS IP IMMEDIATELY. "
        "Attack detected. Review API logs, authentication attempts, endpoint access patterns, "
        "and apply rate limiting or WAF rules."
    )

    return fallback, "Fallback - No LLM"


# =========================
# ROUTES
# =========================

@app.get("/")
def root():
    return {
        "message": "Mobile API Misuse Detector running with Rules + AI + Groq LLM"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "llm_available": groq_client is not None,
        "groq_configured": bool(GROQ_API_KEY),
        "ai_scores_loaded": len(ai_scores)
    }


@app.get("/api/v1/test-llm")
async def test_llm():
    """
    Test rapide pour vérifier Groq.
    """

    if not groq_client:
        return {
            "status": "error",
            "message": "GROQ_API_KEY not configured"
        }

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": "Say exactly: GROQ IS WORKING PROPERLY"
                }
            ],
            temperature=0,
            max_tokens=20
        )

        return {
            "status": "ok",
            "groq": response.choices[0].message.content.strip()
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.post("/api/v1/analyze")
async def analyze(entry: LogEntry):

    # =========================
    # DETECTION RULE-BASED
    # =========================

    rule_score = 20

    if entry.status in [401, 403]:
        rule_score += 40

    if entry.failed_attempts >= 3:
        rule_score += 20

    if "python-requests" in entry.user_agent.lower():
        rule_score += 30

    suspicious_endpoints = [
        "/admin",
        "/config",
        "/debug",
        "/env",
        "/.env"
    ]

    if any(e in entry.endpoint.lower() for e in suspicious_endpoints):
        rule_score += 20

    sql_patterns = [
        "union",
        "select",
        "drop",
        "insert",
        "passwd",
        "etc/passwd",
        "' or '1'='1",
        "\" or \"1\"=\"1"
    ]

    if any(p in entry.endpoint.lower() for p in sql_patterns):
        rule_score += 30

    rule_score = min(rule_score, 100)

    # =========================
    # DETECTION TYPE ATTAQUE
    # =========================

    if entry.failed_attempts >= 3 or (
        entry.status == 401 and "python-requests" in entry.user_agent.lower()
    ):
        attack_type = "bruteforce"

    elif any(e in entry.endpoint.lower() for e in suspicious_endpoints):
        attack_type = "enumeration"

    elif any(p in entry.endpoint.lower() for p in sql_patterns):
        attack_type = "sql_injection"

    elif entry.status in [401, 403]:
        attack_type = "bruteforce"

    else:
        attack_type = "none"

    # =========================
    # SCORES IA
    # =========================

    ai_score = ai_scores.get(entry.ip, 0)
    ai_level = ai_levels.get(entry.ip, "unknown")
    iso_score = ai_iso.get(entry.ip, 0)
    dbscan_score = ai_dbscan.get(entry.ip, 0)
    ae_score = ai_ae.get(entry.ip, 0)

    # Score combiné : 60% règles + 40% IA
    if ai_score > 0:
        final_score = int((rule_score * 0.6) + (float(ai_score) * 100 * 0.4))
    else:
        final_score = rule_score

    final_score = min(final_score, 100)

    risk_level = get_risk_level(final_score)
    action = get_action(final_score)

    # =========================
    # VERIFIER SI IP DEJA BLOQUEE
    # =========================

    if r.exists(f"block:{entry.ip}"):
        action = "blocked"

    # =========================
    # RATE LIMITING
    # =========================

    if final_score >= 60:
        limit = 20 if final_score < 70 else 5
        allowed, remaining = token_bucket_check(entry.ip, limit, 60, r)

        if not allowed:
            action = "blocked"
            r.setex(f"block:{entry.ip}", 900, 1)
            print(f"[REDIS] Rate limit exceeded. IP {entry.ip} blocked.")

    r.set(f"score:{entry.ip}", final_score)

    # =========================
    # LLM RECOMMANDATION
    # ACTIVEE DES SCORE >= 50
    # =========================

    llm_recommendation = ""
    llm_provider = ""

    if final_score >= 50 and attack_type != "none":
        llm_recommendation, llm_provider = await get_llm_recommendation(
            entry.ip,
            final_score,
            risk_level,
            attack_type,
            entry.endpoint
        )

    # =========================
    # BLOCAGE + SLACK
    # ACTIVE DES SCORE >= 70
    # =========================

    blocked = False

    if final_score >= 70:
        blocked = True
        action = "block_and_alert"

        r.setex(f"block:{entry.ip}", 900, 1)
        r.lpush("alerts", f"{entry.ip}|{final_score}|{attack_type}|{entry.endpoint}")

        print(f"[REDIS] IP {entry.ip} blocked for 15 minutes. Score={final_score}")

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
                            {
                                "type": "mrkdwn",
                                "text": f"*IP Address:*\n`{entry.ip}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Country:*\n`{entry.country}`"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Risk Score:*\n`{final_score}/100`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Risk Level:*\n`{risk_level.upper()}`"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Attack Type:*\n`{attack_type}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Action:*\n`{action}`"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Endpoint:*\n`{entry.endpoint}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Method:*\n`{entry.method}`"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Rule Score:*\n`{rule_score}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*AI Score:*\n`{ai_score}` ({ai_level})"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Isolation Forest:*\n`{iso_score}`"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*DBSCAN / AE:*\n`{dbscan_score}` / `{ae_score}`"
                            }
                        ]
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Response:* IP blocked for 15 minutes."
                        }
                    }
                ]
            }

            if llm_recommendation:
                slack_msg["blocks"].append(
                    {
                        "type": "divider"
                    }
                )

                slack_msg["blocks"].append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*LLM Recommendation ({llm_provider}):*\n{llm_recommendation}"
                        }
                    }
                )

            slack_msg["blocks"].append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
                        }
                    ]
                }
            )

            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        SLACK_WEBHOOK,
                        json=slack_msg,
                        timeout=5
                    )

                print(f"[SLACK] Alert sent for {entry.ip}")

            except Exception as e:
                print(f"[SLACK WARNING] {e}")

    # =========================
    # INDEX ELASTICSEARCH
    # =========================

    log_doc = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": entry.ip,
        "method": entry.method,
        "endpoint": entry.endpoint,
        "status": entry.status,
        "latency_ms": entry.latency_ms,
        "user_agent": entry.user_agent,
        "is_mobile": entry.is_mobile,
        "platform": entry.platform,
        "country": entry.country,
        "device_model": entry.device_model,
        "device_type": entry.device_type,
        "failed_attempts": entry.failed_attempts,

        "rule_score": rule_score,
        "ai_score": ai_score,
        "ai_level": ai_level,
        "iso_forest_score": iso_score,
        "dbscan_score": dbscan_score,
        "autoencoder_score": ae_score,

        "risk_score": final_score,
        "risk_level": risk_level,
        "attack_type": attack_type,
        "action": action,
        "blocked": blocked,

        "llm_recommendation": llm_recommendation[:1000] if llm_recommendation else "",
        "llm_provider": llm_provider
    }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ES_URL}/mobile-api-logs-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc",
                json=log_doc,
                timeout=5
            )

        print(f"[ES] Log indexed for {entry.ip}")

    except Exception as e:
        print(f"[ES WARNING] Could not index: {e}")

    # =========================
    # RESPONSE API
    # =========================

    return {
        "ip": entry.ip,
        "score": final_score,
        "rule_score": rule_score,
        "ai_score": ai_score,
        "ai_level": ai_level,
        "iso_forest_score": iso_score,
        "dbscan_score": dbscan_score,
        "autoencoder_score": ae_score,
        "risk_level": risk_level,
        "action": action,
        "attack_type": attack_type,
        "blocked": blocked,
        "llm_provider": llm_provider,
        "llm_recommendation": llm_recommendation if llm_recommendation else None
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

    return {
        "status": "unblocked",
        "ip": ip
    }


@app.get("/api/v1/top-threats")
async def top_threats(limit: int = 10):
    keys = r.keys("score:*")

    threats = [
        {
            "ip": k.split(":")[1],
            "score": int(r.get(k) or 0)
        }
        for k in keys
    ]

    return sorted(
        threats,
        key=lambda x: x["score"],
        reverse=True
    )[:limit]


# =========================
# UTILS
# =========================

def get_risk_level(score: int) -> str:
    if score < 40:
        return "normal"
    if score < 60:
        return "suspect"
    if score < 75:
        return "high"
    if score < 90:
        return "critical"
    return "attack"


def get_action(score: int) -> str:
    if score < 40:
        return "log_only"
    if score < 60:
        return "rate_limit_soft"
    if score < 75:
        return "rate_limit_strict"
    return "block_and_alert"
