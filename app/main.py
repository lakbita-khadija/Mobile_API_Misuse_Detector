from fastapi import FastAPI
from pydantic import BaseModel
import redis
import httpx
import os
import pandas as pd
from datetime import datetime
from app.response.ratelimit import token_bucket_check
from openai import OpenAI
from groq import Groq

ES_URL = "http://elasticsearch:9200"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
FEATHERLESS_API_KEY = os.getenv("FEATHERLESS_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

app = FastAPI(title="Mobile API Misuse Detector")
r = redis.Redis(host='redis', port=6379, decode_responses=True)

# Initialiser les clients LLM
featherless_client = None
groq_client = None

if FEATHERLESS_API_KEY:
    try:
        featherless_client = OpenAI(
            base_url="https://api.featherless.ai/v1",
            api_key=FEATHERLESS_API_KEY,
            timeout=10.0
        )
        print("[LLM] Featherless client initialized")
    except Exception as e:
        print(f"[LLM] Featherless init failed: {e}")

if GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("[LLM] Groq client initialized")
    except Exception as e:
        print(f"[LLM] Groq init failed: {e}")

# Modèles
FEATHERLESS_MODEL = "openguardrails/OpenGuardrails-Text-4B-0124"
GROQ_MODEL = "llama-3.3-70b-versatile"

async def get_llm_recommendation(ip: str, score: int, risk_level: str, attack_type: str) -> tuple:
    """
    Génère une recommandation de sécurité détaillée et actionable.
    Essaie Featherless d'abord, puis Groq.
    Retourne: (recommandation, provider_utilisé)
    """
    
    # Prompt professionnel pour une recommandation longue et structurée
    prompt = f"""You are a senior cybersecurity expert. Analyze this security event and provide a DETAILED, ACTIONABLE recommendation.

SECURITY EVENT:
- IP Address: {ip}
- Risk Score: {score}/100 ({risk_level.upper()})
- Attack Type: {attack_type}

Provide a complete response with these THREE sections:

1. [IMMEDIATE ACTION] - What should be done right now? (blocking, rate limiting, etc.)

2. [INVESTIGATION] - What logs or patterns should the security team analyze?

3. [STRATEGIC MITIGATION] - What long-term security improvements are recommended?

Be specific, professional, and practical. Write in complete sentences."""

    # 1. Essayer Featherless (spécialisé sécurité)
    if featherless_client:
        try:
            response = featherless_client.chat.completions.create(
                model=FEATHERLESS_MODEL,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity expert. Provide detailed, actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=500  # Longue recommandation
            )
            recommendation = response.choices[0].message.content.strip()
            print(f"[LLM] Featherless generated detailed recommendation for {ip} ({len(recommendation)} chars)")
            return recommendation, "Featherless (OpenGuardrails)"
        except Exception as e:
            print(f"[LLM] Featherless failed: {e}")
    
    # 2. Fallback vers Groq
    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity expert. Provide detailed, actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=500
            )
            recommendation = response.choices[0].message.content.strip()
            print(f"[LLM] Groq generated detailed recommendation for {ip} ({len(recommendation)} chars)")
            return recommendation, "Groq (Llama 3.3 70B)"
        except Exception as e:
            print(f"[LLM] Groq failed: {e}")
    
    # 3. Pas de LLM disponible
    return "No LLM available - check API keys. Immediate action: Block IP and investigate logs.", "none"

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
    return {"message": "Mobile API Misuse Detector with Multi-LLM"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "llm_available": featherless_client is not None or groq_client is not None,
        "featherless": featherless_client is not None,
        "groq": groq_client is not None
    }

@app.post("/api/v1/analyze")
async def analyze(entry: LogEntry):
    # Règles de détection
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

    # Score IA
    ai_score = ai_scores.get(entry.ip, 0)
    ai_level = ai_levels.get(entry.ip, "unknown")
    iso_score = ai_iso.get(entry.ip, 0)
    dbscan_score = ai_dbscan.get(entry.ip, 0)
    ae_score = ai_ae.get(entry.ip, 0)

    # Score final combiné
    if ai_score > 0:
        final_score = int((score * 0.6) + (ai_score * 100 * 0.4))
        final_score = min(final_score, 100)
    else:
        final_score = score

    action = get_action(final_score)
    risk_level = get_risk_level(final_score)

    # Rate limiting
    if final_score >= 60:
        limit = 20 if final_score < 90 else 5
        allowed, remaining = token_bucket_check(entry.ip, limit, 60, r)
        if not allowed:
            action = "blocked"
            r.setex(f"block:{entry.ip}", 900, 1)

    r.set(f"score:{entry.ip}", final_score)

    # Déterminer le type d'attaque
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

    # Générer recommandation LLM DÉTAILLÉE pour scores élevés
    llm_recommendation = ""
    llm_provider = ""
    if final_score >= 75:  # Seuil pour LLM (High, Critical, Attack)
        llm_recommendation, llm_provider = await get_llm_recommendation(
            entry.ip, final_score, risk_level, attack_type
        )

    # Alerte Slack pour scores critiques
    if final_score >= 90:
        r.lpush("alerts", f"{entry.ip}|{final_score}|{entry.endpoint}")

        alert_key = f"alerted:{entry.ip}"
        if not r.exists(alert_key) and SLACK_WEBHOOK:
            r.setex(alert_key, 900, 1)

            # Construction du message Slack avec recommandation LLM
            slack_msg = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "🚨 SECURITY ALERT — Mobile API Misuse Detector"}
                    },
                    {"type": "divider"},
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
                            {"type": "mrkdwn", "text": f"*User Agent:*\n`{entry.user_agent[:50]}`"}
                        ]
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Action:* `{action}` — IP blocked for 15 minutes"}
                    }
                ]
            }
            
            # Ajouter la recommandation LLM détaillée
            if llm_recommendation and "No LLM available" not in llm_recommendation:
                slack_msg["blocks"].append({"type": "divider"})
                slack_msg["blocks"].append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🤖 LLM RECOMMENDATION ({llm_provider})*\n{llm_recommendation}"}
                })
            
            slack_msg["blocks"].append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Multi-LLM Security Engine"}]
            })
            
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(SLACK_WEBHOOK, json=slack_msg, timeout=5)
                    print(f"[SLACK] Alert sent for {entry.ip}")
            except Exception as e:
                print(f"[SLACK WARNING] {e}")

    # Indexer dans Elasticsearch
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
        "blocked": final_score >= 90,
        "llm_recommendation": llm_recommendation[:1000],  # Tronqué pour Elasticsearch
        "llm_provider": llm_provider
    }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ES_URL}/mobile-api-logs-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc",
                json=log_doc,
                timeout=5
            )
    except Exception as e:
        print(f"[ES WARNING] Could not index: {e}")

    return {
        "ip": entry.ip,
        "score": final_score,
        "rule_score": score,
        "ai_score": ai_score,
        "ai_level": ai_level,
        "risk_level": risk_level,
        "action": action,
        "attack_type": attack_type,
        "llm_recommendation": llm_recommendation if final_score >= 75 else None,
        "llm_provider": llm_provider if final_score >= 75 else None
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

@app.get("/api/v1/test-llm")
async def test_llm():
    """Test endpoint pour comparer les deux LLM avec recommandations détaillées"""
    test_ip = "93.110.220.181"
    results = {"status": "testing", "featherless": None, "groq": None, "note": "Detailed recommendations (max 500 chars)"}
    
    prompt = "What security actions for IP {test_ip} with score 94 (bruteforce)? Provide detailed recommendation in 3 sentences."
    
    if featherless_client:
        try:
            response = featherless_client.chat.completions.create(
                model=FEATHERLESS_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3
            )
            results["featherless"] = response.choices[0].message.content.strip()
        except Exception as e:
            results["featherless"] = f"Error: {str(e)[:80]}"
    
    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200,
                temperature=0.3
            )
            results["groq"] = response.choices[0].message.content.strip()
        except Exception as e:
            results["groq"] = f"Error: {str(e)[:80]}"
    
    return results

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
    return "block_and_alert"
