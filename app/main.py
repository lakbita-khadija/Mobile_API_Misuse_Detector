from fastapi import FastAPI
from pydantic import BaseModel
import redis
import numpy as np
import httpx
import joblib
import os
import pandas as pd
from datetime import datetime
from app.response.ratelimit import token_bucket_check
from groq import Groq

ES_URL = "http://elasticsearch:9200"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
try:
    iso_model = joblib.load("/app/models/isolation_forest.pkl")
    iso_scaler = joblib.load("/app/models/scaler.pkl")
    dbscan_scaler = joblib.load("/app/models/dbscan_scaler.pkl")
    print("[MODELS] Isolation Forest + DBSCAN loaded")
except Exception as e:
    print(f"[MODELS WARNING] {e}")
    iso_model = None
    iso_scaler = None
app = FastAPI(title="Mobile API Misuse Detector", version="3.0.0")
r = redis.Redis(host='redis', port=6379, decode_responses=True)

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
    ai_scores  = dict(zip(ai_scores_df['ip'], ai_scores_df['risk_score']))
    ai_levels  = dict(zip(ai_scores_df['ip'], ai_scores_df['risk_level']))
    ai_iso     = dict(zip(ai_scores_df['ip'], ai_scores_df['iso_anomaly_score']))
    ai_dbscan  = dict(zip(ai_scores_df['ip'], ai_scores_df['dbscan_anomaly_score']))
    ai_ae      = dict(zip(ai_scores_df['ip'], ai_scores_df['ae_anomaly_score']))
    print(f"[AI] Loaded {len(ai_scores)} IP scores")
except Exception as e:
    print(f"[AI WARNING] Could not load scores: {e}")
    ai_scores = {}; ai_levels = {}; ai_iso = {}; ai_dbscan = {}; ai_ae = {}

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
async def get_llm_recommendation(ip: str, score: int, risk_level: str,
                                  attack_type: str, endpoint: str) -> tuple:
    prompt = f"""You are a senior cybersecurity expert analyzing a REAL ATTACK.

SECURITY EVENT:
- IP: {ip}
- Risk Score: {score}/100 ({risk_level.upper()})
- Attack Type: {attack_type.upper()}
- Endpoint: {endpoint}

Provide a recommendation with EXACTLY these 3 sections:

[IMMEDIATE ACTION] - What to do right now

[INVESTIGATION] - What logs/patterns to analyze

[STRATEGIC MITIGATION] - Long-term improvements

Be concise and professional."""

    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Provide actionable recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            rec = response.choices[0].message.content.strip()
            print(f"[LLM] Recommendation generated for {ip}")
            return rec, "Groq (Llama 3.3 70B)"
        except Exception as e:
            print(f"[LLM] Groq failed: {e}")

    return (
        "[IMMEDIATE ACTION] Block this IP immediately.\n"
        "[INVESTIGATION] Review authentication logs.\n"
        "[STRATEGIC MITIGATION] Implement rate limiting and WAF rules.",
        "Fallback"
    )

# =========================
# SLACK BLOCK KIT
# =========================
def build_slack_alert(entry: LogEntry, final_score: int, risk_level: str,
                      attack_type: str, llm_recommendation: str,
                      llm_provider: str) -> dict:

    filled = final_score // 5
    score_bar = "█" * filled + "░" * (20 - filled)

    risk_emoji = {
        "normal": "🟢", "suspect": "🟡",
        "high": "🟠", "critical": "🔴", "attack": "🚨"
    }.get(risk_level, "⚪")

    attack_emoji = {
        "bruteforce": "🔑", "sql_injection": "💉",
        "enumeration": "🔍", "none": "❓"
    }.get(attack_type, "⚠️")

    country = entry.country if entry.country not in ("unknown", "") else "N/A"
    device  = entry.device_model if entry.device_model not in ("unknown", "") else entry.user_agent[:40]
    detected = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{risk_emoji} Security Alert — {risk_level.upper()} Threat Detected",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Risk Score: `{final_score}/100` — {risk_level.upper()}*\n`{score_bar}` {final_score}%"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*IP Address*\n`{entry.ip}`"},
                {"type": "mrkdwn", "text": f"*Country*\n{country}"},
                {"type": "mrkdwn", "text": f"{attack_emoji} *Attack Type*\n`{attack_type}`"},
                {"type": "mrkdwn", "text": f"*Endpoint*\n`{entry.endpoint}`"},
                {"type": "mrkdwn", "text": f"*Method*\n`{entry.method}`"},
                {"type": "mrkdwn", "text": f"*Device*\n{device}"},
            ]
        },
        {"type": "divider"},
    ]

    if llm_recommendation:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*LLM Recommendation* — _{llm_provider}_\n\n{llm_recommendation[:2800]}"
            }
        })
        blocks.append({"type": "divider"})

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Action:* `block_and_alert` — IP blocked for 15 minutes\n_Detected at {detected} UTC_"
        }
    })

    return {
        "text": f"[{risk_level.upper()}] {entry.ip} — score {final_score}/100 ({attack_type})",
        "blocks": blocks
    }

# =========================
# ROUTES
# =========================
@app.get("/")
def root():
    return {
        "message": "Mobile API Misuse Detector — Rules + AI + Groq LLM",
        "version": "3.0.0"
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "llm_available": groq_client is not None,
        "ai_scores_loaded": len(ai_scores),
        "redis_connected": r.ping()
    }

@app.get("/api/v1/test-llm")
async def test_llm():
    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "Say: GROQ IS WORKING PROPERLY"}],
                max_tokens=20, temperature=0
            )
            return {"status": "ok", "groq": response.choices[0].message.content.strip()}
        except Exception as e:
            return {"status": "error", "groq": str(e)}
    return {"status": "error", "groq": "GROQ_API_KEY not configured"}
def compute_realtime_ai_score(ip: str, entry: LogEntry) -> tuple:
    """Calcule le score IA en temps réel via Redis + modèles pkl"""
    
    key = f"features:{ip}"
    pipe = r.pipeline()
    
    # Incrémenter les compteurs
    pipe.hincrby(key, "request_count", 1)
    pipe.hincrby(key, "login_attempt_count", 1 if entry.endpoint == "/login" else 0)
    pipe.hincrby(key, "failed_login_count", 1 if entry.status == 401 else 0)
    pipe.hincrby(key, "status_404_count", 1 if entry.status == 404 else 0)
    pipe.hincrby(key, "bot_count", 1 if "python-requests" in entry.user_agent.lower() else 0)
    pipe.hincrby(key, "post_count", 1 if entry.method == "POST" else 0)
    pipe.hincrby(key, "mobile_count", 1 if entry.is_mobile else 0)
    pipe.expire(key, 300)  # 5 minutes window
    pipe.execute()

    data = r.hgetall(key)
    req_count = max(int(data.get("request_count", 1)), 1)
    failed    = int(data.get("failed_login_count", 0))
    bot       = int(data.get("bot_count", 0))
    post      = int(data.get("post_count", 0))
    mobile    = int(data.get("mobile_count", 0))
    login     = int(data.get("login_attempt_count", 0))
    s404      = int(data.get("status_404_count", 0))

    features = np.array([[
        req_count,                                      # request_count
        req_count,                                      # max_req_count_5min
        req_count,                                      # avg_req_count_5min
        req_count / 300.0,                              # requests_per_second
        300.0 / req_count,                              # avg_time_between_requests
        1,                                              # unique_endpoints
        1,                                              # unique_ids_accessed
        s404,                                           # status_404_count
        failed / req_count,                             # max_error_rate_5min
        bot / req_count,                                # suspicious_ua_ratio
        bot / req_count,                                # bot_ratio
        mobile / req_count,                             # mobile_ratio
        post / req_count,                               # post_frequency
        req_count,                                      # max_repeated_endpoint_hits
        login,                                          # login_attempt_count
        failed,                                         # failed_login_count
        failed / max(login, 1),                         # failed_login_rate
        login,                                          # max_login_req_per_min
        300.0 / max(login, 1)                           # avg_time_between_login_attempts
    ]])

    if iso_model is None or iso_scaler is None:
        return 0.0, "unknown"

    try:
        features_scaled = iso_scaler.transform(features)
        prediction = iso_model.predict(features_scaled)  # -1=anomalie, 1=normal
        score_raw = iso_model.decision_function(features_scaled)[0]
        
        # Convertir en score 0-1
        # decision_function : négatif = anomalie, positif = normal
        ai_score = max(0.0, min(1.0, -score_raw + 0.5))
        
        if ai_score >= 0.7:
            ai_level = "Critical"
        elif ai_score >= 0.5:
            ai_level = "High"
        elif ai_score >= 0.3:
            ai_level = "Medium"
        else:
            ai_level = "Low"
            
        return round(ai_score, 3), ai_level
        
    except Exception as e:
        print(f"[AI ERROR] {e}")
        return 0.0, "unknown"
@app.post("/api/v1/analyze")
async def analyze(entry: LogEntry):

    # Nettoyer l'IP
    clean_ip = entry.ip.replace("::ffff:", "").strip()
    entry.ip = clean_ip

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

    suspicious_endpoints = ["/admin", "/config", "/debug", "/env", "/.env"]
    if any(e in entry.endpoint for e in suspicious_endpoints):
        rule_score += 20

    sql_patterns = ["UNION", "SELECT", "DROP", "INSERT", "passwd", "etc/passwd"]
    if any(p.lower() in entry.endpoint.lower() for p in sql_patterns):
        rule_score += 30

    rule_score = min(rule_score, 100)

    # =========================
    # SCORES IA
    # =========================
    # Nouveau — score IA en temps réel
    ai_score_realtime, ai_level_realtime = compute_realtime_ai_score(clean_ip, entry)

    # Combiner lookup CSV + temps réel
    ai_score_csv = ai_scores.get(clean_ip, 0)
    ai_level_csv = ai_levels.get(clean_ip, "unknown")

    # Prendre le max des deux
    # Toujours récupérer iso/dbscan/ae du CSV
    iso_score    = ai_iso.get(clean_ip, 0)
    dbscan_score = ai_dbscan.get(clean_ip, 0)
    ae_score     = ai_ae.get(clean_ip, 0)

    if ai_score_csv > 0:
        ai_score = max(ai_score_csv, ai_score_realtime)
        ai_level = ai_level_csv if ai_score_csv >= ai_score_realtime else ai_level_realtime
    else:
        ai_score = ai_score_realtime
        ai_level = ai_level_realtime

    # Score final : 60% règles + 40% IA
    if ai_score > 0:
        final_score = int((rule_score * 0.6) + (ai_score * 100 * 0.4))
        final_score = min(final_score, 100)
    else:
        final_score = rule_score

    action     = get_action(final_score)
    risk_level = get_risk_level(final_score)

    # =========================
    # TYPE D'ATTAQUE
    # =========================
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

    # =========================
    # RATE LIMITING
    # =========================
    if final_score >= 60:
        limit = 20 if final_score < 90 else 5
        allowed, remaining = token_bucket_check(entry.ip, limit, 60, r)
        if not allowed:
            action = "blocked"
            r.setex(f"block:{entry.ip}", 900, 1)

    r.set(f"score:{entry.ip}", final_score)

    # =========================
    # LLM RECOMMANDATION (score >= 60)
    # =========================
    llm_recommendation = ""
    llm_provider = ""
    if final_score >= 60:
        llm_recommendation, llm_provider = await get_llm_recommendation(
            entry.ip, final_score, risk_level, attack_type, entry.endpoint
        )

    # =========================
    # BLOCAGE + ALERTE SLACK (score >= 75)
    # =========================
    if final_score >= 75:
        r.setex(f"block:{entry.ip}", 900, 1)
        r.lpush("alerts", f"{entry.ip}|{final_score}|{entry.endpoint}")

        alert_key = f"alerted:{entry.ip}"
        if not r.exists(alert_key) and SLACK_WEBHOOK:
            r.setex(alert_key, 900, 1)
            slack_payload = build_slack_alert(
                entry=entry,
                final_score=final_score,
                risk_level=risk_level,
                attack_type=attack_type,
                llm_recommendation=llm_recommendation,
                llm_provider=llm_provider
            )
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(SLACK_WEBHOOK, json=slack_payload, timeout=5)
                    print(f"[SLACK] Alert sent for {entry.ip}")
            except Exception as e:
                print(f"[SLACK WARNING] {e}")

    # =========================
    # INDEX ELASTICSEARCH
    # =========================
    log_doc = {
        "timestamp":          datetime.utcnow().isoformat() + "Z",
        "ip":                 entry.ip,
        "method":             entry.method,
        "endpoint":           entry.endpoint,
        "status":             entry.status,
        "latency_ms":         entry.latency_ms,
        "user_agent":         entry.user_agent,
        "is_mobile":          entry.is_mobile,
        "platform":           entry.platform,
        "country":            entry.country,
        "device_model":       entry.device_model,
        "device_type":        entry.device_type,
        "failed_attempts":    entry.failed_attempts,
        "rule_score":         rule_score,
        "ai_score":           ai_score,
        "ai_level":           ai_level,
        "iso_forest_score":   iso_score,
        "dbscan_score":       dbscan_score,
        "autoencoder_score":  ae_score,
        "risk_score":         final_score,
        "risk_level":         risk_level,
        "attack_type":        attack_type,
        "action":             action,
        "blocked":            final_score >= 75,
        "llm_recommendation": llm_recommendation[:2000] if llm_recommendation else "",
        "llm_provider":       llm_provider
    }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{ES_URL}/mobile-api-logs-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc",
                json=log_doc, timeout=5
            )
        print(f"[ES] Indexed {entry.ip} score={final_score} action={action}")
    except Exception as e:
        print(f"[ES WARNING] {e}")

    return {
        "ip":                 entry.ip,
        "score":              final_score,
        "risk_level":         risk_level,
        "action":             action,
        "attack_type":        attack_type,
        "blocked":            final_score >= 75,
        "llm_provider":       llm_provider,
        "llm_recommendation": llm_recommendation if final_score >= 60 else None
    }

# =========================
# ROUTES SUPPLEMENTAIRES
# =========================
@app.get("/api/v1/status/{ip}")
async def status(ip: str):
    return {
        "ip":        ip,
        "blocked":   bool(r.exists(f"block:{ip}")),
        "block_ttl": r.ttl(f"block:{ip}"),
        "score":     int(r.get(f"score:{ip}") or 0)
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

# =========================
# UTILITAIRES
# =========================
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
