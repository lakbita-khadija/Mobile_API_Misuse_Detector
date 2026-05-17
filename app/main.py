from fastapi import FastAPI
from pydantic import BaseModel
import redis
import httpx
import os
import pandas as pd
from datetime import datetime, timedelta
from app.response.ratelimit import token_bucket_check
from groq import Groq

ES_URL = "http://elasticsearch:9200"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

app = FastAPI(title="Mobile API Misuse Detector", version="3.0.0")

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
# FONCTION LLM AMELIOREE
# =========================

async def get_llm_recommendation(
    ip: str,
    score: int,
    risk_level: str,
    attack_type: str,
    endpoint: str,
    country: str,
    rule_score: int,
    ai_score: float,
    iso_score: int,
    dbscan_score: int,
    ae_score: int
) -> tuple:
    """
    Génère une recommandation cybersécurité détaillée via Groq LLM.
    Prompt professionnel structuré pour une réponse actionnable.
    """

    prompt = f"""You are a senior cybersecurity analyst in a SOC (Security Operations Center). 
A confirmed attack has been detected by our AI-powered API Misuse Detection System.

=== SECURITY EVENT DETAILS ===
- IP Address: {ip}
- Country: {country if country else "Unknown"}
- Endpoint: {endpoint}
- HTTP Method: POST
- Attack Type: {attack_type.upper()}
- Risk Score: {score}/100
- Risk Level: {risk_level.upper()}

=== DETECTION BREAKDOWN ===
- Rule-based Score: {rule_score}/100
- AI Model Score: {ai_score}/100
- Isolation Forest: {"ANOMALY" if iso_score == 1 else "NORMAL"}
- DBSCAN Clustering: {"OUTLIER" if dbscan_score == 1 else "NORMAL"}
- Autoencoder: {"HIGH RECONSTRUCTION ERROR" if ae_score == 1 else "NORMAL"}

=== YOUR TASK ===
Provide a professional, actionable security recommendation with EXACTLY these three sections:

[IMMEDIATE ACTION]
- What should the SOC team do RIGHT NOW?
- Specific commands, firewall rules, or WAF configurations?
- Should this IP be blocked permanently or temporarily?

[INVESTIGATION]
- What logs should be analyzed?
- What patterns or IOCs (Indicators of Compromise) to look for?
- Are there related IPs or accounts to check?

[STRATEGIC MITIGATION]
- What long-term security improvements are recommended?
- How to prevent similar attacks in the future?
- What security controls (MFA, WAF, Rate Limiting, etc.) should be implemented?

=== CONSTRAINTS ===
- Be concise but thorough (maximum 400 words)
- Use professional security terminology
- NEVER say the traffic is "safe" - this is a confirmed attack
- Provide specific, actionable advice, not generic statements

Generate the recommendation now:"""

    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a senior cybersecurity expert in a SOC. "
                            "You analyze real attacks detected by AI systems. "
                            "Your recommendations are actionable, specific, and professional. "
                            "You NEVER say an attack is 'safe'."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=600
            )

            recommendation = response.choices[0].message.content.strip()
            print(f"[LLM] Recommendation generated for {ip} ({len(recommendation)} chars)")
            return recommendation, "Groq - Llama 3.3 70B"

        except Exception as e:
            print(f"[LLM ERROR] {e}")

    fallback = (
        f"[IMMEDIATE ACTION] Block IP {ip} at firewall level immediately. "
        f"Implement rate limiting of 5 requests per minute for endpoint {endpoint}.\n\n"
        f"[INVESTIGATION] Review authentication logs for the past 24 hours. "
        f"Check for failed login attempts from this IP or related IPs.\n\n"
        f"[STRATEGIC MITIGATION] Deploy multi-factor authentication (MFA) for all accounts. "
        f"Implement Web Application Firewall (WAF) with brute force protection rules."
    )

    return fallback, "Fallback - No LLM"

# =========================
# FONCTION INDEXATION ALERTES
# =========================

async def index_abuse_alert(
    ip: str,
    score: int,
    risk_level: str,
    attack_type: str,
    endpoint: str,
    method: str,
    country: str,
    rule_score: int,
    ai_score: float,
    iso_score: int,
    dbscan_score: int,
    ae_score: int,
    llm_recommendation: str,
    llm_provider: str,
    action: str
):
    """Indexe une alerte d'abus dans Elasticsearch"""
    
    alert_doc = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "alert_id": f"alert_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{ip.replace('.', '_')}",
        "ip": ip,
        "country": country,
        "attack_type": attack_type,
        "endpoint": endpoint,
        "method": method,
        "risk_score": score,
        "risk_level": risk_level,
        "rule_score": rule_score,
        "ai_score": ai_score,
        "ai_level": "Critical" if ai_score >= 0.9 else "High" if ai_score >= 0.7 else "Medium",
        "iso_forest_score": iso_score,
        "dbscan_score": dbscan_score,
        "autoencoder_score": ae_score,
        "llm_recommendation": llm_recommendation[:2000] if llm_recommendation else "",
        "llm_provider": llm_provider,
        "action_taken": action,
        "blocked": True,
        "block_duration_seconds": 900,
        "blocked_until": (datetime.utcnow() + timedelta(seconds=900)).isoformat() + "Z",
        "status": "active",
        "resolved": False,
        "resolved_at": None,
        "resolved_by": None,
        "severity": "CRITICAL" if score >= 90 else "HIGH" if score >= 75 else "MEDIUM",
        "source": "Mobile API Misuse Detector v3.0",
        "environment": "production"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ES_URL}/abuse-alerts/_doc",
                json=alert_doc,
                timeout=5
            )
            print(f"[ES] Abuse alert indexed for {ip} with ID: {response.json().get('_id')}")
            return response.json().get('_id')
    except Exception as e:
        print(f"[ES ALERT WARNING] Could not index abuse alert: {e}")
        return None

# =========================
# ROUTES
# =========================

@app.get("/")
def root():
    return {
        "message": "Mobile API Misuse Detector running with Rules + AI + Groq LLM",
        "version": "3.0.0",
        "features": [
            "Rule-based detection (bruteforce, enumeration, SQL injection)",
            "AI models (Isolation Forest, DBSCAN, Autoencoder)",
            "Groq LLM for security recommendations",
            "Redis for rate limiting and IP blocking",
            "Elasticsearch for logs and alerts",
            "Slack alerts for critical incidents"
        ]
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "llm_available": groq_client is not None,
        "groq_configured": bool(GROQ_API_KEY),
        "ai_scores_loaded": len(ai_scores),
        "redis_connected": r.ping(),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@app.get("/api/v1/test-llm")
async def test_llm():
    """Test rapide pour vérifier Groq."""
    if not groq_client:
        return {"status": "error", "message": "GROQ_API_KEY not configured"}
    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": "Say exactly: GROQ IS WORKING PROPERLY"}],
            temperature=0,
            max_tokens=20
        )
        return {"status": "ok", "groq": response.choices[0].message.content.strip()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 50, status_filter: str = "active"):
    """Récupère les alertes d'abus depuis Elasticsearch"""
    query = {
        "size": limit,
        "query": {"term": {"status": status_filter}} if status_filter != "all" else {"match_all": {}},
        "sort": [{"timestamp": "desc"}]
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ES_URL}/abuse-alerts/_search",
                json=query,
                timeout=5
            )
            return response.json()
    except Exception as e:
        return {"error": str(e), "alerts": []}

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
    suspicious_endpoints = ["/admin", "/config", "/debug", "/env", "/.env"]
    if any(e in entry.endpoint.lower() for e in suspicious_endpoints):
        rule_score += 20
    sql_patterns = ["union", "select", "drop", "insert", "passwd", "etc/passwd", "' or '1'='1", '" or "1"="1']
    if any(p in entry.endpoint.lower() for p in sql_patterns):
        rule_score += 30
    rule_score = min(rule_score, 100)

    # =========================
    # DETECTION TYPE ATTAQUE
    # =========================
    if entry.failed_attempts >= 3 or (entry.status == 401 and "python-requests" in entry.user_agent.lower()):
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
        return {
            "ip": entry.ip,
            "score": final_score,
            "action": "blocked",
            "message": "IP is currently blocked. Please wait 15 minutes.",
            "block_ttl": r.ttl(f"block:{entry.ip}")
        }

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
    # =========================
    llm_recommendation = ""
    llm_provider = ""
    if final_score >= 50 and attack_type != "none":
        llm_recommendation, llm_provider = await get_llm_recommendation(
            entry.ip, final_score, risk_level, attack_type,
            entry.endpoint, entry.country, rule_score,
            ai_score, iso_score, dbscan_score, ae_score
        )

    # =========================
    # BLOCAGE + SLACK + ALERTES
    # =========================
    blocked = False
    alert_id = None

    if final_score >= 70:
        blocked = True
        action = "block_and_alert"
        r.setex(f"block:{entry.ip}", 900, 1)
        r.lpush("alerts", f"{entry.ip}|{final_score}|{attack_type}|{entry.endpoint}")
        print(f"[REDIS] IP {entry.ip} blocked for 15 minutes. Score={final_score}")

        # INDEXER L'ALERTE DANS ELASTICSEARCH
        alert_id = await index_abuse_alert(
            entry.ip, final_score, risk_level, attack_type,
            entry.endpoint, entry.method, entry.country,
            rule_score, ai_score, iso_score, dbscan_score, ae_score,
            llm_recommendation, llm_provider, action
        )

        # ALERTE SLACK
        alert_key = f"alerted:{entry.ip}"
        if not r.exists(alert_key) and SLACK_WEBHOOK:
            r.setex(alert_key, 900, 1)
            slack_msg = build_slack_alert(
                entry, final_score, risk_level, attack_type,
                rule_score, ai_score, ai_level, iso_score,
                dbscan_score, ae_score, llm_recommendation,
                llm_provider, action, alert_id
            )
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(SLACK_WEBHOOK, json=slack_msg, timeout=5)
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
        "alert_id": alert_id,
        "llm_recommendation": llm_recommendation[:2000] if llm_recommendation else "",
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
        "alert_id": alert_id,
        "llm_provider": llm_provider,
        "llm_recommendation": llm_recommendation if llm_recommendation else None
    }

# =========================
# FONCTIONS UTILITAIRES
# =========================

def build_slack_alert(entry, final_score, risk_level, attack_type, rule_score,
                      ai_score, ai_level, iso_score, dbscan_score, ae_score,
                      llm_recommendation, llm_provider, action, alert_id):
    """Construit le message Slack professionnel"""
    return {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "🚨 SECURITY ALERT — Mobile API Misuse Detector"}},
            {"type": "divider"},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*IP Address:*\n`{entry.ip}`"},
                {"type": "mrkdwn", "text": f"*Country:*\n`{entry.country}`"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Risk Score:*\n`{final_score}/100` — {risk_level.upper()}"},
                {"type": "mrkdwn", "text": f"*Attack Type:*\n`{attack_type}`"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Endpoint:*\n`{entry.endpoint}`"},
                {"type": "mrkdwn", "text": f"*Method:*\n`{entry.method}`"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Rule Score:*\n`{rule_score}`"},
                {"type": "mrkdwn", "text": f"*AI Score:*\n`{ai_score}` ({ai_level})"}
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Isolation Forest:*\n`{iso_score}`"},
                {"type": "mrkdwn", "text": f"*DBSCAN / AE:*\n`{dbscan_score}` / `{ae_score}`"}
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Action:* `{action}` — IP blocked for 15 minutes"}},
            {"type": "divider"} if llm_recommendation else {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*🤖 LLM Recommendation ({llm_provider}):*\n{llm_recommendation}"}} if llm_recommendation else {},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Alert ID: {alert_id} | Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"}]}
        ]
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
    threats = [{"ip": k.split(":")[1], "score": int(r.get(k) or 0)} for k in keys]
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
    return "block_and_alert"
