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

async def get_llm_recommendation(ip: str, score: int, risk_level: str, attack_type: str, endpoint: str) -> tuple:
    """Génère une recommandation de sécurité détaillée avec Groq"""
    
    prompt = f"""You are a senior cybersecurity expert analyzing a REAL ATTACK detected by our AI system.

SECURITY EVENT (CONFIRMED ATTACK - NOT SAFE):
- IP Address: {ip}
- Risk Score: {score}/100 ({risk_level.upper()})
- Attack Type: {attack_type.upper()}
- Endpoint: {endpoint}
- This is a MALICIOUS attack, not normal traffic.

Provide a professional security recommendation with these EXACT sections:

[IMMEDIATE ACTION] - What to do right now (block, rate limit, etc.)

[INVESTIGATION] - What logs and patterns to analyze

[STRATEGIC MITIGATION] - Long-term security improvements

Be specific, actionable, and professional. NEVER say "safe" for attack data. Write in complete sentences."""

    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing REAL attacks. Never say 'safe'. Provide detailed, actionable recommendations with 3 sections: IMMEDIATE ACTION, INVESTIGATION, STRATEGIC MITIGATION."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=600
            )
            recommendation = response.choices[0].message.content.strip()
            print(f"[LLM] Groq generated recommendation for {ip} ({len(recommendation)} chars)")
            return recommendation, "Groq (Llama 3.3 70B)"
        except Exception as e:
            print(f"[LLM] Groq failed: {e}")
    
    return "BLOCK THIS IP IMMEDIATELY - Attack detected. Review authentication logs and implement rate limiting.", "Fallback (No LLM)"

# =========================
# FONCTION POUR CONSTRUIRE LE MESSAGE SLACK (Block Kit)
# =========================

def build_slack_alert(
    entry: LogEntry,
    final_score: int,
    risk_level: str,
    attack_type: str,
    rule_score: int,
    ai_score: float,
    ai_level: str,
    llm_recommendation: str,
    llm_provider: str
) -> dict:
    """
    Construit un message Slack structuré avec Block Kit.
    Rendu visuel : header coloré, champs en grille 2 colonnes,
    barre de score, bloc LLM distinct, bouton d'action.
    """

    score_bar = "█" * (final_score // 10) + "░" * (10 - final_score // 10)

    risk_emoji = {
        "normal":   "🟢",
        "suspect":  "🟡",
        "high":     "🟠",
        "critical": "🔴",
        "attack":   "🚨",
    }.get(risk_level, "⚪")

    attack_emoji = {
        "bruteforce":    "🔑",
        "sql_injection": "💉",
        "enumeration":   "🔍",
        "none":          "❓",
    }.get(attack_type, "⚠️")

    country = entry.country if entry.country and entry.country != "unknown" else "N/A"
    device  = entry.device_model if entry.device_model and entry.device_model != "unknown" else entry.user_agent[:40]

    blocks = [
        # ── HEADER ──────────────────────────────────────────────────
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{risk_emoji} Security Alert — {risk_level.upper()} Threat Detected",
                "emoji": True
            }
        },

        # ── SCORE + BARRE ────────────────────────────────────────────
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Risk Score:* `{final_score}/100` — *{risk_level.upper()}*\n"
                    f"`{score_bar}` {final_score}%"
                )
            }
        },

        {"type": "divider"},

        # ── CHAMPS PRINCIPAUX (2 colonnes) ───────────────────────────
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*🌐 IP Address*\n`{entry.ip}`"},
                {"type": "mrkdwn", "text": f"*🏳️ Country*\n{country}"},
                {"type": "mrkdwn", "text": f"*{attack_emoji} Attack Type*\n`{attack_type}`"},
                {"type": "mrkdwn", "text": f"*📍 Endpoint*\n`{entry.endpoint}`"},
                {"type": "mrkdwn", "text": f"*🔧 Method*\n`{entry.method}`"},
                {"type": "mrkdwn", "text": f"*📱 Device*\n{device}"},
            ]
        },

        {"type": "divider"},

        # ── SCORES DÉTAILLÉS ─────────────────────────────────────────
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Rule Score*\n`{rule_score}/100`"},
                {"type": "mrkdwn", "text": f"*AI Score*\n`{round(ai_score * 100)}/100` ({ai_level})"},
            ]
        },

        {"type": "divider"},
    ]

    # ── RECOMMANDATION LLM (si disponible) ──────────────────────────
    if llm_recommendation:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🤖 LLM Recommendation* — _{llm_provider}_\n\n{llm_recommendation[:2800]}"
            }
        })
        blocks.append({"type": "divider"})

    # ── ACTION + FOOTER ──────────────────────────────────────────────
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": (
                f"*Action taken:* 🔒 `block_and_alert` — IP blocked for *15 minutes*\n"
                f"_Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC · Groq LLM Engine_"
            )
        }
    })

    return {
        "text": f"[{risk_level.upper()}] Security Alert — {entry.ip} scored {final_score}/100 ({attack_type})",
        "blocks": blocks
    }

# =========================
# ROUTES
# =========================

@app.get("/")
def root():
    return {
        "message": "Mobile API Misuse Detector with Rules + AI + Groq LLM",
        "version": "3.0.0"
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "llm_available": groq_client is not None,
        "groq": groq_client is not None,
        "ai_scores_loaded": len(ai_scores),
        "redis_connected": r.ping()
    }

@app.get("/api/v1/test-llm")
async def test_llm():
    """Test endpoint pour vérifier que Groq fonctionne"""
    if groq_client:
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "Say: GROQ IS WORKING PROPERLY"}],
                max_tokens=20,
                temperature=0
            )
            return {"status": "ok", "groq": response.choices[0].message.content.strip()}
        except Exception as e:
            return {"status": "error", "groq": str(e)}
    return {"status": "error", "groq": "GROQ_API_KEY not configured"}

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
    if any(e in entry.endpoint for e in suspicious_endpoints):
        rule_score += 20

    sql_patterns = ["UNION", "SELECT", "DROP", "INSERT", "passwd", "etc/passwd"]
    if any(p.lower() in entry.endpoint.lower() for p in sql_patterns):
        rule_score += 30

    rule_score = min(rule_score, 100)

    # =========================
    # SCORES IA
    # =========================
    ai_score  = ai_scores.get(entry.ip, 0)
    ai_level  = ai_levels.get(entry.ip, "unknown")
    iso_score = ai_iso.get(entry.ip, 0)
    dbscan_score = ai_dbscan.get(entry.ip, 0)
    ae_score  = ai_ae.get(entry.ip, 0)

    # Score final combiné : 60% règles + 40% IA
    if ai_score > 0:
        final_score = int((rule_score * 0.6) + (ai_score * 100 * 0.4))
        final_score = min(final_score, 100)
    else:
        final_score = rule_score

    action     = get_action(final_score)
    risk_level = get_risk_level(final_score)

    # =========================
    # VERIFIER SI IP DEJA BLOQUEE
    # =========================
    if r.exists(f"block:{entry.ip}"):
        return {
            "ip": entry.ip,
            "score": final_score,
            "risk_level": risk_level,
            "action": "blocked",
            "attack_type": "none",
            "message": "IP is currently blocked. Please wait 15 minutes."
        }

    # =========================
    # RATE LIMITING
    # =========================
    if final_score >= 60:
        limit = 20 if final_score < 90 else 5
        allowed, remaining = token_bucket_check(entry.ip, limit, 60, r)
        if not allowed:
            action = "blocked"
            r.setex(f"block:{entry.ip}", 900, 1)
            print(f"[REDIS] Rate limit exceeded - IP {entry.ip} blocked for 15 minutes")

    r.set(f"score:{entry.ip}", final_score)

    # =========================
    # DETECTION TYPE ATTAQUE
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
    # LLM RECOMMANDATION
    # =========================
    llm_recommendation = ""
    llm_provider = ""
    if final_score >= 75:
        llm_recommendation, llm_provider = await get_llm_recommendation(
            entry.ip, final_score, risk_level, attack_type, entry.endpoint
        )

    # =========================
    # BLOCAGE REDIS + ALERTE SLACK
    # =========================
    if final_score >= 90:
        r.setex(f"block:{entry.ip}", 900, 1)
        print(f"[REDIS] IP {entry.ip} BLOCKED for 15 minutes (score={final_score})")
        r.lpush("alerts", f"{entry.ip}|{final_score}|{entry.endpoint}")

        alert_key = f"alerted:{entry.ip}"
        if not r.exists(alert_key) and SLACK_WEBHOOK:
            r.setex(alert_key, 900, 1)

            slack_payload = build_slack_alert(
                entry=entry,
                final_score=final_score,
                risk_level=risk_level,
                attack_type=attack_type,
                rule_score=rule_score,
                ai_score=ai_score,
                ai_level=ai_level,
                llm_recommendation=llm_recommendation,
                llm_provider=llm_provider
            )

            try:
                async with httpx.AsyncClient() as client:
                    await client.post(SLACK_WEBHOOK, json=slack_payload, timeout=5)
                    print(f"[SLACK] Block Kit alert sent for {entry.ip}")
            except Exception as e:
                print(f"[SLACK WARNING] {e}")

    # =========================
    # INDEX ELASTICSEARCH
    # =========================
    log_doc = {
        "timestamp":         datetime.utcnow().isoformat() + "Z",
        "ip":                entry.ip,
        "method":            entry.method,
        "endpoint":          entry.endpoint,
        "status":            entry.status,
        "latency_ms":        entry.latency_ms,
        "user_agent":        entry.user_agent,
        "is_mobile":         entry.is_mobile,
        "platform":          entry.platform,
        "country":           entry.country,
        "device_model":      entry.device_model,
        "device_type":       entry.device_type,
        "failed_attempts":   entry.failed_attempts,
        "rule_score":        rule_score,
        "ai_score":          ai_score,
        "ai_level":          ai_level,
        "iso_forest_score":  iso_score,
        "dbscan_score":      dbscan_score,
        "autoencoder_score": ae_score,
        "risk_score":        final_score,
        "risk_level":        risk_level,
        "attack_type":       attack_type,
        "action":            action,
        "blocked":           final_score >= 90,
        "llm_recommendation": llm_recommendation[:2000] if llm_recommendation else "",
        "llm_provider":      llm_provider
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
        "ip":               entry.ip,
        "score":            final_score,
        "rule_score":       rule_score,
        "ai_score":         ai_score,
        "ai_level":         ai_level,
        "iso_forest_score": iso_score,
        "dbscan_score":     dbscan_score,
        "autoencoder_score":ae_score,
        "risk_level":       risk_level,
        "action":           action,
        "attack_type":      attack_type,
        "blocked":          final_score >= 90,
        "llm_provider":     llm_provider,
        "llm_recommendation": llm_recommendation if final_score >= 75 else None
    }

# =========================
# ROUTES SUPPLEMENTAIRES
# =========================

@app.get("/api/v1/status/{ip}")
async def status(ip: str):
    return {
        "ip":       ip,
        "blocked":  bool(r.exists(f"block:{ip}")),
        "block_ttl": r.ttl(f"block:{ip}"),
        "score":    int(r.get(f"score:{ip}") or 0)
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
# FONCTIONS UTILITAIRES
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
