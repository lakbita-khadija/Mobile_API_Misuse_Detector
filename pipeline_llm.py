import json
import httpx
import asyncio
import os

API_URL = "http://localhost:8000/api/v1/analyze"
OPENAI_KEY = os.getenv("OPENAI_API_KEY")

async def get_recommendation(ip, score, attack_type, endpoint):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-3.5-turbo",
                "max_tokens": 200,
                "messages": [
                    {"role": "system", "content": "Tu es expert en cybersécurité. Réponds en 3 points courts."},
                    {"role": "user", "content": f"Attaque détectée: IP={ip}, score={score}/100, type={attack_type}, endpoint={endpoint}. Que faire?"}
                ]
            },
            timeout=30
        )
        data = resp.json()
        print(f"  DEBUG: {data}")
        if "choices" in data:
            return data["choices"][0]["message"]["content"]
        else:
            return f"Erreur API: {data.get('error', {}).get('message', 'inconnue')}"

async def process_logs():
    print("📂 Lecture security.log...")
    
    with open("backend-express/logs/security.log", "r") as f:
        lines = f.readlines()
    
    print(f"📊 {len(lines)} logs total")
    
    attack_lines = [l for l in lines if '"status":401' in l or '"status":403' in l]
    print(f"🎯 {len(attack_lines)} logs suspects trouvés (401/403)")
    
    attacked = 0
    
    for i, line in enumerate(attack_lines[:50]):
        try:
            log = json.loads(line)
            msg = log.get("message", {})
            
            entry = {
                "ip": msg.get("ip", "unknown").replace("::ffff:", ""),
                "method": msg.get("method", "GET"),
                "endpoint": msg.get("endpoint", "/"),
                "status": msg.get("status", 200),
                "latency_ms": msg.get("response_time_ms", 100),
                "user_agent": msg.get("user_agent", "unknown"),
                "is_mobile": msg.get("device_type") == "mobile",
                "platform": "mobile"
            }
            
            async with httpx.AsyncClient() as client:
                resp = await client.post(API_URL, json=entry, timeout=5)
                result = resp.json()
            
            score = result.get("score", 0)
            print(f"[{i+1}] IP={entry['ip']} Score={score} Action={result.get('action')}")
            
            if score >= 90:
                attacked += 1
                print(f"  🚨 ATTAQUE CRITIQUE ! Appel GPT...")
                rec = await get_recommendation(
                    entry["ip"],
                    score,
                    result.get("risk_level"),
                    entry["endpoint"]
                )
                print(f"  💡 Recommandation:\n{rec}\n")
            
            await asyncio.sleep(0.1)
            
        except Exception as e:
            print(f"[{i+1}] Erreur: {e}")
    
    print(f"\n✅ Terminé ! {attacked} attaques critiques détectées.")

if __name__ == "__main__":
    asyncio.run(process_logs())
