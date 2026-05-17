import json
import httpx
import asyncio

ES_URL = "http://localhost:9200"

async def index_logs():
    print("📂 Lecture security.log...")
    
    with open("backend-express/logs/security.log", "r") as f:
        lines = f.readlines()
    
    print(f"📊 {len(lines)} logs à indexer")
    indexed = 0
    errors = 0
    
    async with httpx.AsyncClient() as client:
        for i, line in enumerate(lines):
            try:
                log = json.loads(line)
                msg = log.get("message", {})
                
                doc = {
                    "timestamp": msg.get("timestamp"),
                    "ip": msg.get("ip", "").replace("::ffff:", ""),
                    "endpoint": msg.get("endpoint", "/"),
                    "method": msg.get("method", "GET"),
                    "status": msg.get("status", 200),
                    "latency_ms": msg.get("response_time_ms", 0),
                    "user_agent": msg.get("user_agent", ""),
                    "device_type": msg.get("device_type", ""),
                    "device_model": msg.get("device_model", ""),
                    "country": msg.get("country", ""),
                    "failed_attempts": msg.get("failed_attempts", 0)
                }
                
                await client.post(
                    f"{ES_URL}/security-logs-2026.05.17/_doc",
                    json=doc,
                    timeout=5
                )
                indexed += 1
                
                if i % 1000 == 0:
                    print(f"  [{i}/{len(lines)}] indexés...")
                    
            except Exception as e:
                errors += 1
                continue
    
    print(f"\n✅ Terminé ! {indexed} logs indexés, {errors} erreurs")

if __name__ == "__main__":
    asyncio.run(index_logs())
