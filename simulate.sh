#!/bin/bash
echo "🎬 Simulation en cours..."

# Trafic normal
echo "👤 Trafic normal..."
for i in {1..5}; do
  curl -s -X POST http://localhost:8000/api/v1/analyze \
    -H "Content-Type: application/json" \
    -d "{\"ip\":\"192.168.1.$i\",\"method\":\"GET\",\"endpoint\":\"/api/products\",\"status\":200,\"latency_ms\":120,\"user_agent\":\"Mozilla/5.0\"}" > /dev/null
  sleep 0.2
done

# Bruteforce
echo "🔨 Attaque bruteforce..."
for i in {1..15}; do
  curl -s -X POST http://localhost:8000/api/v1/analyze \
    -H "Content-Type: application/json" \
    -d '{"ip":"10.0.0.99","method":"POST","endpoint":"/api/login","status":401,"latency_ms":50,"user_agent":"python-requests/2.28"}' > /dev/null
  sleep 0.2
done

# Bot scanner
echo "🤖 Bot scanner..."
for ep in "/admin" "/config" "/.env" "/debug"; do
  curl -s -X POST http://localhost:8000/api/v1/analyze \
    -H "Content-Type: application/json" \
    -d "{\"ip\":\"185.220.101.5\",\"method\":\"GET\",\"endpoint\":\"$ep\",\"status\":403,\"latency_ms\":30,\"user_agent\":\"python-requests/2.28\"}" > /dev/null
  sleep 0.2
done

echo "✅ Simulation terminée!"
