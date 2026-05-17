#!/bin/bash

echo "🚨 GÉNÉRATION DE TOUS LES TYPES D'ATTAQUES 🚨"
echo ""

# 1. Bruteforce - IPs critiques connues
echo "1. Bruteforce attacks (score 90-94)..."
CRITICAL_IPS=("93.110.220.181" "106.226.178.87" "151.25.29.64" "40.77.167.13" "207.46.13.9" "91.99.72.15")
for ip in "${CRITICAL_IPS[@]}"; do
  for i in {1..10}; do
    curl -s -X POST http://localhost:8000/api/v1/analyze \
      -H "Content-Type: application/json" \
      -d "{\"ip\":\"$ip\",\"method\":\"POST\",\"endpoint\":\"/login\",\"status\":401,\"latency_ms\":50,\"user_agent\":\"python-requests/2.25\",\"country\":\"RU\",\"device_model\":\"Unknown\"}" > /dev/null
  done
  echo "   $ip: 10 attaques"
done

# 2. Enumeration attacks
echo ""
echo "2. Enumeration attacks (score 70-85)..."
ENUM_IPS=("185.220.101.5" "45.155.205.233" "94.102.61.78")
ENDPOINTS=("/admin" "/config" "/debug" "/env" "/.env" "/backup" "/wp-admin" "/phpmyadmin" "/api/v1/internal")

for ip in "${ENUM_IPS[@]}"; do
  for endpoint in "${ENDPOINTS[@]}"; do
    curl -s -X POST http://localhost:8000/api/v1/analyze \
      -H "Content-Type: application/json" \
      -d "{\"ip\":\"$ip\",\"method\":\"GET\",\"endpoint\":\"$endpoint\",\"status\":403,\"latency_ms\":30,\"user_agent\":\"python-requests/2.28\",\"country\":\"DE\",\"device_model\":\"Linux\"}" > /dev/null
  done
  echo "   $ip: ${#ENDPOINTS[@]} attaques"
done

# 3. SQL Injection attacks
echo ""
echo "3. SQL Injection attacks (score 70-85)..."
SQL_IPS=("66.249.66.91" "185.130.5.253" "193.70.81.14")
PAYLOADS=("UNION SELECT password" "OR 1=1" "DROP TABLE users" "SELECT * FROM" "1=1--" "'; DROP TABLE" "OR '1'='1" "AND 1=1")

for ip in "${SQL_IPS[@]}"; do
  for payload in "${PAYLOADS[@]}"; do
    curl -s -X POST http://localhost:8000/api/v1/analyze \
      -H "Content-Type: application/json" \
      -d "{\"ip\":\"$ip\",\"method\":\"GET\",\"endpoint\":\"/search?q=$payload\",\"status\":200,\"latency_ms\":10,\"user_agent\":\"Mozilla/5.0\",\"country\":\"US\",\"device_model\":\"Google Pixel\"}" > /dev/null
  done
  echo "   $ip: ${#PAYLOADS[@]} attaques"
done

# 4. IPs avec score IA élevé (comportement anormal)
echo ""
echo "4. High AI score IPs (comportement anormal)..."
HIGH_AI_IPS=("130.185.74.243" "157.55.39.220" "188.211.189.185")
for ip in "${HIGH_AI_IPS[@]}"; do
  for i in {1..15}; do
    curl -s -X POST http://localhost:8000/api/v1/analyze \
      -H "Content-Type: application/json" \
      -d "{\"ip\":\"$ip\",\"method\":\"GET\",\"endpoint\":\"/login\",\"status\":200,\"latency_ms\":50,\"user_agent\":\"Mozilla/5.0\",\"country\":\"FR\",\"device_model\":\"iPhone 15\"}" > /dev/null
  done
  echo "   $ip: 15 requêtes suspectes"
done

echo ""
echo "✅ GÉNÉRATION TERMINÉE !"
echo ""
echo "📊 RÉCAPITULATIF:"
echo "   - Bruteforce: 60 attaques"
echo "   - Enumeration: 24 attaques"
echo "   - SQL Injection: 32 attaques"
echo "   - High AI score: 45 requêtes"
echo "   TOTAL: ~161 logs d'attaque"
echo ""
echo "🌐 Va dans Kibana maintenant: http://localhost:5601"
echo "   → Discover → Filtre: attack_type: bruteforce OR enumeration OR sql_injection"
