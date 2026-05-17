#!/bin/bash

API="http://localhost:8000/api/v1/analyze"
LOG="backend-express/logs/security.log"

echo "🎬 Lecture de security.log en temps réel"
echo "========================================="

count=0
normal=0
suspect=0
high=0
critical=0
attack=0

while IFS= read -r line; do
    ip=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('ip','').replace('::ffff:',''))" 2>/dev/null)
    endpoint=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('endpoint',''))" 2>/dev/null)
    status=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('status',''))" 2>/dev/null)
    user_agent=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('user_agent',''))" 2>/dev/null)
    method=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('method','GET'))" 2>/dev/null)
    latency=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('response_time_ms',100))" 2>/dev/null)
    country=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('country','unknown'))" 2>/dev/null)
    device_model=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('device_model','unknown'))" 2>/dev/null)
    device_type=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('device_type','unknown'))" 2>/dev/null)
    failed=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('failed_attempts',0))" 2>/dev/null)

    result=$(curl -s -X POST $API \
        -H "Content-Type: application/json" \
        -d "{\"ip\":\"$ip\",\"method\":\"$method\",\"endpoint\":\"$endpoint\",\"status\":$status,\"latency_ms\":$latency,\"user_agent\":\"$user_agent\",\"country\":\"$country\",\"device_model\":\"$device_model\",\"device_type\":\"$device_type\",\"failed_attempts\":$failed}" 2>/dev/null)

    score=$(echo $result | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('score',0))" 2>/dev/null)
    action=$(echo $result | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('action',''))" 2>/dev/null)
    level=$(echo $result | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('risk_level',''))" 2>/dev/null)
    attack_type=$(echo $result | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('attack_type',''))" 2>/dev/null)
    ai=$(echo $result | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('ai_score',0))" 2>/dev/null)

    count=$((count + 1))

    case $action in
        "log_only")
            echo "✅ [$count] IP=$ip | Score=$score | AI=$ai | $action | $country | $endpoint"
            normal=$((normal + 1))
            ;;
        "rate_limit_soft")
            echo "🔵 [$count] IP=$ip | Score=$score | AI=$ai | $action | $country | $endpoint"
            suspect=$((suspect + 1))
            ;;
        "rate_limit_strict")
            echo "🟡 [$count] IP=$ip | Score=$score | AI=$ai | $action | $country | $endpoint"
            high=$((high + 1))
            ;;
        "captcha_required")
            echo "🟠 [$count] IP=$ip | Score=$score | AI=$ai | $action | $attack_type | $country | $endpoint"
            critical=$((critical + 1))
            ;;
        "block_and_alert")
            echo "🚨 [$count] IP=$ip | Score=$score | AI=$ai | $action | $attack_type | $country | $endpoint"
            attack=$((attack + 1))
            ;;
        "blocked")
            echo "🔴 [$count] IP=$ip | Score=$score | AI=$ai | BLOCKED | $attack_type | $country | $endpoint"
            attack=$((attack + 1))
            ;;
    esac

    sleep 0.5

done < "$LOG"

echo ""
echo "========================================="
echo "📊 RÉSUMÉ FINAL"
echo "========================================="
echo "✅ Normal (log_only)        : $normal"
echo "🔵 Suspect (rate_limit_soft): $suspect"
echo "🟡 Haut risque (strict)     : $high"
echo "🟠 Critique (captcha)       : $critical"
echo "🚨 Attaque (block_and_alert): $attack"
echo "📈 Total analysés           : $count"
echo ""
echo "🔥 Top menaces :"
curl -s http://localhost:8000/api/v1/top-threats | python3 -m json.tool
