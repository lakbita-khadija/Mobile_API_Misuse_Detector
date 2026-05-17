#!/bin/bash

API="http://localhost:8000/api/v1/analyze"
LOG="backend-express/logs/security.log"

echo "========================================"
echo "  Mobile API Misuse Detector — Live Demo"
echo "========================================"

count=0
normal=0
suspect=0
high=0
attack=0
skipped=0

while IFS= read -r line; do

    ip_raw=$(echo $line | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['message'].get('ip',''))" 2>/dev/null)

    # Ignorer 127.0.0.1 et localhost
    if [[ "$ip_raw" == *"127.0.0.1"* ]] || [[ "$ip_raw" == *"::1"* ]]; then
        skipped=$((skipped + 1))
        continue
    fi

    ip=$(echo $ip_raw | sed 's/::ffff://g')
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
    blocked=$(echo $result | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('blocked',False))" 2>/dev/null)

    count=$((count + 1))

    case $action in
        "log_only")
            echo "[ OK ]  [$count] IP=$ip | Score=$score | $level | $country | $endpoint"
            normal=$((normal + 1))
            ;;
        "rate_limit_soft")
            echo "[WARN]  [$count] IP=$ip | Score=$score | $level | $attack_type | $country | $endpoint"
            suspect=$((suspect + 1))
            ;;
        "rate_limit_strict")
            echo "[HIGH]  [$count] IP=$ip | Score=$score | $level | $attack_type | $country | $endpoint"
            high=$((high + 1))
            ;;
        "block_and_alert")
            echo "[ALERT] [$count] IP=$ip | Score=$score | $level | $attack_type | $country | $endpoint | BLOCKED=$blocked"
            attack=$((attack + 1))
            ;;
        "blocked")
            echo "[BLOCK] [$count] IP=$ip | Score=$score | ALREADY BLOCKED | $country"
            attack=$((attack + 1))
            ;;
    esac

    sleep 0.5

done < "$LOG"

echo ""
echo "========================================"
echo "  SUMMARY"
echo "========================================"
echo "  Normal   (log_only)       : $normal"
echo "  Suspect  (rate_limit_soft): $suspect"
echo "  High     (rate_limit_strict): $high"
echo "  Attack   (block_and_alert): $attack"
echo "  Skipped  (localhost)      : $skipped"
echo "  Total analyzed            : $count"
echo ""
echo "  Top Threats :"
curl -s http://localhost:8000/api/v1/top-threats | python3 -m json.tool
