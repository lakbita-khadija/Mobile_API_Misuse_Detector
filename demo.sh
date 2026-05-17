#!/bin/bash
# ============================================================
#  run_abuse_detector.sh
#  Mobile API Misuse Detector — Security Log Replayer
# ============================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────
BASE_URL="${API_URL:-http://localhost:8000}"
API="${BASE_URL}/api/v1/analyze"
LOG="${LOG_FILE:-backend-express/logs/security.log}"
DELAY="${REPLAY_DELAY:-0.3}"
TOP_N="${TOP_THREATS:-10}"
MIN_SCORE_DISPLAY="${MIN_SCORE:-0}"

# ── Couleurs ANSI ────────────────────────────────────────────
RESET="\033[0m"
BOLD="\033[1m"
RED="\033[38;5;196m"
ORANGE="\033[38;5;208m"
YELLOW="\033[38;5;220m"
BLUE="\033[38;5;75m"
GREEN="\033[38;5;82m"
CYAN="\033[38;5;51m"
GRAY="\033[38;5;245m"
BG_RED="\033[41m"

# ── Helpers ──────────────────────────────────────────────────
repeat_char() { printf "%${2}s" | tr ' ' "$1"; }

bar() {
    local score=$1 width=20
    local filled=$(( score * width / 100 ))
    local empty=$(( width - filled ))
    local color
    if   [ "$score" -ge 90 ]; then color="$RED"
    elif [ "$score" -ge 75 ]; then color="$ORANGE"
    elif [ "$score" -ge 60 ]; then color="$YELLOW"
    elif [ "$score" -ge 40 ]; then color="$BLUE"
    else                           color="$GREEN"
    fi
    printf "${color}%s${GRAY}%s${RESET}" \
        "$(repeat_char '█' $filled)" \
        "$(repeat_char '░' $empty)"
}

ts() { date '+%H:%M:%S'; }

parse_log_field() {
    local json="$1" field="$2" default="${3:-}"
    python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    msg = d.get('message', d)
    if isinstance(msg, str):
        try:
            msg = json.loads(msg)
        except:
            pass
    if not isinstance(msg, dict):
        msg = d
    v = str(msg.get('$field', '$default')).replace('::ffff:', '')
    print(v if v not in ('', 'None') else '$default')
except Exception as e:
    print('$default')
" <<< "$json" 2>/dev/null
}

parse_result_field() {
    local json="$1" field="$2" default="${3:-}"
    python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    v = d.get('$field', '$default')
    print(v if v not in ('', None) else '$default')
except:
    print('$default')
" <<< "$json" 2>/dev/null
}

# ── Vérifications ─────────────────────────────────────────────
check_deps() {
    for cmd in curl python3; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}[ERROR]${RESET} '$cmd' est requis mais non installé." >&2
            exit 1
        fi
    done
}

check_api() {
    local health
    health=$(curl -sf "${BASE_URL}/health" 2>/dev/null) || true
    if ! echo "$health" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('status')=='ok' else 1)" 2>/dev/null; then
        echo -e "${RED}[ERROR]${RESET} API inaccessible : ${BASE_URL}" >&2
        echo -e "${GRAY}        Lancez : docker compose up -d${RESET}" >&2
        exit 1
    fi
}

check_log() {
    if [ ! -f "$LOG" ]; then
        echo -e "${RED}[ERROR]${RESET} Fichier log introuvable : $LOG" >&2
        echo -e "${GRAY}        Définissez LOG_FILE=<chemin> pour changer le path.${RESET}" >&2
        exit 1
    fi
    TOTAL_LINES=$(grep -c '' "$LOG" || echo 1)
}

# ── Bannière ──────────────────────────────────────────────────
print_banner() {
    echo -e ""
    echo -e "${BOLD}${CYAN}┌─────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}${CYAN}│   Mobile API Misuse Detector — Security Log Replayer    │${RESET}"
    echo -e "${BOLD}${CYAN}└─────────────────────────────────────────────────────────┘${RESET}"
    echo -e "${GRAY}  Log     : $LOG  (${TOTAL_LINES} lignes)${RESET}"
    echo -e "${GRAY}  API     : $API${RESET}"
    echo -e "${GRAY}  Délai   : ${DELAY}s  |  Score min affiché : ${MIN_SCORE_DISPLAY}${RESET}"
    echo -e ""
    printf "${GRAY}  %-4s  %-15s  %-22s  %-3s  %-18s  %-13s  %-4s  %s${RESET}\n" \
           "#" "IP" "Score" "AI" "Action" "Attack" "CC" "Endpoint"
    echo -e "${GRAY}  $(repeat_char '─' 100)${RESET}"
}

# ── Formatage action ──────────────────────────────────────────
action_fmt() {
    case "$1" in
        log_only)          echo -e "${GREEN}✔  log_only       ${RESET}" ;;
        rate_limit_soft)   echo -e "${BLUE}↓  rate_soft      ${RESET}" ;;
        rate_limit_strict) echo -e "${YELLOW}⚠  rate_strict    ${RESET}" ;;
        captcha_required)  echo -e "${ORANGE}⊘  captcha        ${RESET}" ;;
        block_and_alert)   echo -e "${RED}✖  block_alert    ${RESET}" ;;
        blocked)           echo -e "${BG_RED}   BLOCKED        ${RESET}" ;;
        *)                 echo -e "${GRAY}?  $1             ${RESET}" ;;
    esac
}

# ── Compteurs ─────────────────────────────────────────────────
count=0; skipped=0; normal=0; suspect=0
high=0; critical=0; attack_count=0; err_count=0
START_TS=$(date +%s)

# ── Boucle principale ─────────────────────────────────────────
main() {
    check_deps
    check_api
    check_log
    print_banner

    while IFS= read -r line; do
        [ -z "$line" ] && continue

        ip=$(parse_log_field "$line" "ip" "0.0.0.0")
        endpoint=$(parse_log_field "$line" "endpoint" "/")
        status=$(parse_log_field "$line" "status" "200")
        user_agent=$(parse_log_field "$line" "user_agent" "unknown")
        method=$(parse_log_field "$line" "method" "GET")
        latency=$(parse_log_field "$line" "response_time_ms" "100")
        country=$(parse_log_field "$line" "country" "XX")
        device_model=$(parse_log_field "$line" "device_model" "unknown")
        device_type=$(parse_log_field "$line" "device_type" "unknown")
        failed=$(parse_log_field "$line" "failed_attempts" "0")

        # Payload JSON sérialisé proprement (pas d'injection de guillemets)
        payload=$(python3 -c "
import json
print(json.dumps({
    'ip':             '$ip',
    'method':         '$method',
    'endpoint':       '$endpoint',
    'status':         int('${status:-200}'),
    'latency_ms':     int('${latency:-100}'),
    'user_agent':     '$user_agent',
    'country':        '$country',
    'device_model':   '$device_model',
    'device_type':    '$device_type',
    'failed_attempts':int('${failed:-0}')
}))
" 2>/dev/null) || { err_count=$((err_count+1)); continue; }

        result=$(curl -sf -X POST "$API" \
            -H "Content-Type: application/json" \
            --max-time 5 \
            -d "$payload" 2>/dev/null) || {
            err_count=$((err_count+1))
            echo -e "  ${GRAY}[$(ts)] Erreur API pour $ip${RESET}"
            continue
        }

        score=$(parse_result_field "$result" "score" "0")
        action=$(parse_result_field "$result" "action" "unknown")
        attack_type=$(parse_result_field "$result" "attack_type" "none")
        ai_raw=$(parse_result_field "$result" "ai_score" "0")
        ai=$(python3 -c "print(round(float('${ai_raw:-0}') * 100))" 2>/dev/null || echo "0")

        # Filtre score minimum
        if [ "${score:-0}" -lt "$MIN_SCORE_DISPLAY" ]; then
            skipped=$((skipped+1)); continue
        fi

        count=$((count+1))

        case "$action" in
            log_only)                normal=$((normal+1)) ;;
            rate_limit_soft)         suspect=$((suspect+1)) ;;
            rate_limit_strict)       high=$((high+1)) ;;
            captcha_required)        critical=$((critical+1)) ;;
            block_and_alert|blocked) attack_count=$((attack_count+1)) ;;
        esac

        printf "  ${GRAY}%-4s${RESET}  ${CYAN}%-15s${RESET}  %s ${BOLD}%3s${RESET}  ${GRAY}%3s%%${RESET}  %s  ${GRAY}%-13s  %-4s${RESET}  %-30s\n" \
            "$count" "$ip" "$(bar ${score:-0})" "$score" "$ai" \
            "$(action_fmt $action)" "$attack_type" "$country" "$endpoint"

        if [ "$action" = "block_and_alert" ] || [ "$action" = "blocked" ]; then
            echo -e "  ${BG_RED}${BOLD}  [$(ts)] BLOCKED: $ip → $endpoint (score=$score, $attack_type)  ${RESET}"
        fi

        sleep "$DELAY"

    done < "$LOG"

    print_summary
}

# ── Résumé final ──────────────────────────────────────────────
print_summary() {
    local elapsed=$(( $(date +%s) - START_TS ))

    echo -e ""
    echo -e "${BOLD}${CYAN}┌─────────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BOLD}${CYAN}│                     RÉSUMÉ FINAL                        │${RESET}"
    echo -e "${BOLD}${CYAN}└─────────────────────────────────────────────────────────┘${RESET}"
    echo -e ""
    printf "  ${GREEN}✔  Normal        (log_only)    : ${BOLD}%d${RESET}\n"  "$normal"
    printf "  ${BLUE}↓  Suspect       (rate_soft)   : ${BOLD}%d${RESET}\n"  "$suspect"
    printf "  ${YELLOW}⚠  Haut risque   (rate_strict) : ${BOLD}%d${RESET}\n" "$high"
    printf "  ${ORANGE}⊘  Critique      (captcha)     : ${BOLD}%d${RESET}\n" "$critical"
    printf "  ${RED}✖  Attaques      (block/alert) : ${BOLD}%d${RESET}\n"   "$attack_count"
    printf "  ${GRAY}!  Erreurs API                 : ${BOLD}%d${RESET}\n"  "$err_count"
    printf "  ${GRAY}–  Filtrés (score < %d)        : ${BOLD}%d${RESET}\n" "$MIN_SCORE_DISPLAY" "$skipped"
    echo -e ""
    printf "  ${BOLD}Total analysés : %d  |  Durée : %ds${RESET}\n" "$count" "$elapsed"
    echo -e ""
    echo -e "${BOLD}${CYAN}  Top ${TOP_N} menaces actives :${RESET}"
    echo -e "${GRAY}  $(repeat_char '─' 50)${RESET}"
    curl -sf "${BASE_URL}/api/v1/top-threats?limit=${TOP_N}" 2>/dev/null \
        | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for i, t in enumerate(data, 1):
        filled = t['score'] // 5
        b = '█' * filled + '░' * (20 - filled)
        print(f\"  {i:>2}. {t['ip']:<18} {b} {t['score']:>3}/100\")
except:
    print('  (aucune donnée)')
" 2>/dev/null
    echo -e ""
}

# ── Ctrl+C propre ─────────────────────────────────────────────
trap 'echo -e "\n${YELLOW}[STOP]${RESET} Interrompu par l'\''utilisateur."; print_summary; exit 0' INT TERM

main
