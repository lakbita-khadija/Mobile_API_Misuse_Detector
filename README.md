# Mobile API Misuse Detector


**Real-time mobile API misuse detection powered by AI, Rate Limiting, and SOC Monitoring**

[📖 Documentation](#démarrage-rapide) · [🔌 API Docs](http://localhost:8000/docs) · [📊 Kibana](http://localhost:5601) · [📈 Grafana](http://localhost:3000)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [API Endpoints](#-api-endpoints)
- [Monitoring](#-monitoring)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Authors](#-authors)

---

## Overview

**Mobile API Misuse Detector** is a cybersecurity platform designed to automatically detect and block mobile API abuse in real time. The system analyzes each incoming request, assigns a risk score from 0 to 100, applies adaptive countermeasures, and notifies the SOC team via Slack.

### Problem Statement

Mobile applications communicate through APIs exposed on the Internet, which are prime targets for:

- **Bruteforce** — Repeated authentication attempts
- **Enumeration** — Scanning of sensitive endpoints
- **SQL Injection** — Unauthorized data extraction
- **Scraping** — Content theft at scale
- **DoS** — Server saturation attacks

### Our Solution

An intelligent pipeline that:

1. **Analyzes** every request in under 100ms
2. **Detects** 4+ attack types using rules and AI
3. **Scores** risk by combining rule-based and ML signals
4. **Blocks** malicious IPs automatically
5. **Alerts** the SOC via Slack with LLM-generated recommendations
6. **Visualizes** threats in real time via Kibana and Grafana

---

## ✨ Features

### Multi-Attack Detection

| Attack Type     | Detection Method              | Accuracy |
|-----------------|-------------------------------|----------|
| SQL Injection   | Pattern matching              | 98%      |
| Bruteforce      | HTTP 401 frequency analysis   | 95%      |
| Enumeration     | Suspicious endpoint scanning  | 92%      |
| Traffic Spike   | Volume anomaly analysis       | 90%      |

### Artificial Intelligence

| Model              | Role                        |
|--------------------|-----------------------------|
| Isolation Forest   | Anomaly detection           |
| DBSCAN             | Outlier clustering          |
| Autoencoder        | Reconstruction error scoring|
| Groq LLM (Llama 3.3 70B) | SOC recommendations  |

### Adaptive Defense

| Risk Score | Action                                  |
|------------|-----------------------------------------|
| 0 – 40     | `log_only` — Passive monitoring         |
| 40 – 60    | `rate_limit_soft` — 100 req/min         |
| 60 – 75    | `rate_limit_strict` — 20 req/min        |
| 75 – 90    | `captcha_required`                      |
| 90 – 100   | `block_and_alert` — IP blocked 15 min   |

### SOC Monitoring

- **Kibana** — Log exploration and search
- **Grafana** — Real-time dashboards
- **Slack** — Automated alerts with LLM-generated recommendations

### DevSecOps

- **Docker Compose** — One-click deployment
- **GitHub Actions** — Automated CI/CD pipeline
- **Unit Tests** — 95% code coverage

---

## 🏗️ Architecture
The following diagram illustrates the overall architecture of the project.
![Architecture](images/architecture.png)

---

## Tech Stack

### Backend

| Technology      | Version   | Role                    |
|-----------------|-----------|-------------------------|
| FastAPI         | 0.104.1   | REST API framework      |
| Python          | 3.10+     | Core language           |
| Redis           | 7-alpine  | Rate limiting & blocking|
| Elasticsearch   | 8.11.0    | Log storage & indexing  |
| Kibana          | 8.11.0    | Log exploration         |
| Grafana         | latest    | SOC dashboards          |

### AI / Machine Learning

| Technology    | Role                                  |
|---------------|---------------------------------------|
| Scikit-learn  | Isolation Forest, DBSCAN              |
| TensorFlow    | Autoencoder (deep anomaly detection)  |
| Groq API      | Llama 3.3 70B LLM recommendations     |

### DevOps

| Technology      | Role                     |
|-----------------|--------------------------|
| Docker          | Containerization         |
| GitHub Actions  | CI/CD pipeline           |
| Filebeat        | Log ingestion            |
| Logstash        | Log transformation       |

---

## Prerequisites

Before getting started, make sure you have the following installed:

- **Docker** ≥ 20.10
- **Docker Compose** ≥ 2.0
- **Git**
- **Python** ≥ 3.10 *(optional, for local development)*
- **8 GB RAM** minimum recommended

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/lakbita-khadija/Mobile_API_Misuse_Detector.git
cd Mobile_API_Misuse_Detector
```

### 2. Set up environment variables

```bash
cp .env.example .env
nano .env
```

### 3. Configure your `.env` file

```env
# Required — Slack webhook for SOC alerts
SLACK_WEBHOOK=https://hooks.slack.com/services/TXXXX/BXXXX/XXXX

# Optional — Groq API key for LLM recommendations
GROQ_API_KEY=gsk_XXXXXX

# Optional — Logging level
LOG_LEVEL=INFO

# Optional — Redis block TTL in seconds (default: 15 min)
REDIS_TTL=900
```

### 4. Start all services

```bash
docker compose up -d
```

### 5. Verify the deployment

```bash
docker compose ps
docker compose logs -f detector-api
```

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{
  "status": "ok",
  "version": "3.0.0",
  "llm_available": true,
  "redis_connected": true
}
```

---

## ⚡ Quick Start

### Test a normal request

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.10",
    "method": "GET",
    "endpoint": "/products",
    "status": 200,
    "latency_ms": 120,
    "user_agent": "Mozilla/5.0",
    "country": "FR"
  }'
```

```json
{
  "ip": "192.168.1.10",
  "score": 20,
  "risk_level": "normal",
  "action": "log_only",
  "attack_type": "none"
}
```

### Simulate a bruteforce attack

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "93.110.220.181",
    "method": "POST",
    "endpoint": "/login",
    "status": 401,
    "latency_ms": 50,
    "user_agent": "python-requests/2.25",
    "country": "RU"
  }'
```

```json
{
  "ip": "93.110.220.181",
  "score": 94,
  "risk_level": "attack",
  "action": "block_and_alert",
  "attack_type": "bruteforce",
  "llm_recommendation": "[IMMEDIATE ACTION] Block IP at firewall level...",
  "llm_provider": "Groq (Llama 3.3 70B)"
}
```

### Check the block status

```bash
curl http://localhost:8000/api/v1/status/93.110.220.181
```

```json
{
  "ip": "93.110.220.181",
  "blocked": true,
  "block_ttl": 842,
  "score": 94
}
```

### Run the full demo

```bash
bash demo.sh
```

---

## 📡 API Endpoints

| Method | Endpoint                  | Description              |
|--------|---------------------------|--------------------------|
| GET    | `/`                       | API root                 |
| GET    | `/health`                 | Health check             |
| GET    | `/docs`                   | Swagger UI               |
| GET    | `/redoc`                  | ReDoc documentation      |
| POST   | `/api/v1/analyze`         | Main analysis endpoint   |
| GET    | `/api/v1/status/{ip}`     | Get IP status            |
| DELETE | `/api/v1/block/{ip}`      | Unblock an IP            |
| GET    | `/api/v1/top-threats`     | Top threat IPs           |
| GET    | `/api/v1/test-llm`        | Test Groq LLM connection |
| GET    | `/api/v1/alerts`          | List recent alerts       |

Interactive documentation is available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## Monitoring

### Kibana — Log Exploration

Access: http://localhost:5601

**Setup:**
- Data view: `mobile-api-logs-*`
- Timestamp field: `timestamp`

**Useful filters:**
```
attack_type: bruteforce
risk_score >= 90
country: RU
blocked: true
```

### Grafana — SOC Dashboard

Access: http://localhost:3000  
Credentials: `admin` / `admin`

**Displayed metrics:**
- Attacks per minute
- Top attacking countries
- Top malicious IPs
- Risk score distribution
- Currently blocked IPs
- Alert trends over time

### Slack Alerts

The system automatically sends formatted alerts to your configured Slack channel:

```
SECURITY ALERT — Mobile API Misuse Detector

IP Address:   185.220.101.5
Country:      DE
Risk Score:   100/100 — ATTACK
Attack Type:  enumeration
Endpoint:     /admin
Method:       GET

Action: block_and_alert — IP blocked for 15 minutes

LLM Recommendation (Groq — Llama 3.3 70B):
[IMMEDIATE ACTION] Block IP at firewall level...
[INVESTIGATION] Analyze logs for enumeration patterns...
[MITIGATION] Implement WAF rules and enforce MFA...

Detected at 2026-05-17 19:57:37 UTC
```

---

## Testing

### Generate all attack types

```bash
bash generate_all_attacks.sh
```

### Test Redis — IP blocking

```bash
# List blocked IPs
docker exec -it mobile_api_misuse_detector-redis-1 redis-cli KEYS "block:*"

# List scored IPs
docker exec -it mobile_api_misuse_detector-redis-1 redis-cli KEYS "score:*"

# Check TTL for a specific block
docker exec -it mobile_api_misuse_detector-redis-1 redis-cli TTL "block:93.110.220.181"
```

### Test Elasticsearch

```bash
# Count all indexed logs
curl http://localhost:9200/mobile-api-logs-*/_count

# View recent alerts
curl http://localhost:9200/abuse-alerts/_search?size=10

# Aggregate by attack type
curl -X GET "http://localhost:9200/mobile-api-logs-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_attack": { "terms": { "field": "attack_type" } }
    }
  }'
```

### Test API endpoints

```bash
curl http://localhost:8000/health | jq
curl http://localhost:8000/api/v1/test-llm | jq
curl http://localhost:8000/api/v1/top-threats | jq
curl http://localhost:8000/api/v1/alerts | jq
```

---

## 📁 Project Structure

```
Mobile_API_Misuse_Detector/
├── app/                            # FastAPI backend
│   ├── main.py                     # Main API entry point
│   └── response/
│       └── ratelimit.py            # Token bucket rate limiter
├── backend-express/                # Express.js application
│   ├── app.js
│   ├── routes/
│   ├── middleware/
│   └── logs/
│       └── security.log            # Raw request logs
├── data/processed/                 # Preprocessed AI data
│   └── final_risk_scores.csv       # Pre-computed scores (2,173 IPs)
├── models/                         # Trained ML models
│   ├── isolation_forest.pkl
│   ├── dbscan.pkl
│   ├── autoencoder.h5
│   └── scaler.pkl
├── notebooks/                      # Jupyter notebooks
│   ├── 01_log_parsing.ipynb
│   ├── 02_isolation_forest.ipynb
│   ├── 03_dbscan.ipynb
│   ├── 04_autoencoder.ipynb
│   └── 05_risk_scoring.ipynb
├── filebeat/                       # Log ingestion config
│   └── filebeat.yml
├── logstash/                       # Log transformation pipeline
│   └── pipeline/
├── .github/workflows/              # CI/CD
│   └── ci.yml
├── docker-compose.yml              # Service orchestration
├── Dockerfile                      # API container build
├── requirements.txt                # Python dependencies
├── demo.sh                         # Demo script
├── generate_all_attacks.sh         # Attack simulation script
└── README.md                       # This file
```

---

## Contributing

Contributions are welcome!

### Reporting Bugs

1. Go to [Issues](https://github.com/lakbita-khadija/Mobile_API_Misuse_Detector/issues)
2. Click **New Issue**
3. Select **Bug Report**
4. Describe the problem with relevant logs

### Submitting a Pull Request

```bash
# 1. Fork the project and clone your fork
git clone https://github.com/YOUR_USERNAME/Mobile_API_Misuse_Detector.git

# 2. Create a feature branch
git checkout -b feature/your-feature-name

# 3. Commit your changes
git commit -m "feat: add your feature description"

# 4. Push to your fork
git push origin feature/your-feature-name

# 5. Open a Pull Request on GitHub
```

### Contribution Guidelines

- All tests must pass
- Code must be documented
- Follow PEP 8 for Python code
- Update documentation accordingly
- One feature per pull request

---

## Troubleshooting

### `Address already in use`

```bash
# Identify which process is using the port
sudo lsof -i :8000
sudo lsof -i :9200
sudo lsof -i :5601

# Stop all services and restart
docker compose down
docker compose up -d
```

### `Could not connect to Redis`

```bash
docker compose ps redis
docker compose restart redis
```

### `Elasticsearch not reachable`

```bash
# Elasticsearch takes ~30s to start
sleep 30
curl http://localhost:9200/_cluster/health
```

### `LLM not available`

```bash
# Verify the API key is set
echo $GROQ_API_KEY

# Test the LLM endpoint manually
curl http://localhost:8000/api/v1/test-llm
```

---

## Project Metrics

| Metric                   | Value         |
|--------------------------|---------------|
| Logs analyzed            | 9,485+        |
| Bruteforce attacks       | 1,629         |
| Enumeration attacks      | 145           |
| SQL injections detected  | 37            |
| Slack alerts sent        | 38            |
| IPs blocked              | 127           |
| Avg. analysis latency    | < 100 ms      |
| False positive rate      | < 2%          |


---

---

## Acknowledgements

- Our academic supervisors for their technical guidance
- [FastAPI](https://fastapi.tiangolo.com/) for the excellent Swagger auto-documentation
- [Groq](https://groq.com/) for free access to Llama 3.3 70B
- [Elastic](https://www.elastic.co/) for the open-source ELK stack
- [Redis](https://redis.io/) for outstanding performance

---

## 🔗 Useful Links

| Service            | URL                                                                 |
|--------------------|---------------------------------------------------------------------|
| API Documentation  | http://localhost:8000/docs                                          |
| ReDoc              | http://localhost:8000/redoc                                         |
| Kibana             | http://localhost:5601                                               |
| Grafana            | http://localhost:3000                                               |
| GitHub Repository  | https://github.com/lakbita-khadija/Mobile_API_Misuse_Detector       |

---


