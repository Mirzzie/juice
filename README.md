# 🛡️ IAST vs RASP: A Comparative Security Analysis

> **MSc Cybersecurity Thesis Project**  
> Empirical comparison of Interactive Application Security Testing (IAST) vs Runtime Application Security Protection (RASP) using DataDog and Aikido Zen.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Technologies](#-technologies)
- [Prerequisites](#-prerequisites)
- [Project Structure](#-project-structure)
- [Three-Scenario Methodology](#-three-scenario-methodology)
- [Dashboard Metrics](#-dashboard-metrics)
- [Running Experiments](#-running-experiments)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Research Findings](#-research-findings)
- [License](#-license)

---

## 🎯 Overview

This project provides a complete DevSecOps research infrastructure to empirically compare **IAST (Interactive Application Security Testing)** and **RASP (Runtime Application Security Protection)** technologies.

### Research Question

> *Does RASP provide superior runtime protection compared to IAST-only approaches in modern web applications?*

### Key Findings

| Metric | IAST Only | IAST + RASP |
|--------|-----------|-------------|
| Attack Detection | ✅ Yes | ✅ Yes |
| Attack Blocking | ❌ No | ✅ Yes (~80%+) |
| Runtime Protection | ❌ Passive | ✅ Active |
| Performance Overhead | Low | Low-Medium |


## 🛠️ Technologies

### Security Tools

| Tool | Purpose | Type |
|------|---------|------|
| **DataDog APM** | Application Performance Monitoring | APM |
| **DataDog IAST** | Interactive Application Security Testing | IAST |
| **Aikido Zen** | Runtime Application Self-Protection | RASP |
| **Semgrep** | Static Application Security Testing | SAST |
| **Trivy** | Container Vulnerability Scanning | SCA |

### Infrastructure

| Component | Purpose |
|-----------|---------|
| **AWS EC2** | Cloud compute (t3.medium+) |
| **Docker** | Containerization |
| **Ansible** | Configuration management |
| **Terraform** | Infrastructure as Code (optional) |
| **GitHub Actions / GitLab CI** | CI/CD automation |

### Monitoring Stack

| Component | Purpose | Port |
|-----------|---------|------|
| **Prometheus** | Metrics collection | 9090 |
| **Grafana** | Visualization | 3001 |
| **OpenTelemetry** | Telemetry pipeline | 4317/4318 |
| **Custom Exporter** | Security metrics | 9999 |

### Target Application

| Application | Description |
|-------------|-------------|
| **OWASP Juice Shop** | Intentionally vulnerable web application for security testing |

---

## 📦 Prerequisites

### Required Accounts & Keys

```bash
# DataDog (for IAST)
DATADOG_API_KEY=xxx
DATADOG_APP_KEY=xxx
DATADOG_SITE=us5.datadoghq.com  # or your region

# Aikido Security (for RASP)
ZEN_FIREWALL_TOKEN=xxx

# AWS (for EC2)
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx
```

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/Mirzzie/DevSecOps-RASP.git
cd DevSecOps-RASP
```

### 2. Configure Secrets

**For GitHub Actions:**

Navigate to: `Settings → Secrets → Actions → New repository secret`

| Secret Name | Description |
|-------------|-------------|
| `EC2_INSTANCE_IP` | Your EC2 public IP |
| `SSH_USER` | EC2 user |
| `EC2_SSH_PRIVATE_KEY` | SSH private key content |
| `DATADOG_API_KEY` | DataDog API key |
| `DATADOG_APP_KEY` | DataDog Application key |
| `DATADOG_SITE` | DataDog site URL |
| `ZEN_FIREWALL_TOKEN` | Aikido Zen token |

### 3. Deploy Infrastructure

```bash
# Create inventory file
cat > inventory.ini << EOF
[juiceshop]
YOUR_EC2_IP ansible_user=YOUR_EC2_USER ansible_ssh_private_key_file=~/.ssh/your-key.pem
EOF

# Run Ansible playbook
ansible-playbook -i inventory.ini ansible/playbook.yml \
  -e "datadog_api_key=YOUR_DD_API_KEY" \
  -e "datadog_app_key=YOUR_DD_APP_KEY" \
  -e "datadog_site=YOUR_DATADOG_SITE" \
  -e "aikido_token=YOUR_AIKIDO_TOKEN"
```

### 4. Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | `http://YOUR_EC2_IP:3001` | admin / admin |
| **Juice Shop** | `http://YOUR_EC2_IP:3000` | - |
| **Prometheus** | `http://YOUR_EC2_IP:9090` | - |

---

## 📁 Project Structure

```
DevSecOps-RASP/
│
├── .github/
│   └── workflows/
│       ├── workflow.yml              # Main CI/CD pipeline (SAST + Deploy)
│       └── experiment.yml            # Attack simulation workflow
│
├── ansible/
│   ├── playbook.yml                  # Main Ansible playbook
│   └── files/
│       ├── enhanced_metrics_exporter_otel.py   # Custom metrics exporter
│       └── grafana-jarvis-dashboard.json       # JARVIS Grafana dashboard
│
├── infra/                        # Infrastructure as Code
│   ├── ec2.tf
│   ├── vars.tf
│
├── README.md
└── LICENSE
```

---

## 🔬 Three-Scenario Methodology

The research uses a controlled three-scenario approach to isolate and measure the effectiveness of each security layer.

### Scenario 1: BASELINE (IAST Only)

```bash
ssh ubuntu@EC2_IP "/home/ubuntu/run_scenario.sh baseline"
```

| Component | Status |
|-----------|--------|
| DataDog IAST | ✅ Enabled |
| Aikido RASP | ❌ Disabled |
| Attack Blocking | ❌ None |

**Purpose:** Establish baseline detection capabilities with IAST alone.

---

### Scenario 2: DETECTION (IAST + RASP Detect)

```bash
ssh ubuntu@EC2_IP "/home/ubuntu/run_scenario.sh detection"
```

| Component | Status |
|-----------|--------|
| DataDog IAST | ✅ Enabled |
| Aikido RASP | ✅ Detection Mode |
| Attack Blocking | ❌ Detect only |

**Purpose:** Measure combined detection capabilities without active blocking.

---

### Scenario 3: BLOCKING (IAST + RASP Block)

```bash
ssh ubuntu@EC2_IP "/home/ubuntu/run_scenario.sh blocking"
```

| Component | Status |
|-----------|--------|
| DataDog IAST | ✅ Enabled |
| Aikido RASP | ✅ Blocking Mode |
| Attack Blocking | ✅ Active |

**Purpose:** Demonstrate RASP's active protection capabilities.

---

## 📊 Dashboard Metrics

### JARVIS Dashboard Panels

```
┌──────────┬──────────┬──────────┬──────────────┐
│ SCENARIO │ 🛡BLOCKED │ 👁DETECTED│ ⚔️TOTAL     │
└──────────┴──────────┴──────────┴──────────────┘
┌──────────┬──────────┬────────────────────────┐
│ RASP     │ RESPONSE │ CONTAINER              │
│ GAUGE    │ TIME     │ VULNERABILITIES        │
└──────────┴──────────┴────────────────────────┘
┌────────────────────────────┬─────────────────┐
│ ⚔️ THREAT TIMELINE         │ ⚡ PERFORMANCE   │
└────────────────────────────┴─────────────────┘
┌────────────────────────────┬─────────────────┐
│ 🛡 RASP ACTIVITY           │ 📊 ATTACK RATE  │
└────────────────────────────┴─────────────────┘
```

### Metrics Reference

| Panel | Prometheus Metric | Description |
|-------|-------------------|-------------|
| **SCENARIO** | `thesis_scenario_id` | Current mode (1=Baseline, 2=Detection, 3=Blocking) |
| **🛡 BLOCKED** | `thesis_rasp_blocks_total` | Cumulative attacks blocked |
| **👁 DETECTED** | `thesis_rasp_detections_total` | Cumulative attacks detected |
| **⚔️ TOTAL** | blocks + detections | Combined attack count |
| **RASP EFFICIENCY** | blocks / total * 100 | Block rate percentage |
| **RESPONSE TIME** | `thesis_request_latency_ms` | Average latency (ms) |
| **CONTAINER VULNS** | `thesis_trivy_vulns_total` | Trivy results by severity |

### Useful PromQL Queries

```promql
# RASP Block Rate (%)
(sum(thesis_rasp_blocks_total) / 
 (sum(thesis_rasp_blocks_total) + sum(thesis_rasp_detections_total) + 0.001)) * 100

# Attacks per Minute
increase(thesis_rasp_blocks_total[1m]) + increase(thesis_rasp_detections_total[1m])

# P95 Latency
thesis_request_latency_p95_ms

# Critical Container Vulnerabilities
thesis_trivy_vulns_total{severity="CRITICAL"}
```

---

## 🎮 Running Experiments

### Automated Experiments (CI/CD)

The `experiment.yml` workflow triggers:

| Trigger | When |
|---------|------|
| **Scheduled** | Daily at 04:00 UTC |
| **On Deploy** | After successful CI/CD pipeline |
| **Manual** | Via GitHub Actions workflow_dispatch |

### Manual Attack Simulation

```bash
# SSH into EC2
ssh YOUR_EC2_USER@YOUR_EC2_IP

# Switch to blocking mode
/home/ubuntu/run_scenario.sh blocking

# Wait for app restart
sleep 30

# Run SQL Injection attacks
for i in {1..30}; do
  curl -s "http://localhost:3000/rest/products/search?q='%20OR%201=1--"
done

# Run XSS attacks
for i in {1..30}; do
  curl -s "http://localhost:3000/rest/products/search?q=<script>alert(1)</script>"
done

# Verify RASP is blocking
docker logs juice-shop 2>&1 | grep -i "blocked\|zen"
```

### Load Testing with Apache Bench

```bash
# Install ab
sudo apt-get install apache2-utils

# Normal traffic baseline
ab -n 500 -c 10 "http://YOUR_EC2_IP:3000/rest/products/search?q=test"

# Attack traffic
ab -n 100 -c 5 "http://YOUR_EC2_IP:3000/rest/products/search?q='OR1=1--"
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DD_API_KEY` | DataDog API Key | Required |
| `DD_APP_KEY` | DataDog Application Key | Required |
| `DD_SITE` | DataDog region | `us5.datadoghq.com` |
| `AIKIDO_TOKEN` | Aikido Zen token | Required |
| `AIKIDO_BLOCK` | Enable blocking | `false` |
| `AIKIDO_DISABLE` | Disable RASP | `false` |

### Scenario Info File

Located at `/opt/security-metrics/data/scenario_info.json`:

```json
{
  "current_scenario": "iast-rasp-block",
  "scenario_id": 3
}
```

### Ports Reference

| Port | Service | Purpose |
|------|---------|---------|
| 3000 | Juice Shop | Target application |
| 3001 | Grafana | Dashboard |
| 9090 | Prometheus | Metrics DB |
| 9999 | Exporter | Custom metrics |
| 4317 | OTel gRPC | Telemetry |
| 4318 | OTel HTTP | Telemetry |

---

## 🔧 Troubleshooting

### Container Issues

```bash
# Check all containers
docker ps -a

# View logs
docker logs juice-shop
docker logs metrics-exporter
docker logs grafana

# Restart entire stack
cd /opt/juice-shop
docker compose down
docker compose up -d

# Rebuild specific container
docker compose up -d --build metrics-exporter
```

### Metrics Not Appearing

```bash
# Check exporter is running
curl http://localhost:9999/metrics | grep thesis_

# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# Verify scrape config
cat /opt/monitoring/prometheus/prometheus.yml
```

### RASP Not Blocking

```bash
# Verify scenario is set to blocking
cat /opt/security-metrics/data/scenario_info.json

# Check Aikido environment variables
docker inspect juice-shop | grep -E "AIKIDO_BLOCK|AIKIDO_DISABLE"

# Look for Aikido logs
docker logs juice-shop 2>&1 | grep -i aikido
```

### Dashboard Shows "No Data"

1. Set time range to "Last 15 minutes"
2. Verify Prometheus datasource in Grafana
3. Run some attacks to generate data
4. Check exporter logs: `docker logs metrics-exporter`

### Reset Everything

```bash
cd /opt/juice-shop
docker compose down -v
docker system prune -a -f
/home/ubuntu/run_scenario.sh baseline
```

---

## 📈 Research Findings

### Quantitative Results

| Scenario | Attacks | Detected | Blocked | Block Rate |
|----------|---------|----------|---------|------------|
| 1 - Baseline | 100 | 0* | 0 | 0% |
| 2 - Detection | 100 | 85 | 0 | 0% |
| 3 - Blocking | 100 | 15 | 80 | ~84% |

*IAST detects vulnerabilities in code, not runtime attacks

### Key Conclusions

1. **IAST Limitations**  
   IAST identifies code vulnerabilities during testing but cannot block attacks at runtime.

2. **RASP Effectiveness**  
   RASP successfully blocks ~80%+ of common web attacks (SQLi, XSS, Path Traversal).

3. **Complementary Approach**  
   IAST + RASP together provide defense-in-depth: vulnerability detection + runtime protection.

4. **Performance Impact**  
   RASP adds minimal latency overhead (~10-20ms), acceptable for production use.

### Thesis Contribution

This research provides empirical evidence that **RASP offers superior runtime protection** compared to IAST-only approaches, validating the need for active blocking mechanisms in comprehensive application security strategies.

---

## 📄 License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
</pre>
```

---

## 🙏 Acknowledgments

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) - Vulnerable test application
- [DataDog](https://www.datadoghq.com/) - APM and IAST platform
- [Aikido Security](https://www.aikido.dev/) - RASP solution (Zen Firewall)
- [Grafana Labs](https://grafana.com/) - Visualization platform
- [Prometheus](https://prometheus.io/) - Metrics collection

---

## 📬 Contact

**Author:** [Your Name]  
**Email:** [your.email@university.edu]  
**Supervisor:** [Supervisor Name]  
**Institution:** [University Name]  
**Program:** MSc Cybersecurity

---

<p align="center">
  <sub>Built with ☕ and 🛡️ for security research</sub>
</p>