# 🛡 Real-Time SOC Malware Defense Dashboard

A real-time Security Operations Center (SOC) dashboard built with Flask that monitors system activity, detects suspicious behavior, and provides automated recommendations and response actions.

---

## 📌 Project Overview

This system simulates a SOC environment by:
- Collecting real-time system metrics (CPU, Memory, Disk)
- Tracking security-related events
- Classifying threats by severity (LOW, MEDIUM, HIGH)
- Generating AI-style recommendations
- Providing automated response actions (SOAR-like behavior)
- Visualizing everything in a real-time web dashboard

---

## ⚙️ Features

### 📊 Monitoring
- CPU usage tracking (real-time)
- Memory usage tracking
- Disk usage visualization

### 🔐 Security Event Tracking
- Live security event feed
- Event categorization (e.g., ransomware, brute force, malware)
- Severity classification system

### 🤖 Detection & Response
- Recommendation engine for mitigation steps
- Auto-response engine (SOAR simulation)
- Incident-based enrichment of events

### 📡 Real-Time Dashboard
- Live updating charts using Chart.js
- Auto-refresh every 1.5 seconds
- Interactive event panel
- Severity-based UI highlighting

---

## 🏗 Project Structure
Malware_Defense/
├── main.py
├── requirements.txt
├── README.md
├── config/
│   └── system_config.yaml
├── src/
│   ├── core/
│   │   └── config_loader.py
│   ├── monitoring/
│   ├── detection/
│   ├── defense/
│   ├── utils/
│   │   └── logger.py
│   └── dashboard/
├── data/
│   ├── logs/
│   └── quarantine/
└── tests/

app.py / main.py

## 🚀 How to Run the Project

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd <project-folder>

## 2. Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

## 3. Install dependencies
pip install -r requirements.txt

## 4. Run the application
python main.py

## 5. Open in browser
http://127.0.0.1:5000

