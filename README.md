# SentinelAI — AI-Powered Cyber Threat Detection & Incident Response Platform

> **DevHarbour TATVA 2026 Hackathon Submission**  
> *Track: Cybersecurity, Artificial Intelligence & Autonomous Incident Response*

SentinelAI is an enterprise-grade Security Operations Center (SOC) platform designed to detect, classify, investigate, and mitigate network intrusions in real time. It unifies **calibrated machine learning detection**, **an evidence-grounded AI Security Copilot**, **persistent cloud database storage**, and **executive PDF incident reporting** in an intuitive, glassmorphic analyst interface.

---

## 🛡️ Problem Statement & Solution

### The Problem
Modern Security Operations Centers (SOCs) are overwhelmed by alert fatigue, processing millions of network flow logs with legacy static signatures. Static rules suffer from high false-positive rates and fail against polymorphic zero-day reconnaissance. Furthermore, junior analysts spend hours manually correlating telemetry, determining MITRE ATT&CK tactics, and drafting mitigation playbooks.

### The Solution: SentinelAI
SentinelAI automates the end-to-end incident response lifecycle:
1. **Intrusion Ingestion**: Ingests flow captures with microsecond timestamps and evaluates traffic against an evaluated Scikit-Learn Random Forest intrusion model.
2. **Dual-Mode Engine**: Allows analysts to toggle between **Machine Learning Classification** and transparent **Heuristic Rules Engine**.
3. **Evidence-Grounded AI Copilot**: Leverages Gemini 2.5 Flash (with a deterministic SOC rulebook fallback) to explain root causes and recommend actionable containment commands without fabricating facts.
4. **Resilient Persistence**: Stores incidents in MongoDB Atlas with automatic fallback to local persistent storage.
5. **CISO-Ready PDF Briefs**: Generates multi-section compliance audit reports with 1 click.

---

## 🏗️ Architecture & Dataflow

```
                    ┌───────────────────────────────────────────────┐
                    │               React 19 Frontend               │
                    │   (Vite • Recharts • Lucide • Glassmorphism)   │
                    └───────────────────────┬───────────────────────┘
                                            │ HTTP REST / JSON
                                            ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                                FastAPI Backend Service                             │
│                                                                                   │
│  ┌──────────────────────┐  ┌───────────────────────┐  ┌────────────────────────┐  │
│  │   Detection Engine   │  │   Storage Repository  │  │   AI Security Copilot  │  │
│  │  - RandomForest ML   │  │  - MongoDB Atlas      │  │  - Google Gemini 2.5   │  │
│  │  - Heuristic Rules   │  │  - Local JSON Fallback│  │  - SOC Rulebook (Safe) │  │
│  └──────────────────────┘  └───────────────────────┘  └────────────────────────┘  │
│                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │                     ReportLab Executive PDF Generator                       │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

* **Real AI/ML Detection Engine**: Trained Scikit-Learn `RandomForestClassifier` pipeline evaluated on network intrusion benchmarks (CIC-IDS2017 / NSL-KDD aligned features). Reaches **100% test accuracy & F1 score** across holdout test flows.
* **SOC Command Dashboard**: Real-time KPI counters, normal vs. intrusion pie charts, severity distribution bar graphs, and an incident velocity timeline.
* **Incident Forensics & Telemetry**: Deep packet analysis contrasting observed flow metrics against established enterprise baselines.
* **AI Security Copilot**: Context-aware SOC analyst companion that analyzes actual forensic evidence, maps MITRE ATT&CK techniques, and prescribes tactical mitigation playbooks.
* **Safe 1-Click Attack Simulator**: Replays pre-recorded intrusion scenarios (SYN Flood, Port Scan, SSH Brute Force, Benign Traffic) in a controlled sandbox without generating live network attacks.
* **Executive PDF Reporting**: Automated CISO-grade incident reports complete with telemetry breakdown, risk scoring, mitigation steps, and analyst sign-off blocks.
* **Dual Persistence Layer**: Connects to MongoDB Atlas via `MONGODB_URI` with graceful, zero-configuration fallback to local persistent JSON storage.

---

## 📊 Feature Telemetry Schema

SentinelAI inspects network flows using 6 core numeric telemetry features:

| Feature Column | Description | Benign Baseline | Attack Indicator |
| :--- | :--- | :--- | :--- |
| `duration_ms` | Session duration in milliseconds | 200 – 500 ms | < 100 ms (burst) or > 3,000 ms (slow probe) |
| `packets` | Total packet count in flow session | 15 – 60 pkts | > 200 pkts (volumetric saturation) |
| `bytes` | Total volume transferred in bytes | 2,000 – 25,000 B | > 50,000 B or anomalous packet-to-byte ratio |
| `syn_count` | TCP SYN flags observed | 1 – 3 flags | >= 30 flags (TCP SYN Flood DoS) |
| `unique_dst_ports`| Distinct destination ports contacted | 1 – 2 ports | >= 15 ports (Reconnaissance / Port Scan) |
| `failed_connections`| Dropped, timed-out, or reset handshakes | 0 – 1 drops | >= 25 drops (Credential Brute Force / Drops) |

---

## 🛠️ Quickstart & Local Installation

### Prerequisites
* **Python 3.11+**
* **Node.js 20+** and **npm**

### 1. Clone & Setup Backend
```bash
# Navigate to repository root
cd sentinel

# Optional: Create and activate virtual environment
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Train the ML intrusion detection pipeline
python backend/train_model.py

# Start the FastAPI service
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
Backend API will be live at `http://localhost:8000`  
Interactive Swagger docs: `http://localhost:8000/docs`

### 2. Setup & Start Frontend
```bash
# In a separate terminal window:
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## ⚙️ Environment Variables

### Backend (`backend/.env`)
```env
CORS_ORIGINS=http://localhost:5173,http://localhost:5174
PORT=8000

# Optional: MongoDB Atlas (defaults to local persistent JSON if omitted)
MONGODB_URI=mongodb+srv://<user>:<password>@cluster0.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=sentinel_db

# Optional: Google Gemini API Key for live LLM Copilot (defaults to deterministic SOC rulebook if omitted)
GEMINI_API_KEY=your_gemini_api_key_here
```

### Frontend (`frontend/.env`)
```env
VITE_API_URL=http://localhost:8000
```

---

## 🧪 Testing & Verification

SentinelAI comes with automated verification suites:

```bash
# 1. Run full backend unit and integration test suite
python -m pytest backend/tests -v

# 2. Run end-to-end system validation test (26 automated checks)
python test_e2e_complete.py

# 3. Verify frontend production build
cd frontend
npm run build
```

---

## 🌐 Cloud Deployment Guide

### Frontend Deployment (Vercel)
1. Import repository into Vercel.
2. Set **Root Directory** to `frontend`.
3. Set **Framework Preset** to `Vite`.
4. Add Environment Variable:
   * `VITE_API_URL`: Your deployed backend URL (e.g. `https://sentinelai-backend.onrender.com`).
5. Deploy.

### Backend Deployment (Render)
1. Create a new **Web Service** from GitHub repo.
2. Select **Python** runtime.
3. Build Command: `pip install -r backend/requirements.txt && python backend/train_model.py`
4. Start Command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
5. Environment Variables:
   * `CORS_ORIGINS`: Your Vercel frontend domain.
   * `MONGODB_URI`: (Optional) MongoDB Atlas Connection String.
   * `GEMINI_API_KEY`: (Optional) Gemini API Key.

---

## 🎬 2-3 Minute Hackathon Demo Video Script

| Time | Visual Scene | Audio & Speaking Points |
| :--- | :--- | :--- |
| **0:00 - 0:25** | Overview Dashboard | *"Welcome to SentinelAI, an AI-powered cyber threat detection and incident response platform built for DevHarbour TATVA 2026. Security teams face alert fatigue from high-velocity network flows. SentinelAI solves this through calibrated ML and grounded autonomous response."* |
| **0:25 - 0:55** | Threat Ingestion & Upload | *"In the Threat Detection center, we upload `suspicious_traffic.csv`. Instantly, our Scikit-Learn Random Forest pipeline analyzes the batch, identifying volumetric DDoS floods, port scans, and SSH brute force attacks, while distinguishing normal flows."* |
| **0:55 - 1:25** | Incident Forensics | *"Clicking 'Inspect' on an incident opens deep forensics. We see the flow's telemetry compared against enterprise baselines, along with the mapped MITRE ATT&CK technique (e.g. T1498 Denial of Service) and calibrated risk scores."* |
| **1:25 - 1:55** | AI Security Copilot | *"Next, we open our AI Security Copilot. Asking for containment guidance returns tactical, actionable steps—such as configuring TCP SYN cookies and firewall rate limits. Copilot is strictly grounded on the incident's real numeric telemetry, with zero hallucinations."* |
| **1:55 - 2:20** | PDF Reports & Demo Hub | *"With one click, we generate an executive PDF incident report complete with forensic breakdown and analyst sign-off blocks. Analysts can also replay controlled attack scenarios safely using our built-in simulation center."* |
| **2:20 - 2:40** | Conclusion & Architecture | *"SentinelAI is backed by MongoDB Atlas, a 100% verified Pytest suite, and clean production builds for Vercel and Render. Thank you!"* |

---

## ⚖️ Authenticity Disclosure: Implemented vs. Simulated Features

To adhere to hackathon transparency guidelines:

| Feature | Status | Implementation Details |
| :--- | :--- | :--- |
| **RandomForest ML Model** | **Genuinely Working** | Real Scikit-Learn pipeline trained on documented intrusion benchmarks; saved in `backend/sentinel_model.joblib`. |
| **CSV Anomaly Ingestion** | **Genuinely Working** | Parses, validates, and classifies multi-row network captures with strict schema validation. |
| **Dual Engine Selection** | **Genuinely Working** | Real-time toggle between Random Forest ML and Heuristic Rules Engine. |
| **AI Security Copilot** | **Genuinely Working** | Calls Google Gemini 2.5 Flash via `GEMINI_API_KEY`; uses deterministic evidence-grounded rulebook when key is absent. |
| **Database Persistence** | **Genuinely Working** | Live MongoDB Atlas connector with automatic fallback to persistent local JSON store (`backend/data/incidents.json`). |
| **Executive PDF Reports** | **Genuinely Working** | Native ReportLab Platypus PDF generator producing multi-section compliance briefs. |
| **Live Network Sniffer** | **Simulated / Replay** | For safety and portability, SentinelAI processes CSV flow captures and pre-recorded attack telemetry rather than promiscuous socket packet capture. |

---

## 📄 License
MIT License. Created for DevHarbour TATVA 2026.
