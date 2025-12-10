# Network Anomaly Detection System

## Complete Technical Documentation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Installation Guide](#3-installation-guide)
4. [Dataset Information](#4-dataset-information)
5. [Machine Learning Algorithms](#5-machine-learning-algorithms)
6. [API Documentation](#6-api-documentation)
7. [Frontend Dashboard](#7-frontend-dashboard)
8. [How It Works](#8-how-it-works)
9. [Configuration](#9-configuration)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Project Overview

### What is Network Anomaly Detection?

Network Anomaly Detection is a cybersecurity technique that identifies unusual patterns in network traffic that could indicate security threats such as:

- **DDoS Attacks** - Distributed Denial of Service
- **Port Scanning** - Reconnaissance attacks
- **Brute Force** - Password guessing attacks
- **Web Attacks** - SQL injection, XSS
- **Botnets** - Compromised machine networks
- **Infiltration** - Unauthorized network access

### Why This Project?

Traditional security systems rely on **signature-based detection** which can only detect known threats. This system uses **machine learning** to detect unknown (zero-day) attacks by learning what "normal" traffic looks like and flagging deviations.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-method Detection** | Statistical, Isolation Forest, and Combined |
| **Attack Classification** | Identifies specific attack types |
| **Real-time Dashboard** | Live monitoring with charts |
| **File Upload Analysis** | Analyze CSV traffic files |
| **Alert Management** | Track and acknowledge threats |
| **Export Functionality** | Download results as CSV |

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                 │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────────────┐│
│  │ Dashboard │ │ Detection │ │  Alerts   │ │ Analytics/Settings││
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────────┬─────────┘│
│        │             │             │                 │          │
│        └─────────────┴─────────────┴─────────────────┘          │
│                              │                                   │
│                         HTTP/REST                                │
└──────────────────────────────┼───────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────┐
│                         BACKEND API                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                      FastAPI Server                          │ │
│  │  /api/detect  /api/stats  /api/alerts  /api/simulate        │ │
│  └──────────────────────────┬──────────────────────────────────┘ │
│                              │                                    │
│  ┌───────────────────────────┴────────────────────────────────┐  │
│  │                    DETECTION ENGINE                         │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐│  │
│  │  │  Statistical │ │  Isolation   │ │  Attack Classifier   ││  │
│  │  │  (Z-score)   │ │   Forest     │ │  (Random Forest)     ││  │
│  │  └──────────────┘ └──────────────┘ └──────────────────────┘│  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────┐
│                          DATA LAYER                               │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │   CICIDS2017   │  │  Preprocessor  │  │   Saved Models     │  │
│  │    Dataset     │  │  (Scaler)      │  │   (.joblib)        │  │
│  └────────────────┘  └────────────────┘  └────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### File Structure

```
network-anomaly-detection/
├── src/
│   ├── __init__.py
│   ├── train.py                 # Model training script
│   ├── data/
│   │   ├── __init__.py
│   │   ├── loader.py            # Dataset loading
│   │   └── preprocessor.py      # Data cleaning & normalization
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── statistical.py       # Z-score & IQR detection
│   │   ├── isolation_forest.py  # ML anomaly detection
│   │   └── classifier.py        # Attack classification
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI application
│   │   ├── routes.py            # API endpoints
│   │   └── models.py            # Request/response schemas
│   └── utils/
│       ├── __init__.py
│       ├── config.py            # Configuration settings
│       └── logger.py            # Logging setup
├── frontend/
│   ├── pages/
│   │   ├── _app.js
│   │   ├── index.js             # Dashboard
│   │   ├── detection.js         # File upload & analysis
│   │   ├── alerts.js            # Alert management
│   │   ├── analytics.js         # Charts & metrics
│   │   └── settings.js          # Configuration
│   ├── components/
│   │   ├── Sidebar.js
│   │   ├── StatsCards.js
│   │   ├── AlertsPanel.js
│   │   ├── TrafficChart.js
│   │   └── AttackDistribution.js
│   └── styles/
│       └── globals.css
├── models/                       # Saved ML models
├── data/
│   └── raw/                      # CICIDS2017 CSV files
├── notebooks/
│   └── 01_data_exploration.ipynb
├── requirements.txt
└── README.md
```

---

## 3. Installation Guide

### Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher
- 4GB+ RAM (for model training)

### Step-by-Step Installation

#### 1. Clone/Navigate to Project
```bash
cd network-anomaly-detection
```

#### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv
venv\Scripts\activate  # Windows
# or
source venv/bin/activate  # Linux/Mac
```

#### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

#### 4. Download Dataset
1. Go to: https://www.unb.ca/cic/datasets/ids-2017.html
2. Download `MachineLearningCSV.zip`
3. Extract and place CSV files in `data/raw/`

#### 5. Train Models
```bash
python -m src.train
```

#### 6. Start Backend API
```bash
uvicorn src.api.main:app --reload
```
API runs at: http://localhost:8000

#### 7. Start Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Dashboard runs at: http://localhost:3000

---

## 4. Dataset Information

### CICIDS2017 Dataset

The **Canadian Institute for Cybersecurity Intrusion Detection System 2017** dataset is one of the most comprehensive network intrusion datasets available.

#### Dataset Statistics

| Metric | Value |
|--------|-------|
| Total Records | ~2.8 million |
| Features | 78 original, 15 selected |
| Attack Types | 14 categories |
| Collection Period | July 3-7, 2017 |
| Size | ~1GB compressed |

#### Attack Types Included

| Attack | Description |
|--------|-------------|
| **BENIGN** | Normal traffic |
| **DDoS** | Distributed Denial of Service |
| **DoS Hulk** | DoS using Hulk tool |
| **DoS GoldenEye** | DoS using GoldenEye |
| **DoS Slowloris** | Slow HTTP DoS |
| **PortScan** | Port scanning activity |
| **FTP-Patator** | FTP brute force |
| **SSH-Patator** | SSH brute force |
| **Web Attack - Brute Force** | Web login brute force |
| **Web Attack - XSS** | Cross-site scripting |
| **Web Attack - SQL Injection** | Database injection |
| **Infiltration** | Network infiltration |
| **Bot** | Botnet traffic |
| **Heartbleed** | SSL vulnerability exploit |

#### Selected Features (15)

These features were selected based on research and importance for detection:

| # | Feature | Description | Unit |
|---|---------|-------------|------|
| 1 | Flow Duration | Total flow duration | μs |
| 2 | Total Fwd Packets | Packets in forward direction | count |
| 3 | Total Backward Packets | Packets in backward direction | count |
| 4 | Flow Bytes/s | Byte rate | bytes/s |
| 5 | Flow Packets/s | Packet rate | packets/s |
| 6 | Fwd Packet Length Mean | Avg forward packet size | bytes |
| 7 | Bwd Packet Length Mean | Avg backward packet size | bytes |
| 8 | Flow IAT Mean | Mean inter-arrival time | μs |
| 9 | Fwd IAT Mean | Forward IAT mean | μs |
| 10 | Bwd IAT Mean | Backward IAT mean | μs |
| 11 | Fwd PSH Flags | PSH flag count (forward) | count |
| 12 | SYN Flag Count | SYN flags in flow | count |
| 13 | ACK Flag Count | ACK flags in flow | count |
| 14 | Packet Length Variance | Variance in packet sizes | bytes² |
| 15 | Average Packet Size | Mean packet size | bytes |

---

## 5. Machine Learning Algorithms

### 5.1 Statistical Detection

Statistical methods detect anomalies based on mathematical properties of the data distribution.

#### Z-Score Method

The Z-score measures how many standard deviations a data point is from the mean.

**Formula:**
```
Z = (X - μ) / σ

Where:
- X = data point
- μ = mean of the data
- σ = standard deviation
```

**Detection Rule:**
```python
is_anomaly = |z_score| > threshold  # threshold = 3.0 by default
```

**Intuition:** Normal data falls within 3 standard deviations. Points outside are anomalies.

#### IQR (Interquartile Range) Method

Uses quartiles to detect outliers.

**Formula:**
```
IQR = Q3 - Q1
Lower Bound = Q1 - 1.5 × IQR
Upper Bound = Q3 + 1.5 × IQR
```

**Detection Rule:**
```python
is_anomaly = (X < lower_bound) or (X > upper_bound)
```

### 5.2 Isolation Forest

Isolation Forest is an unsupervised machine learning algorithm specifically designed for anomaly detection.

#### How It Works

1. **Random Partitioning:** The algorithm randomly selects a feature and splits the data at a random point
2. **Isolation:** This process repeats, creating a tree structure
3. **Path Length:** Anomalies are isolated faster (shorter paths) because they are different from normal data

**Key Insight:** Anomalies are few and different, so they require fewer splits to be isolated.

```
Normal Point Path:     ●──┬──┬──┬──┬──●  (long path)
Anomaly Path:          ●──┬──●           (short path)
```

#### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| n_estimators | 100 | Number of trees |
| contamination | 0.1 | Expected anomaly ratio |
| random_state | 42 | For reproducibility |

#### Code Example
```python
from sklearn.ensemble import IsolationForest

model = IsolationForest(contamination=0.1, n_estimators=100)
model.fit(normal_traffic_data)
predictions = model.predict(new_data)
# -1 = anomaly, 1 = normal
```

### 5.3 Random Forest Classifier

Used for multi-class attack classification. After detecting an anomaly, this classifier identifies the specific attack type.

#### How It Works

1. **Ensemble of Trees:** Creates multiple decision trees
2. **Bootstrapping:** Each tree trains on a random subset of data
3. **Voting:** Final prediction is the majority vote of all trees

#### Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| n_estimators | 100 | Number of trees |
| max_depth | 20 | Maximum tree depth |
| n_jobs | -1 | Use all CPU cores |

#### Attack Categories

The classifier groups attacks into broader categories:

| Original Label | Mapped Category |
|----------------|-----------------|
| DDoS, DoS Hulk, DoS GoldenEye | DDoS Attack |
| PortScan | Port Scan |
| FTP-Patator, SSH-Patator | Brute Force |
| Web Attack - XSS, SQL Injection | Web Attack |
| Bot | Botnet |
| BENIGN | Normal |

---

## 6. API Documentation

### Base URL
```
http://localhost:8000
```

### Endpoints

#### Health Check
```
GET /health
```
**Response:**
```json
{
  "status": "healthy",
  "models_loaded": true,
  "timestamp": "2024-01-01T12:00:00"
}
```

---

#### Detect Anomalies
```
POST /api/detect
```
**Request Body:**
```json
{
  "flows": [
    {
      "flow_duration": 120000,
      "total_fwd_packets": 10,
      "total_bwd_packets": 8,
      "flow_bytes_per_sec": 1500.5,
      "flow_packets_per_sec": 15.0,
      "fwd_packet_length_mean": 150.5,
      "bwd_packet_length_mean": 200.3,
      "flow_iat_mean": 8000.0,
      "fwd_iat_mean": 10000.0,
      "bwd_iat_mean": 12000.0,
      "fwd_psh_flags": 2,
      "syn_flag_count": 1,
      "ack_flag_count": 5,
      "packet_length_variance": 500.0,
      "average_packet_size": 175.4
    }
  ],
  "method": "combined"
}
```

**Response:**
```json
{
  "total_flows": 1,
  "anomalies_detected": 0,
  "detection_rate": 0.0,
  "method_used": "combined",
  "results": [
    {
      "index": 0,
      "is_anomaly": false,
      "score": 1.23,
      "attack_type": null,
      "attack_confidence": null,
      "method": "combined"
    }
  ],
  "timestamp": "2024-01-01T12:00:00"
}
```

---

#### Get Statistics
```
GET /api/stats
```
**Response:**
```json
{
  "total_flows_analyzed": 1000,
  "total_anomalies_detected": 150,
  "detection_rate": 0.15,
  "attack_distribution": {
    "DDoS Attack": 80,
    "Port Scan": 50,
    "Brute Force": 20
  },
  "model_status": {
    "preprocessor": true,
    "statistical": true,
    "isolation_forest": true,
    "classifier": true
  },
  "uptime_seconds": 3600.5
}
```

---

#### Get Alerts
```
GET /api/alerts?limit=20&unacknowledged_only=false
```
**Response:**
```json
{
  "total_alerts": 50,
  "unacknowledged": 10,
  "alerts": [
    {
      "id": "uuid-here",
      "timestamp": "2024-01-01T12:00:00",
      "severity": "high",
      "attack_type": "DDoS Attack",
      "source_info": {"flow_index": 5},
      "score": 3.5,
      "is_acknowledged": false
    }
  ]
}
```

---

#### Acknowledge Alert
```
POST /api/alerts/{alert_id}/acknowledge
```

---

#### Simulate Traffic
```
POST /api/simulate?num_samples=10&anomaly_ratio=0.3
```

---

#### Get Model Info
```
GET /api/models/info
```
**Response:**
```json
{
  "models": {
    "preprocessor": {
      "status": "loaded",
      "type": "StandardScaler"
    },
    "statistical": {
      "status": "loaded",
      "type": "Statistical (Z-score, IQR)",
      "zscore_threshold": 3.0
    },
    "isolation_forest": {
      "status": "loaded",
      "type": "Isolation Forest",
      "contamination": 0.1,
      "n_estimators": 100
    },
    "classifier": {
      "status": "loaded",
      "type": "Random Forest Classifier",
      "classes": ["Normal", "DDoS Attack", "Port Scan"],
      "n_estimators": 100
    }
  },
  "features": ["Flow Duration", "..."],
  "feature_count": 15
}
```

---

## 7. Frontend Dashboard

### Pages Overview

#### 1. Dashboard (/)
- **Stats Cards:** Total flows, anomalies, detection rate, uptime
- **Traffic Chart:** Line chart showing normal vs anomaly traffic over time
- **Attack Distribution:** Pie chart of attack types
- **Recent Alerts:** Latest security alerts

#### 2. Detection (/detection)
- **File Upload:** Drag & drop CSV files
- **Method Selection:** Choose detection method
- **Results Table:** View detection results
- **Export:** Download results as CSV

#### 3. Alerts (/alerts)
- **Alert List:** All security alerts
- **Filtering:** By severity (critical, high, medium)
- **Acknowledge:** Mark alerts as handled
- **Statistics:** Alert counts by category

#### 4. Analytics (/analytics)
- **Traffic Timeline:** 24-hour traffic visualization
- **Attack Distribution:** Horizontal bar chart
- **Model Status:** Active/inactive models
- **Performance Metrics:** Model information table

#### 5. Settings (/settings)
- **Detection Settings:** Threshold configuration
- **Dashboard Settings:** Auto-refresh options
- **Model Information:** Loaded models status
- **About:** System information

---

## 8. How It Works

### Detection Flow

```
1. INPUT: Network flow data (15 features)
          ↓
2. PREPROCESSING:
   - Handle missing values
   - Replace infinities
   - Normalize with StandardScaler
          ↓
3. DETECTION (Parallel):
   ┌─────────────────────────────────────┐
   │ Statistical  │  Isolation Forest   │
   │  (Z-score)   │                      │
   │      ↓       │         ↓            │
   │  is_anomaly  │    is_anomaly        │
   └─────────────────────────────────────┘
          ↓
4. COMBINE RESULTS:
   - Anomaly if ANY method flags it
   - Take maximum score
          ↓
5. CLASSIFY (if anomaly):
   - Random Forest predicts attack type
   - Returns confidence score
          ↓
6. OUTPUT:
   - is_anomaly: boolean
   - score: float
   - attack_type: string
   - confidence: float
```

### Training Flow

```
1. LOAD DATA:
   - Read CICIDS2017 CSV files
   - Combine all files
          ↓
2. PREPROCESS:
   - Clean missing values
   - Select 15 features
   - Split: 80% train, 20% test
          ↓
3. TRAIN MODELS:
   ┌─────────────────────────────────────┐
   │ Statistical   │ Trained on normal  │
   │ Detector      │ traffic only       │
   ├───────────────┼────────────────────┤
   │ Isolation     │ Trained on normal  │
   │ Forest        │ traffic only       │
   ├───────────────┼────────────────────┤
   │ Attack        │ Trained on ALL     │
   │ Classifier    │ traffic with labels│
   └─────────────────────────────────────┘
          ↓
4. EVALUATE:
   - Test on held-out data
   - Report accuracy
          ↓
5. SAVE:
   - Models saved to models/ folder
   - Preprocessor saved separately
```

---

## 9. Configuration

### Configuration File: `src/utils/config.py`

```python
# Detection settings
ISOLATION_FOREST_CONTAMINATION = 0.1  # 10% expected anomalies
STATISTICAL_ZSCORE_THRESHOLD = 3.0     # Z-score cutoff

# Selected features (15)
SELECTED_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    # ... (see full list in config.py)
]

# Attack type mapping
ATTACK_TYPES = {
    'BENIGN': 'Normal',
    'DDoS': 'DDoS Attack',
    'DoS Hulk': 'DoS Attack',
    # ... (see full mapping in config.py)
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| API_HOST | 0.0.0.0 | API server host |
| API_PORT | 8000 | API server port |

---

## 10. Troubleshooting

### Common Issues

#### "No module named 'sklearn'"
```bash
python -m pip install scikit-learn
```

#### "Models not loaded"
```bash
# Train models first
python -m src.train
```

#### "No CSV files found"
- Download CICIDS2017 dataset
- Place CSV files in `data/raw/` folder

#### "API connection refused"
- Ensure backend is running: `uvicorn src.api.main:app --reload`
- Check port 8000 is not in use

#### "Frontend won't start"
```bash
cd frontend
npm install  # Install dependencies
npm run dev  # Start development server
```

#### Memory Error during training
- Reduce sample size in `src/train.py`:
```python
train_all_models(sample_size=50000)  # Use smaller sample
```

---

## Summary

This Network Anomaly Detection System combines:
- **Statistical methods** for simple, fast detection
- **Isolation Forest** for ML-based anomaly detection
- **Random Forest** for attack classification
- **Modern dashboard** for visualization and management

The system is designed to be:
- **Easy to use** - Simple API and intuitive dashboard
- **Accurate** - Multiple detection methods for better coverage
- **Extensible** - Add new models or features easily
- **Educational** - Well-documented for learning purposes

---

## 11. Feature Mapping: Dataset to Live Traffic

This section explains how each training feature (from CICIDS2017) maps to real-time traffic captured via Scapy.

### Feature Computation Table

| # | Feature Name | Unit | Dataset Source | Live Traffic Computation (Scapy) |
|---|-------------|------|----------------|----------------------------------|
| 1 | **Flow Duration** | μs | Direct | `(pkt[-1].time - pkt[0].time) × 1,000,000` |
| 2 | **Total Fwd Packets** | count | Direct | Count packets where `pkt[IP].src == first_src` |
| 3 | **Total Backward Packets** | count | Direct | Count packets where `pkt[IP].src != first_src` |
| 4 | **Flow Bytes/s** | bytes/s | Direct | `total_bytes / flow_duration` |
| 5 | **Flow Packets/s** | pkts/s | Direct | `total_packets / flow_duration` |
| 6 | **Fwd Packet Length Mean** | bytes | Direct | `mean(len(pkt) for fwd packets)` |
| 7 | **Bwd Packet Length Mean** | bytes | Direct | `mean(len(pkt) for bwd packets)` |
| 8 | **Flow IAT Mean** | μs | Direct | `mean(pkt[i].time - pkt[i-1].time) × 1,000,000` |
| 9 | **Fwd IAT Mean** | μs | Direct | Mean inter-arrival time for forward packets |
| 10 | **Bwd IAT Mean** | μs | Direct | Mean inter-arrival time for backward packets |
| 11 | **Fwd PSH Flags** | count | Direct | `count(pkt[TCP].flags & 'P')` for forward |
| 12 | **SYN Flag Count** | count | Direct | `count(pkt[TCP].flags & 'S')` |
| 13 | **ACK Flag Count** | count | Direct | `count(pkt[TCP].flags & 'A')` |
| 14 | **Packet Length Variance** | bytes² | Direct | `variance(len(pkt) for all packets)` |
| 15 | **Average Packet Size** | bytes | Direct | `mean(len(pkt) for all packets)` |

### Flow Identification (5-Tuple)

Each network flow is uniquely identified by:
```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

The system uses **bidirectional flow aggregation** - packets in both directions are grouped together by sorting IP addresses to create consistent flow keys.

---

## 12. Threat Model & Assumptions

### Network Architecture

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────────────────────────┐
│  Attacker   │      │  Host-Only /     │      │         Protected Host           │
│    VM       │ ───► │  Virtual Switch  │ ───► │  ┌─────────────────────────────┐│
│ (Kali Linux)│      │                  │      │  │    Network Anomaly IDS      ││
└─────────────┘      └──────────────────┘      │  │  ┌───────┐  ┌───────────┐  ││
                                                │  │  │Scapy  │→ │ML Models  │  ││
                                                │  │  │Sniffer│  │Detection  │  ││
                                                │  │  └───────┘  └───────────┘  ││
                                                │  │         ↓                   ││
                                                │  │  ┌───────────────────────┐ ││
                                                │  │  │ Windows Firewall Block│ ││
                                                │  │  └───────────────────────┘ ││
                                                │  └─────────────────────────────┘│
                                                └─────────────────────────────────┘
```

### Threat Assumptions

| Assumption | Description |
|------------|-------------|
| **Deployment** | Host-based IDS running on Windows with admin privileges |
| **Network** | Controlled lab environment or small network |
| **Attacker** | External attacker on same network segment |
| **Traffic** | Unencrypted traffic (TLS inspection not supported) |
| **Scale** | Low to medium traffic rates (< 10,000 packets/sec) |

### Supported Attack Types

| Attack Category | Specific Attacks | Detection Method |
|-----------------|------------------|------------------|
| **DoS/DDoS** | Hulk, GoldenEye, Slowloris, SYN Flood | ML + Rate Rules |
| **Port Scanning** | Nmap SYN, TCP Connect, UDP Scan | ML + Port Count Rules |
| **Brute Force** | SSH, FTP password attacks | ML + Connection Rate |
| **Web Attacks** | SQL Injection, XSS, Brute Force | ML Classification |
| **Botnet** | C&C Communication patterns | ML Classification |
| **Infiltration** | Backdoor, data exfiltration | ML Classification |

---

## 13. Design Tradeoffs

### Why These Technologies?

| Choice | Rationale | Alternative Considered |
|--------|-----------|----------------------|
| **Python + Scapy** | Easy to develop, extensive packet parsing, educational | C/C++ with libpcap (faster but harder) |
| **Random Forest** | Good accuracy, interpretable, handles imbalanced data | Deep Learning (higher accuracy but less explainable) |
| **15 Features** | Balance between accuracy (78 available) and real-time speed | All 78 features (slower), 5 features (less accurate) |
| **CICIDS2017 Dataset** | Modern, realistic attacks, well-documented | NSL-KDD (older), UNSW-NB15 (less common) |
| **Multi-method Detection** | Reduces false negatives by combining approaches | Single model (simpler but less robust) |
| **Windows Firewall** | Native integration, no extra setup | iptables (Linux only), custom firewall |

### Performance vs Accuracy

```
                    Accuracy
                        ↑
                        │      ★ Our System
                 95% ───┼──────●──────────────
                        │     /
                 90% ───┼────/
                        │   /
                 85% ───┼──/
                        │ /
                 80% ───┼/
                        └─────────────────────→
                             5    10   15   Features
                        
Legend: More features = higher accuracy but slower processing
```

### Multi-Method Detection Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    INPUT: Network Flow                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
    ┌─────────┐     ┌──────────┐     ┌──────────┐
    │Statistical│   │Isolation │     │  Rules   │
    │ Z-Score  │   │  Forest  │     │ Engine   │
    └────┬────┘    └────┬─────┘     └────┬─────┘
         │              │                │
         └──────────────┴────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ ANY method flags│ ──► ANOMALY
              │   as anomaly?   │
              └────────┬────────┘
                       │ Yes
                       ▼
              ┌─────────────────┐
              │ Random Forest   │
              │ Attack Classify │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Alert + Block   │
              └─────────────────┘
```

---

## 14. Limitations & Future Work

### Current Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **Scapy packet drops** | May miss attacks at > 10K pps | Use dedicated NIC, increase buffer |
| **Encrypted traffic** | Cannot inspect TLS/HTTPS content | Integrate with TLS proxy |
| **Single-host** | Not distributed or scalable | Future: distributed sensors |
| **Dataset age** | CICIDS2017 may lack recent attack patterns | Retrain with newer datasets |
| **False positives** | Legitimate high traffic may trigger | Tune thresholds, use whitelisting |
| **Windows only** | Firewall blocking uses Windows API | Add iptables support for Linux |

### Future Enhancements

1. **Deep Learning Models**
   - LSTM/GRU for sequential pattern detection
   - Autoencoders for unsupervised anomaly detection

2. **Distributed Architecture**
   - Multiple sensors feeding central analyzer
   - Horizontal scaling for enterprise networks

3. **Enhanced Datasets**
   - UNSW-NB15 (2015) - More attack types
   - CIC-IDS2018 - Updated attack variations
   - Custom dataset from live network capture

4. **Additional Features**
   - DNS query analysis
   - HTTP request inspection
   - User behavior analytics (UEBA)

5. **Integrations**
   - SIEM integration (Splunk, ELK)
   - Threat intelligence feeds
   - Automated incident response (SOAR)

---

## 15. Evaluation Metrics

### Model Performance (on CICIDS2017 test set)

| Metric | Value | Description |
|--------|-------|-------------|
| **Accuracy** | ~94% | Overall correct predictions |
| **Precision** | ~92% | True positives / All positives |
| **Recall** | ~96% | True positives / Actual positives |
| **F1-Score** | ~94% | Harmonic mean of precision/recall |

### Confusion Matrix Interpretation

```
                    Predicted
                 Normal    Attack
              ┌──────────┬──────────┐
    Actual    │   TN     │    FP    │   ← False Alarm Rate
    Normal    │ (Correct)│ (Error)  │
              ├──────────┼──────────┤
    Actual    │   FN     │    TP    │   ← Detection Rate
    Attack    │ (Missed) │ (Caught) │
              └──────────┴──────────┘
```

### API Endpoint for Metrics

```
GET /api/evaluate
```

Returns real-time evaluation metrics based on detected traffic.

---

*Documentation generated for Graduation Project - Network Anomaly Detection System*
