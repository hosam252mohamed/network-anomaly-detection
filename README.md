# Network Anomaly Detection System

A machine learning-based system for detecting network anomalies and classifying attack types.

## Features

- 📊 **Statistical Detection** - Z-score and IQR-based anomaly detection
- 🌲 **Isolation Forest** - ML-based anomaly detection
- 🎯 **Attack Classification** - Identify attack types (DDoS, PortScan, etc.)
- 📈 **Interactive Dashboard** - Real-time monitoring and visualization
- 🔔 **Alert System** - Notifications for detected anomalies

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Download Dataset

Download CICIDS2017 from: https://www.unb.ca/cic/datasets/ids-2017.html

Place CSV files in `data/raw/` folder.

### 3. Train Models

```bash
python -m src.train
```

### 4. Start API Server

```bash
uvicorn src.api.main:app --reload
```

### 5. Start Dashboard

```bash
cd frontend
npm install
npm run dev
```

## Project Structure

```
network-anomaly-detection/
├── data/               # Dataset files
├── src/                # Python source code
│   ├── data/           # Data loading & preprocessing
│   ├── detection/      # ML detection algorithms
│   └── api/            # FastAPI backend
├── models/             # Saved ML models
├── frontend/           # React dashboard
└── notebooks/          # Jupyter notebooks
```

## Tech Stack

- **Backend**: Python, FastAPI, Scikit-learn
- **Frontend**: React, Next.js, Chart.js
- **Dataset**: CICIDS2017

## License

MIT License

## VM Interface
\Device\NPF_{9EA43F3D-BF54-4A96-9C56-E5CFC9A0D4ED}

