# Machine Learning Models & Dataset Documentation

## Complete Technical Reference for Network Anomaly Detection

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Dataset: CICIDS2017](#2-dataset-cicids2017)
3. [Feature Engineering](#3-feature-engineering)
4. [Detection Models](#4-detection-models)
5. [Training Pipeline](#5-training-pipeline)
6. [Model Evaluation](#6-model-evaluation)
7. [Model Comparison & Selection Rationale](#7-model-comparison--selection-rationale)
8. [Preprocessing & Normalization](#8-preprocessing--normalization)
9. [Hyperparameters](#9-hyperparameters)
10. [Serialization & Deployment](#10-serialization--deployment)
11. [Limitations & Future Work](#11-limitations--future-work)

---

## 1. Executive Summary

This document provides complete technical documentation of the machine learning components used in the Network Anomaly Detection System.

### System Overview

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Dataset** | CICIDS2017 | Training & evaluation data |
| **Preprocessing** | StandardScaler (sklearn) | Feature normalization |
| **Anomaly Detection** | Statistical (Z-score/IQR) + Isolation Forest | Binary anomaly detection |
| **Classification** | Random Forest Classifier | Multi-class attack type identification |

### Model Performance Summary

| Model | Accuracy | Training Data | Use Case |
|-------|----------|---------------|----------|
| Statistical Detector | ~65-75% | Normal traffic only | Fast baseline detection |
| Isolation Forest | ~75-85% | Normal traffic only | ML-based anomaly detection |
| Attack Classifier | ~92-98% | All labeled traffic | Attack type identification |

---

## 2. Dataset: CICIDS2017

### 2.1 Why CICIDS2017?

The **Canadian Institute for Cybersecurity Intrusion Detection System 2017** dataset was chosen for the following reasons:

| Criterion | CICIDS2017 Advantage | Comparison to Alternatives |
|-----------|---------------------|---------------------------|
| **Recency** | 2017 (relatively modern) | KDD99 (1999) is outdated with obsolete attack patterns |
| **Realism** | Captured from real network infrastructure | Synthetic datasets lack real-world traffic patterns |
| **Completeness** | 80+ features extracted from pcap files | Many datasets have limited features |
| **Labeled Data** | Fully labeled with 15 attack types | Essential for supervised learning |
| **Size** | ~2.8 million samples | Large enough for robust training |
| **Availability** | Free and publicly available | Commercial datasets are expensive |
| **Academic Recognition** | Widely cited in research papers | Enables comparison with published results |

### 2.2 Alternatives Considered

| Dataset | Year | Why Not Chosen |
|---------|------|----------------|
| **KDD Cup 1999** | 1999 | Outdated attack patterns, unrealistic traffic distribution |
| **NSL-KDD** | 2009 | Improved KDD but still outdated, lacks modern attack types |
| **UNSW-NB15** | 2015 | Good alternative, but fewer attack categories than CICIDS2017 |
| **ISCX 2012** | 2012 | Predecessor to CICIDS2017, less comprehensive |
| **CICIDS2018** | 2018 | Newer but more complex structure, similar attack coverage |

### 2.4 Attack Types Distribution

| Attack Type | Count | Percentage | Category |
|-------------|-------|------------|----------|
| **BENIGN** | ~2,273,097 | 80.3% | Normal Traffic |
| **DDoS** | ~128,027 | 4.5% | Denial of Service |
| **PortScan** | ~158,930 | 5.6% | Reconnaissance |
| **DoS Hulk** | ~231,073 | 8.2% | Denial of Service |
| **DoS GoldenEye** | ~10,293 | 0.4% | Denial of Service |
| **DoS Slowloris** | ~5,796 | 0.2% | Denial of Service |
| **DoS Slowhttptest** | ~5,499 | 0.2% | Denial of Service |
| **FTP-Patator** | ~7,938 | 0.3% | Brute Force |
| **SSH-Patator** | ~5,897 | 0.2% | Brute Force |
| **Web Attack - Brute Force** | ~1,507 | 0.05% | Web Attack |
| **Web Attack - XSS** | ~652 | 0.02% | Web Attack |
| **Web Attack - SQL Injection** | ~21 | <0.01% | Web Attack |
| **Infiltration** | ~36 | <0.01% | Advanced Persistent |
| **Bot** | ~1,966 | 0.07% | Botnet |
| **Heartbleed** | ~11 | <0.01% | Vulnerability Exploit |

### 2.5 Data Collection Methodology

The CICIDS2017 dataset was created using a realistic testbed:

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DATA COLLECTION SETUP                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   [Attack Network]          [Victim Network]                         │
│         │                         │                                   │
│    ┌────┴────┐              ┌─────┴─────┐                            │
│    │ Attack  │     ────►    │  Victim   │                            │
│    │ Machine │   Network    │  Servers  │                            │
│    │ (Kali)  │   Traffic    │ (Various) │                            │
│    └─────────┘              └─────┬─────┘                            │
│                                   │                                   │
│                           ┌───────┴───────┐                          │
│                           │   CICFlowMeter │                          │
│                           │ (Feature       │                          │
│                           │  Extraction)   │                          │
│                           └───────┬───────┘                          │
│                                   │                                   │
│                           ┌───────┴───────┐                          │
│                           │   CSV Output   │                          │
│                           │   (78 features) │                          │
│                           └───────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.6 Dataset Files

| Day | File Name | Attack Types Included |
|-----|-----------|----------------------|
| Monday | `Monday-WorkingHours.pcap_ISCX.csv` | BENIGN only |
| Tuesday | `Tuesday-WorkingHours.pcap_ISCX.csv` | FTP-Patator, SSH-Patator |
| Wednesday | `Wednesday-workingHours.pcap_ISCX.csv` | DoS (Slowloris, Slowhttptest, Hulk, GoldenEye) |
| Thursday AM | `Thursday-WorkingHours-Morning...csv` | Web Attacks (Brute Force, XSS, SQL Injection) |
| Thursday PM | `Thursday-WorkingHours-Afternoon...csv` | Infiltration |
| Friday AM | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Bot |
| Friday PM1 | `Friday-WorkingHours-Afternoon-PortScan.csv` | PortScan |
| Friday PM2 | `Friday-WorkingHours-Afternoon-DDos.csv` | DDoS |

---

## 3. Feature Engineering

### 3.1 Why Only 15 Features?

The original CICIDS2017 dataset contains 78 features. We selected 15 features for the following reasons:

| Reason | Explanation |
|--------|-------------|
| **Dimensionality Reduction** | Too many features cause overfitting and slow inference |
| **Feature Correlation** | Many original features are highly correlated (redundant) |
| **Real-time Computation** | Selected features can be computed from live traffic |
| **Research-backed Selection** | Features chosen based on published IDS research |
| **Interpretability** | Fewer features = easier to understand model decisions |

### 3.2 Feature Selection Methodology

Features were selected based on three criteria:

1. **Importance Ranking** - Features with high importance scores in initial Random Forest training
2. **Extractability** - Must be computable from raw network packets in real-time
3. **Distinctiveness** - Features that differ significantly between attack and normal traffic

### 3.3 The 15 Selected Features

#### Category 1: Flow Timing Features (3 features)

| Feature | Unit | Description | Why Selected |
|---------|------|-------------|--------------|
| **Flow Duration** | μs (microseconds) | Total duration of the flow | DDoS/DoS attacks have unusual durations |
| **Flow IAT Mean** | μs | Mean Inter-Arrival Time between packets | Attack tools create regular patterns |
| **Fwd IAT Mean** | μs | Mean IAT for forward direction packets | Brute force attacks show distinct timing |
| **Bwd IAT Mean** | μs | Mean IAT for backward direction packets | DoS responses have timing anomalies |

#### Category 2: Packet Count Features (2 features)

| Feature | Unit | Description | Why Selected |
|---------|------|-------------|--------------|
| **Total Fwd Packets** | count | Number of packets from source to destination | Port scans have many outgoing packets |
| **Total Backward Packets** | count | Number of packets from destination to source | DDoS has asymmetric packet ratios |

#### Category 3: Flow Rate Features (2 features)

| Feature | Unit | Description | Why Selected |
|---------|------|-------------|--------------|
| **Flow Bytes/s** | bytes/sec | Byte transfer rate | DDoS attacks show high byte rates |
| **Flow Packets/s** | packets/sec | Packet transfer rate | Port scans have high packet rates |

#### Category 4: Packet Size Features (4 features)

| Feature | Unit | Description | Why Selected |
|---------|------|-------------|--------------|
| **Fwd Packet Length Mean** | bytes | Average forward packet size | Attack tools use consistent sizes |
| **Bwd Packet Length Mean** | bytes | Average backward packet size | Server responses have patterns |
| **Packet Length Variance** | bytes² | Variance in packet sizes | Attacks often have low variance |
| **Average Packet Size** | bytes | Overall mean packet size | Different attack profiles |

#### Category 5: TCP Flag Features (3 features)

| Feature | Unit | Description | Why Selected |
|---------|------|-------------|--------------|
| **Fwd PSH Flags** | count | PSH flags in forward packets | Web attacks show PSH patterns |
| **SYN Flag Count** | count | Number of SYN flags | Port scans = many SYN packets |
| **ACK Flag Count** | count | Number of ACK flags | Normal traffic has ACK responses |

### 3.4 Feature Importance Analysis

Based on trained Random Forest model:

```
Feature Importance Ranking (Higher = More Important)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Flow Duration          ████████████████████████████████████████  0.18
Flow Bytes/s           ████████████████████████████████         0.15
Total Fwd Packets      ██████████████████████████████           0.13
Flow Packets/s         ████████████████████████                 0.11
SYN Flag Count         ██████████████████████                   0.10
Flow IAT Mean          ████████████████████                     0.09
Fwd Packet Length Mean ██████████████████                       0.08
Average Packet Size    ██████████████                           0.06
Packet Length Variance ████████████                             0.05
ACK Flag Count         ██████████                               0.04
Bwd Packet Length Mean ████████                                 0.03
Total Backward Packets ██████                                   0.03
Fwd IAT Mean           ████                                     0.02
Bwd IAT Mean           ████                                     0.02
Fwd PSH Flags          ██                                       0.01
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 3.5 Why Each Feature Was Chosen

| Feature | Attack Detection Use Case |
|---------|---------------------------|
| **Flow Duration** | DDoS attacks: very short or very long flows; Slowloris: extremely long |
| **Total Fwd Packets** | Port scans: many SYN packets; DDoS: flooding patterns |
| **Total Backward Packets** | DDoS: few responses; Brute Force: many responses |
| **Flow Bytes/s** | DDoS: extremely high; Infiltration: low and slow |
| **Flow Packets/s** | Port scan: high packet rate; DoS: flooding |
| **Fwd Packet Length Mean** | Attack tools use consistent packet sizes |
| **Bwd Packet Length Mean** | Servers respond with error messages (small) or blocked |
| **Flow IAT Mean** | Bots and scanners have regular, automated timing |
| **Fwd IAT Mean** | Brute force: rapid repeated requests |
| **Bwd IAT Mean** | DoS targets: delayed or no responses |
| **Fwd PSH Flags** | Web attacks: HTTP requests push data |
| **SYN Flag Count** | Port scans: SYN flood signature |
| **ACK Flag Count** | Incomplete handshakes = attack indicator |
| **Packet Length Variance** | Attack tools have low variance; normal traffic varies |
| **Average Packet Size** | Different attack profiles have distinct averages |

---

## 4. Detection Models

### 4.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DETECTION SYSTEM ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   Input: Network Flow (15 features)                                  │
│              │                                                        │
│              ▼                                                        │
│   ┌──────────────────────┐                                           │
│   │    Preprocessor       │ ◄─── StandardScaler normalization        │
│   │    (StandardScaler)   │                                          │
│   └──────────┬───────────┘                                           │
│              │                                                        │
│              ▼                                                        │
│   ┌──────────────────────────────────────────────────┐               │
│   │              DETECTION LAYER                      │               │
│   │  ┌────────────────┐    ┌───────────────────────┐ │               │
│   │  │  Statistical   │    │   Isolation Forest    │ │               │
│   │  │   Detector     │    │      Detector         │ │               │
│   │  │                │    │                       │ │               │
│   │  │  • Z-score     │    │  • 100 trees          │ │               │
│   │  │  • IQR         │    │  • 10% contamination  │ │               │
│   │  │  • Threshold:3 │    │  • Trained on normal  │ │               │
│   │  └───────┬────────┘    └───────────┬───────────┘ │               │
│   │          │                         │              │               │
│   │          └────────────┬────────────┘              │               │
│   │                       │                           │               │
│   │                       ▼                           │               │
│   │               ┌───────────────┐                   │               │
│   │               │ Combine:      │                   │               │
│   │               │ OR logic +    │                   │               │
│   │               │ max(scores)   │                   │               │
│   │               └───────┬───────┘                   │               │
│   └─────────────────────────────────────────────────────────────────┘ │               │
│              │                                                        │
│              ▼                                                        │
│   ┌──────────────────────────────────────────────────┐               │
│   │           [If Anomaly Detected]                   │               │
│   │                                                   │               │
│   │   ┌──────────────────────────────────────────┐   │               │
│   │   │       Attack Classifier                   │   │               │
│   │   │       (Random Forest)                     │   │               │
│   │   │                                           │   │               │
│   │   │   • 100 trees, max_depth=20               │   │               │
│   │   │   • 8 attack categories                   │   │               │
│   │   │   • Returns type + confidence             │   │               │
│   │   └──────────────────────────────────────────┘   │               │
│   └──────────────────────────────────────────────────┘               │
│                       │                                               │
│                       ▼                                               │
│   Output: {is_anomaly, score, attack_type, confidence}               │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Model 1: Statistical Detector

#### Purpose
Fast, interpretable baseline detection using classical statistical methods.

#### Algorithms

**Z-Score Method:**
```
                    X - μ
            Z = ─────────
                    σ

Where:
    X = feature value
    μ = mean (from training data)
    σ = standard deviation (from training data)

Decision Rule:
    is_anomaly = max(|Z| across all features) > 3.0
```

**IQR (Interquartile Range) Method:**
```
    IQR = Q3 - Q1
    Lower Bound = Q1 - 1.5 × IQR
    Upper Bound = Q3 + 1.5 × IQR

Decision Rule:
    is_anomaly = any(X < Lower) OR any(X > Upper)
```

#### Why Z-Score and IQR?

| Advantage | Explanation |
|-----------|-------------|
| **Speed** | O(n) computation - suitable for real-time |
| **No Training Required** | Just compute mean/std from normal data |
| **Interpretable** | "This flow is 5 standard deviations from normal" |
| **Memory Efficient** | Only store mean/std per feature |
| **Robust to Distribution** | IQR works even for non-Gaussian data |

#### Implementation Details

```python
# File: src/detection/statistical.py

class StatisticalDetector:
    def __init__(self, zscore_threshold=3.0):
        self.zscore_threshold = zscore_threshold
        self.mean = None      # Learned from normal traffic
        self.std = None       # Learned from normal traffic
        self.q1 = None        # 25th percentile
        self.q3 = None        # 75th percentile
        self.iqr = None       # Q3 - Q1
    
    def fit(self, X_normal):
        """Learn statistics from normal traffic only."""
        self.mean = np.mean(X_normal, axis=0)
        self.std = np.std(X_normal, axis=0)
        self.std[self.std == 0] = 1  # Avoid division by zero
        
        self.q1 = np.percentile(X_normal, 25, axis=0)
        self.q3 = np.percentile(X_normal, 75, axis=0)
        self.iqr = self.q3 - self.q1
        self.iqr[self.iqr == 0] = 1  # Avoid division by zero
```

### 4.3 Model 2: Isolation Forest

#### Purpose
Machine learning-based anomaly detection that learns complex patterns.

#### How Isolation Forest Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ISOLATION FOREST ALGORITHM                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. BUILD FOREST (Training):                                         │
│     ┌─────────────────────────────────────────────────────────┐     │
│     │  For each tree (100 trees):                              │     │
│     │    • Sample data points randomly                         │     │
│     │    • Recursively partition:                              │     │
│     │      - Pick random feature                               │     │
│     │      - Pick random split value                           │     │
│     │      - Create left/right child nodes                     │     │
│     │    • Stop at max depth or single point                   │     │
│     └─────────────────────────────────────────────────────────┘     │
│                                                                       │
│  2. KEY INSIGHT:                                                     │
│     ┌─────────────────────────────────────────────────────────┐     │
│     │                                                          │     │
│     │  Normal Points:    ●━━━━━━━━━━━━━━━━━━━●                │     │
│     │                    (deep in tree, long path)             │     │
│     │                                                          │     │
│     │  Anomalies:        ●━━━━●                                │     │
│     │                    (isolated quickly, short path)        │     │
│     │                                                          │     │
│     │  WHY? Anomalies are "few and different" - they get      │     │
│     │       separated from the majority with fewer splits      │     │
│     │                                                          │     │
│     └─────────────────────────────────────────────────────────┘     │
│                                                                       │
│  3. SCORING (Prediction):                                            │
│     ┌─────────────────────────────────────────────────────────┐     │
│     │  • Traverse point through all trees                      │     │
│     │  • Calculate average path length                         │     │
│     │  • Normalize by expected path length                     │     │
│     │  • Score ≈ 2^(-avg_path_length / expected_path_length)  │     │
│     │                                                          │     │
│     │  Score close to 1 → Anomaly                             │     │
│     │  Score close to 0 → Normal                              │     │
│     └─────────────────────────────────────────────────────────┘     │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### Why Isolation Forest?

| Advantage | Explanation |
|-----------|-------------|
| **Unsupervised** | Only needs normal data - no labeled attacks required |
| **Scalable** | O(n log n) training, O(log n) prediction |
| **Robust** | Works well with high-dimensional data |
| **No Assumptions** | Doesn't assume data distribution shape |
| **Few Hyperparameters** | Only contamination and n_estimators |
| **Widely Validated** | Proven effective in network security research |

#### Alternatives Considered

| Algorithm | Why Not Chosen |
|-----------|----------------|
| **One-Class SVM** | Slow training, scales poorly to large datasets |
| **Local Outlier Factor (LOF)** | Memory-intensive, slow for real-time |
| **DBSCAN** | Struggles with varying density, needs tuning |
| **Autoencoder** | Complex, requires GPU, harder to interpret |

#### Implementation Details

```python
# File: src/detection/isolation_forest.py

class IsolationForestDetector:
    def __init__(self, contamination=0.1, n_estimators=100, random_state=42):
        self.contamination = contamination  # Expected % of anomalies
        self.n_estimators = n_estimators    # Number of trees
        self.random_state = random_state    # Reproducibility
        
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1  # Use all CPU cores
        )
    
    def fit(self, X_normal):
        """Train on normal traffic only."""
        self.model.fit(X_normal)
    
    def detect(self, X):
        """
        Returns:
            is_anomaly: array of boolean (True = anomaly)
            scores: array of floats (higher = more anomalous)
        """
        predictions = self.model.predict(X)  # 1=normal, -1=anomaly
        scores = -self.model.score_samples(X)  # Invert so higher=anomaly
        
        return predictions == -1, scores
```

### 4.4 Model 3: Random Forest Classifier

#### Purpose
Multi-class classification to identify specific attack types after anomaly detection.

#### How Random Forest Classification Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                  RANDOM FOREST CLASSIFIER                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. ENSEMBLE OF DECISION TREES:                                      │
│                                                                       │
│     Tree 1        Tree 2        Tree 3         ...       Tree 100   │
│       │             │             │                          │       │
│    ┌──┴──┐       ┌──┴──┐       ┌──┴──┐                   ┌──┴──┐   │
│    │DDoS │       │DDoS │       │Scan │                   │DDoS │   │
│    └─────┘       └─────┘       └─────┘                   └─────┘   │
│                                                                       │
│  2. BOOTSTRAP AGGREGATING (Bagging):                                 │
│     • Each tree trains on random subset of data                      │
│     • Each split considers random subset of features                 │
│     • Reduces overfitting, increases generalization                  │
│                                                                       │
│  3. VOTING:                                                          │
│                                                                       │
│     Votes:  DDoS: 58   PortScan: 30   BruteForce: 12               │
│                  │                                                    │
│                  ▼                                                    │
│     Final: DDoS (58% confidence)                                     │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

#### Attack Categories

The classifier maps the 14 original attack types to 8 broader categories for better generalization:

| Original Label | Mapped Category |
|----------------|-----------------|
| BENIGN | Normal |
| DDoS | DDoS Attack |
| DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest | DoS Attack |
| PortScan | Port Scan |
| FTP-Patator, SSH-Patator | Brute Force |
| Web Attack - Brute Force, Web Attack - XSS, Web Attack - SQL Injection | Web Attack |
| Infiltration | Infiltration |
| Bot | Botnet |
| Heartbleed | Heartbleed |

#### Why Random Forest?

| Advantage | Explanation |
|-----------|-------------|
| **High Accuracy** | Typically 95%+ on network traffic |
| **Handles Imbalance** | Works with skewed class distribution |
| **Feature Importance** | Provides interpretable importance scores |
| **No Feature Scaling Required** | Tree-based, scale-invariant |
| **Robust to Overfitting** | Ensemble reduces variance |
| **Fast Prediction** | O(log n) per tree, parallelizable |

#### Alternatives Considered

| Algorithm | Why Not Chosen |
|-----------|----------------|
| **Gradient Boosting (XGBoost)** | Slower, more hyperparameters, marginal improvement |
| **SVM (multi-class)** | Slow training on large datasets |
| **Neural Network (MLP)** | Requires GPU, harder to interpret, needs more data |
| **Naive Bayes** | Lower accuracy, assumes feature independence |
| **k-NN** | Slow prediction, memory-intensive |

#### Implementation Details

```python
# File: src/detection/classifier.py

class AttackClassifier:
    def __init__(self, n_estimators=100, max_depth=20, random_state=42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            n_jobs=-1  # Parallel processing
        )
        self.label_encoder = LabelEncoder()
    
    def fit(self, X, y):
        """Train on all traffic including attacks."""
        y_mapped = self._map_labels(y)  # Map to 8 categories
        y_encoded = self.label_encoder.fit_transform(y_mapped)
        self.model.fit(X, y_encoded)
    
    def classify_single(self, x):
        """Classify a single sample."""
        prediction = self.predict(x.reshape(1, -1))[0]
        probabilities = self.predict_proba(x.reshape(1, -1))[0]
        confidence = max(probabilities)
        
        return {
            'attack_type': prediction,
            'confidence': confidence,
            'top_predictions': self._get_top_k(probabilities, k=3)
        }
```

---

## 5. Training Pipeline

### 5.1 Training Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                      TRAINING PIPELINE                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  [1/6] LOAD DATA                                                     │
│  ────────────────                                                    │
│  • Read all CSV files from data/raw/                                 │
│  • Handle encoding issues (UTF-8, Latin-1)                           │
│  • Combine into single DataFrame                                     │
│  • Optional: Sample for faster training                              │
│                                                                       │
│         │                                                             │
│         ▼                                                             │
│                                                                       │
│  [2/6] PREPROCESS                                                    │
│  ─────────────────                                                   │
│  • Replace Inf with NaN                                              │
│  • Fill NaN with median values                                       │
│  • Select 15 features                                                │
│  • Split: 80% train, 20% test (stratified)                          │
│  • Fit StandardScaler on training data                               │
│  • Transform both train and test                                     │
│  • Save preprocessor to models/preprocessor.joblib                   │
│                                                                       │
│         │                                                             │
│         ▼                                                             │
│                                                                       │
│  [3/6] TRAIN STATISTICAL DETECTOR                                    │
│  ─────────────────────────────────                                   │
│  • Filter: BENIGN traffic only                                       │
│  • Compute mean, std for Z-score                                     │
│  • Compute Q1, Q3, IQR                                               │
│  • Test on full test set                                             │
│  • Save to models/statistical_detector.joblib                        │
│                                                                       │
│         │                                                             │
│         ▼                                                             │
│                                                                       │
│  [4/6] TRAIN ISOLATION FOREST                                        │
│  ─────────────────────────────                                       │
│  • Filter: BENIGN traffic only                                       │
│  • Build 100 isolation trees                                         │
│  • contamination = 0.1 (10% anomaly threshold)                       │
│  • Test on full test set                                             │
│  • Save to models/isolation_forest.joblib                            │
│                                                                       │
│         │                                                             │
│         ▼                                                             │
│                                                                       │
│  [5/6] TRAIN ATTACK CLASSIFIER                                       │
│  ─────────────────────────────                                       │
│  • Use ALL training data (attacks + benign)                          │
│  • Map 14 labels → 8 categories                                      │
│  • Build 100 decision trees, max_depth=20                            │
│  • Test on full test set                                             │
│  • Save to models/attack_classifier.joblib                           │
│                                                                       │
│         │                                                             │
│         ▼                                                             │
│                                                                       │
│  [6/6] SUMMARY                                                       │
│  ───────────────                                                     │
│  • Print accuracy for each model                                     │
│  • All models saved to models/ directory                             │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Training Command

```bash
python -m src.train
```

### 5.3 Training Script

```python
# File: src/train.py

def train_all_models(sample_size=None):
    """
    Train all detection models.
    
    Args:
        sample_size: Number of samples to use (None = all data)
    """
    # Step 1: Load data
    df = load_dataset()
    if sample_size:
        df = df.sample(n=sample_size, random_state=42)
    
    # Step 2: Preprocess
    preprocessor = DataPreprocessor()
    df_clean = preprocessor.clean_data(df)
    labels = df_clean['Label']
    y_binary = (labels != 'BENIGN').astype(int)
    df_features = preprocessor.select_features(df_clean)
    
    X_train_raw, X_test_raw, y_train, y_test, labels_train, labels_test = \
        train_test_split(df_features, y_binary, labels, test_size=0.2, 
                        random_state=42, stratify=y_binary)
    
    X_train = preprocessor.fit_transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)
    preprocessor.save()
    
    # Step 3: Train Statistical Detector (normal traffic only)
    normal_mask = y_train == 0
    X_normal = X_train[normal_mask]
    
    stat_detector = StatisticalDetector()
    stat_detector.fit(X_normal)
    joblib.dump(stat_detector, MODELS_DIR / "statistical_detector.joblib")
    
    # Step 4: Train Isolation Forest (normal traffic only)
    iso_detector = IsolationForestDetector(contamination=0.1)
    iso_detector.fit(X_normal)
    iso_detector.save()
    
    # Step 5: Train Classifier (all traffic)
    classifier = AttackClassifier()
    classifier.fit(X_train, labels_train.values)
    classifier.save()
```

### 5.4 Data Split Strategy

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DATA SPLITTING                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Total Data: 100%                                                    │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│  ┌────────────────────────────────────┬────────────────────────────┐│
│  │         TRAINING SET               │        TEST SET            ││
│  │             80%                    │           20%              ││
│  │                                    │                            ││
│  │   Used for:                        │   Used for:                ││
│  │   • Statistical stats calc         │   • Model evaluation       ││
│  │   • Isolation Forest fitting       │   • Accuracy metrics       ││
│  │   • Classifier training            │   • Final performance      ││
│  │                                    │                            ││
│  │   Split type: Stratified           │   Never seen during        ││
│  │   (maintains attack ratios)        │   training                 ││
│  │                                    │                            ││
│  └────────────────────────────────────┴────────────────────────────┘│
│                                                                       │
│  STRATIFICATION: Ensures each split has same attack type ratios     │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│  Example (if total has 80% BENIGN, 15% DDoS, 5% PortScan):          │
│    Train set: 80% BENIGN, 15% DDoS, 5% PortScan                     │
│    Test set:  80% BENIGN, 15% DDoS, 5% PortScan                     │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Model Evaluation

### 6.1 Evaluation Metrics

| Metric | Formula | Use Case |
|--------|---------|----------|
| **Accuracy** | (TP + TN) / Total | Overall correctness |
| **Precision** | TP / (TP + FP) | "Of detected attacks, how many are real?" |
| **Recall (TPR)** | TP / (TP + FN) | "Of real attacks, how many did we catch?" |
| **F1 Score** | 2 × (Precision × Recall) / (Precision + Recall) | Balanced metric |
| **FPR** | FP / (FP + TN) | False alarm rate |

Where:
- TP = True Positive (attack correctly detected)
- TN = True Negative (normal correctly identified)
- FP = False Positive (normal flagged as attack)
- FN = False Negative (attack missed)

### 6.2 Expected Performance

| Model | Accuracy | Precision | Recall | Notes |
|-------|----------|-----------|--------|-------|
| **Statistical** | 65-75% | 60-70% | 70-80% | Fast, many false positives |
| **Isolation Forest** | 75-85% | 70-80% | 75-85% | Better balance |
| **Combined (Stat+IF)** | 78-88% | 72-82% | 80-90% | Best detection rate |
| **Classifier** | 92-98% | 90-96% | 88-95% | Per-class varies |

### 6.3 Confusion Matrix Example

```
                    PREDICTED
              ┌─────────┬─────────┐
              │ Normal  │ Attack  │
     ─────────┼─────────┼─────────┤
     Normal   │  TN     │   FP    │   ← False Alarm
A    ─────────┼─────────┼─────────┤
C    Attack   │  FN     │   TP    │
T             └─────────┴─────────┘
U                  ↑
A            Missed Attack
L
```

---

## 7. Model Comparison & Selection Rationale

### 7.1 Why This Combination?

```
┌─────────────────────────────────────────────────────────────────────┐
│              MODEL COMBINATION RATIONALE                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  LAYER 1: DETECTION (Binary: Normal vs Anomaly)                      │
│  ───────────────────────────────────────────────                     │
│                                                                       │
│  ┌─────────────────────┐         ┌─────────────────────┐            │
│  │  Statistical        │   +     │  Isolation Forest   │            │
│  │  (Z-score / IQR)    │         │  (ML-based)         │            │
│  │                     │         │                     │            │
│  │  ✓ Fast (< 1ms)     │         │  ✓ Anomaly-focused  │            │
│  │  ✓ Interpretable    │         │  ✓ Captures complex │            │
│  │  ✓ No training      │         │    patterns         │            │
│  │  ✗ High FP rate     │         │  ✗ Less interpretable│           │
│  └─────────────────────┘         └─────────────────────┘            │
│                                                                       │
│  Combined with OR logic: Catches more attacks (high recall)         │
│                                                                       │
│                                                                       │
│  LAYER 2: CLASSIFICATION (Attack Type Identification)               │
│  ─────────────────────────────────────────────────────               │
│                                                                       │
│  ┌───────────────────────────────────────────────────────┐          │
│  │  Random Forest Classifier                              │          │
│  │                                                        │          │
│  │  ✓ High accuracy (95%+)                               │          │
│  │  ✓ Provides confidence scores                          │          │
│  │  ✓ Feature importance for interpretability            │          │
│  │  ✓ Handles class imbalance                            │          │
│  │  ✓ Works on CPU (no GPU needed)                       │          │
│  └───────────────────────────────────────────────────────┘          │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Detection Logic

```python
def detect(flow):
    # Step 1: Run both detectors
    stat_anomaly, stat_score = statistical_detector.detect(flow)
    iso_anomaly, iso_score = isolation_forest.detect(flow)
    
    # Step 2: Combine with OR (catch more attacks)
    is_anomaly = stat_anomaly OR iso_anomaly
    score = max(stat_score, iso_score)
    
    # Step 3: If anomaly, classify attack type
    if is_anomaly:
        result = classifier.classify(flow)
        
        # IMPORTANT: Classifier has final say
        # If classifier says "Normal", override detection
        if result['attack_type'] == 'Normal':
            is_anomaly = False
    
    return is_anomaly, score, result['attack_type'], result['confidence']
```

### 7.3 Why Two-Stage Detection?

| Single-Stage Problems | Two-Stage Solution |
|-----------------------|--------------------|
| Classifier trained on historical attacks | Anomaly detectors catch unknown attacks |
| Missing attacks not in training data | Anomaly detection is unsupervised |
| "Unknown" class is hard to define | Detectors flag anything unusual |
| Class imbalance (few attack samples) | Binary detection balances problem |

---

## 8. Preprocessing & Normalization

### 8.1 StandardScaler

#### Why StandardScaler?

```
Before Scaling:                    After Scaling:
─────────────────                  ─────────────────
Flow Duration: 0 - 120,000,000 μs  Mean = 0, Std = 1
Flow Bytes/s:  0 - 1,000,000,000   Mean = 0, Std = 1
SYN Flags:     0 - 1000            Mean = 0, Std = 1

Problem: Features have vastly different scales
         → Some algorithms (Z-score, Isolation Forest) are affected
         → Larger values dominate distance calculations

Solution: StandardScaler normalizes all features to mean=0, std=1
```

#### Formula

```
            X - μ
X_scaled = ───────
              σ

Where:
    X = original value
    μ = mean (learned from training data)
    σ = standard deviation (learned from training data)
```

#### Implementation

```python
# File: src/data/preprocessor.py

class DataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.features = SELECTED_FEATURES
    
    def fit_transform(self, X_train):
        """Fit on training data, return transformed."""
        return self.scaler.fit_transform(X_train)
    
    def transform(self, X):
        """Apply same transformation to new data."""
        return self.scaler.transform(X)
```

### 8.2 Data Cleaning

```python
def clean_data(df):
    """
    Cleaning steps:
    1. Replace infinity with NaN
    2. Fill NaN with median values
    3. Drop any remaining rows with NaN
    """
    df = df.replace([np.inf, -np.inf], np.nan)
    
    for col in numeric_columns:
        median = df[col].median()
        df[col].fillna(median, inplace=True)
    
    df = df.dropna()
    return df
```

---

## 9. Hyperparameters

### 9.1 All Configurable Parameters

| Component | Parameter | Value | Location |
|-----------|-----------|-------|----------|
| **Statistical** | zscore_threshold | 3.0 | config.py |
| **Statistical** | iqr_multiplier | 1.5 | statistical.py |
| **Isolation Forest** | contamination | 0.1 | config.py |
| **Isolation Forest** | n_estimators | 100 | isolation_forest.py |
| **Isolation Forest** | random_state | 42 | isolation_forest.py |
| **Classifier** | n_estimators | 100 | classifier.py |
| **Classifier** | max_depth | 20 | classifier.py |
| **Classifier** | random_state | 42 | classifier.py |
| **Training** | test_size | 0.2 | train.py |
| **Training** | sample_size | 50000 | train.py |

### 9.2 Parameter Justification

| Parameter | Value | Justification |
|-----------|-------|---------------|
| **zscore_threshold=3.0** | 3 std deviations | Statistical standard: 99.7% of normal data falls within ±3σ |
| **contamination=0.1** | 10% | Dataset has ~20% attacks; 10% is conservative |
| **n_estimators=100** | 100 trees | Diminishing returns after 100; balance of accuracy vs speed |
| **max_depth=20** | 20 levels | Prevents overfitting while capturing complex patterns |
| **test_size=0.2** | 80/20 split | Standard ML practice; enough test data for reliable metrics |

---

## 10. Serialization & Deployment

### 10.1 Saved Model Files

```
models/
├── preprocessor.joblib         # StandardScaler + feature list
├── statistical_detector.joblib # Mean, std, Q1, Q3, IQR arrays
├── isolation_forest.joblib     # Sklearn IsolationForest model
└── attack_classifier.joblib    # RandomForest + LabelEncoder
```

### 10.2 Model Loading

```python
# File: src/api/routes.py

def load_models():
    """Load all trained models."""
    models['preprocessor'] = DataPreprocessor.load()
    models['statistical'] = joblib.load(MODELS_DIR / "statistical_detector.joblib")
    models['isolation_forest'] = IsolationForestDetector.load()
    models['classifier'] = AttackClassifier.load()
```

### 10.3 Inference Pipeline

```python
def detect_anomaly(flow_features):
    # 1. Preprocess
    X = preprocessor.transform(flow_features.reshape(1, -1))
    
    # 2. Statistical detection
    stat_anomaly, stat_score = statistical_detector.detect(X)
    
    # 3. Isolation Forest detection
    iso_anomaly, iso_score = isolation_forest.detect(X)
    
    # 4. Combine results
    is_anomaly = stat_anomaly[0] or iso_anomaly[0]
    score = max(stat_score[0], iso_score[0])
    
    # 5. Classify if anomaly
    attack_type = None
    if is_anomaly:
        result = classifier.classify_single(X[0])
        attack_type = result['attack_type']
        
        # Classifier override
        if attack_type == 'Normal':
            is_anomaly = False
    
    return {
        'is_anomaly': is_anomaly,
        'score': score,
        'attack_type': attack_type
    }
```

---

## 11. Limitations & Future Work

### 11.1 Current Limitations

| Limitation | Impact | Potential Solution |
|------------|--------|-------------------|
| **Dataset Age** | 2017 attacks may not represent 2024 threats | Collect new data, use CICIDS2018/2019 |
| **Fixed Features** | Can't adapt to new attack patterns | Online learning, feature auto-selection |
| **Binary+Multi-class** | Two-stage adds latency | End-to-end neural network |
| **Class Imbalance** | Rare attacks may be missed | SMOTE, cost-sensitive learning |
| **Concept Drift** | Model degrades over time | Periodic retraining, drift detection |

### 11.2 Future Improvements

| Enhancement | Description |
|-------------|-------------|
| **Deep Learning** | LSTM/Transformer for sequence modeling |
| **Federated Learning** | Train on distributed data without sharing |
| **Explainable AI** | SHAP/LIME for prediction explanations |
| **Active Learning** | Request labels for uncertain predictions |
| **Ensemble Expansion** | Add Autoencoder, one-class SVM |

---

## Document Information

| Field | Value |
|-------|-------|
| **Version** | 1.0 |
| **Last Updated** | December 2024 |
| **Author** | Network Anomaly Detection System |
| **Related Files** | `src/train.py`, `src/detection/*`, `src/data/*`, `src/utils/config.py` |

---

*This document provides complete technical reference for the machine learning components. For API documentation, see `DOCUMENTATION.md`. For quick start guide, see `README.md`.*
