# ⚙️ Home-IDS: Engineering & Architecture Manual

This manual is written for developers, security engineers, and data scientists. It deeply explores the internal mathematics, system architecture, and code-level orchestration of Home-IDS Version 7.

Unlike the User Manual (which explains *how to use* the system), this document explains exactly **how the system is built** and **why the mathematics work**.

---

## 📋 Table of Contents
1. [Core Architecture & The Real-Time Pipeline (`pipeline.py`)](#1-core-architecture--the-real-time-pipeline-pipelinepy)
2. [The Hypothesis & Evidence Engine (HEE)](#2-the-hypothesis--evidence-engine-hee)
3. [Machine Learning Methodologies](#3-machine-learning-methodologies)
4. [Temporal Mathematics & Baselining](#4-temporal-mathematics--baselining)
5. [Mitigation Pipeline & IPS Integrity](#5-mitigation-pipeline--ips-integrity)

---

## 1. Core Architecture & The Real-Time Pipeline (`pipeline.py`)

The heart of Home-IDS is `src/core/pipeline.py`. It is a strict `while True` execution loop that must never block. To achieve high throughput (processing thousands of packets per second), it relies on an asynchronous event architecture and highly concurrent memory locking.

### 1.1 Ingestion & File Cursors
Home-IDS fuses two completely different data streams:
1. **Pi-hole (SQLite)**: Polled asynchronously using `pihole_collector.py`.
2. **Zeek NDR (JSON Logs)**: Tailed continuously using `zeek_collector.py`.

**The `tail -F` Problem**: Standard file trailing is dangerous in production. If the python script crashes, upon reboot, `tail` would start reading from the end of the file, losing all the packets that arrived while the script was dead.
**The Solution**: `zeek_collector.py` utilizes a custom cursor tracking mechanism (`state/zeek_cursor_*.json`). As it processes Zeek JSON events, it serializes the exact byte-offset and file `inode` to disk. On reboot, it seeks to that exact byte offset, guaranteeing **zero packet loss** and **zero duplicate processing**.

### 1.2 The 5-Phase Execution Loop
To prevent Thread Deadlocks while calculating math on thousands of devices concurrently, `pipeline.py` strictly adheres to a 5-Phase lock-release pattern:

1. **Phase 1: State Snapshot (Fast Lock)**: The engine briefly locks the `StateManager` LRU Cache, copies the device's current baseline variables into local thread memory, and immediately releases the lock.
2. **Phase 2: Pre-fetch (No Lock)**: The engine parses raw Zeek dictionaries. Since this is purely functional, no locks are required.
3. **Phase 3: Local Compute (Fast Lock)**: The lock is re-acquired to compute localized temporal features (Z-Scores, Entropy).
4. **Phase 4: Expensive I/O (No Lock)**: The engine releases the lock to perform HTTP requests to AlienVault OTX, AbuseIPDB, and VirusTotal. This is critical—if the network drops, the engine will not freeze the `StateManager` while waiting for a 5-second API timeout.
5. **Phase 5: ML Scoring & Decision (Fast Lock)**: The lock is acquired one final time to push the computed feature matrix into the Hypothesis Engine and IsolationForest models.

---

## 2. The Hypothesis & Evidence Engine (HEE)

Located in `src/core/decision_engine.py`, the HEE replaces traditional "If-This-Then-That" rule engines with a probabilistic evidence graph.

### 2.1 The Evidence Store
Every anomaly detected by the feature extractors is normalized into an `Evidence` object.
```python
Evidence(
    type="zeek_lateral_scan",
    source="zeek",
    value=450,           # Raw number of S0/REJ packets
    confidence=0.90,     # Sensor reliability 
    independence_group="zeek_network"
)
```
The `independence_group` prevents evidence stuffing. If Zeek detects 500 dropped TCP packets, and Pi-hole detects 500 NXDOMAIN queries, the engine knows these are independent vectors. If Zeek detects an SMB scan and Zeek *also* detects an RDP scan, they are grouped under `zeek_network` and only the highest confidence value is passed to the Hypothesis graph.

### 2.2 Hypothesis Graphs & Node Weighting
A Hypothesis (e.g., `DATA_EXFILTRATION`) is a Directed Acyclic Graph (DAG). It requires specific evidence nodes to trigger.
- **DGA Beaconing**: Requires (`high_entropy` OR `ml_anomaly`) AND (`nxdomain_ratio`).
- **Data Exfiltration**: Requires (`outbound_bytes_zscore > 4.0`) AND (`connection_duration > 3600s`).

### 2.3 Markov State Transitions
The most advanced feature in the HEE is the `MarkovStateTracker`.
It maintains an $N \times N$ matrix of historical device states (`BENIGN`, `ANOMALOUS`, `SUSPICIOUS`, `HIGH`). 
If a smart plug stays in `BENIGN` for 6 months, the transition probability `P(BENIGN -> CRITICAL)` mathematically approaches `0.0001`. If it suddenly spikes to `CRITICAL`, the Markov Anomaly Score multiplies the final Threat Confidence, easily pushing it over the containment threshold.

---

## 3. Machine Learning Methodologies

Home-IDS utilizes a Tri-Brain approach to solve the classic IDS dilemma: high detection rates vs. high false-positive rates.

### 3.1 Brain 1: `ml_engine.py` (Bespoke IsolationForests)
We use `scikit-learn`'s `IsolationForest` because it does not require labeled training data (Unsupervised Learning).
- **The Global Model**: `models/ids_model.pkl` is trained on the aggregate $X$ matrix of your entire home. It acts as a baseline for new, unknown devices.
- **The Bespoke Fork**: Once a device generates `ml_warmup_samples` (e.g., 5,000 queries), `ml_engine.py` forks a new matrix specifically for that IP address (`devices/192.168.1.45.pkl`). 
- **The Math**: The model splits the feature space using random hyperplanes. If a data point (a network event) requires very few splits to be isolated in a terminal leaf node, it is mathematically deemed an anomaly.

### 3.2 Brain 2: `fp_engine.py` (CL-AFPE)
To prevent Brain 1 from blocking your smart TV when it downloads a firmware update, Brain 2 intercepts alerts before containment fires.
- **LightGBM ONNX Classifier**: A gradient-boosted decision tree optimized for tabular data. It calculates the raw probability $P(False Positive | Features)$.
- **FastEmbed Vector Similarity**: The engine serializes the alert payload into a string and passes it through `bge-small-en-v1.5-onnx-q`. It generates a 384-dimensional dense vector. It then calculates the **Cosine Similarity** against vectors of known benign events in the `fp_trust_cache.json`. If Similarity > 0.82, the alert is suppressed.
- **Live threshold tuning**: All four Stage 2/3 thresholds (`fp_lgbm_threshold`, `fp_embed_similarity_threshold`, `fp_combined_suppress_threshold`, `fp_combined_uncertain_threshold`) are read via a fresh `self.config.get(...)` call on every single evaluation — as of Version 7.0 there is no cached/construction-time copy anywhere in the evaluation path, so edits to `config.yaml` take effect on the very next alert with no restart.

### 3.3 Brain 3: `ollama_analyzer.py` (LLM Cognitive Core)
Brain 3 takes the JSON output of Brain 2 and feeds it to a localized Large Language Model (LLaMA 3.1) with a strict system prompt.
The LLM is given access to external context (AlienVault, device types). If the LLM deduces a benign telemetry pattern, a python regex extracts the domain from the LLM's Markdown output and dynamically injects it into `config.yaml`'s `network_and_devices.safe_host_patterns` list. As of Version 7.0 this write goes through `ruamel.yaml`'s round-trip mode rather than plain `pyyaml`, specifically so the file's existing comments and category structure survive the edit — a plain `yaml.safe_dump()` would silently discard every comment in the file on the first automated write.

---

## 4. Temporal Mathematics & Baselining

Home-IDS does not use static thresholds (e.g., "Alert if queries > 100"). It uses rolling statistical baselines, implemented in `src/core/state_guard.py`.

### 4.1 Exponentially Weighted Moving Average (EWMA)
For a feature $x$ at time $t$, the EWMA baseline $\mu_t$ is updated as:
$$ \mu_t = \alpha \cdot x_t + (1 - \alpha) \cdot \mu_{t-1} $$
Where $\alpha$ (defined as `baseline_alpha` in config) controls the memory. A small $\alpha$ (0.05) ensures the baseline is highly resistant to sudden spikes, meaning a malware infection cannot quickly "poison" the baseline to make itself look normal.

### 4.2 Welford's Online Algorithm for Variance
To compute the Z-Score, we need the standard deviation $\sigma$. Because storing millions of data points in memory is impossible, we use Welford's algorithm to compute rolling variance $\sigma^2$ on the fly:
$$ \sigma^2_t = (1 - \alpha) \cdot (\sigma^2_{t-1} + \alpha \cdot (x_t - \mu_{t-1})^2) $$
The final Z-Score is simply:
$$ Z = \frac{x_t - \mu_t}{\sigma_t} $$
If $Z > 3.0$, the event is a 3-sigma anomaly (top 0.3% of statistical probability).

### 4.3 Shannon Entropy for DGA Detection
Located in `src/utils.py`, we calculate the entropy $H$ of a domain string to detect Domain Generation Algorithms (e.g., `x89zj2.biz`):
$$ H = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i) $$
Where $P(x_i)$ is the character frequency. High entropy domains ($H > 4.5$) combined with a high `nxdomain_ratio` mathematically proves a botnet is hunting for a C2 server.

---

## 5. Mitigation Pipeline & IPS Integrity

The execution of containment is localized in `src/mitigation/ips.py`. It is engineered for fail-safe resilience.

### 5.1 Layer 7 (Pi-hole Sinkhole)
The engine executes a POST request to the Pi-hole `/api/v2/domains` endpoint. If the Pi-hole is offline, the domain is pushed into a Thread-Safe Dead Letter Queue (DLQ). The pipeline will automatically retry the mitigation on the next cycle, ensuring malicious domains are eventually sinkholed when the API returns online.

### 5.2 Layer 3 (Fritz!Box WAN Sever)
Uses the TR-064 SOAP API framework. By crafting a specific XML envelope, the engine instructs the router to apply the "Blocked" profile to the infected MAC address. This severs internet access at the physical gateway while leaving local LAN access intact (allowing you to SSH in and remediate the machine).

### 5.3 Layer 2 (Scapy ARP Tarpit)
The most aggressive mitigation. The engine forks a daemonized Scapy thread that continuously broadcasts forged ARP (IPv4) and NDP (IPv6) `is-at` packets on the local subnet. It tells the infected device that the MAC address of the Gateway is `00:00:00:00:00:00`. The infected device updates its internal routing table and routes all outbound malware traffic into a blackhole, neutralizing the threat even if Layer 3 (Router) mitigation fails.
