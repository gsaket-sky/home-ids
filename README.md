# 🛡️ Home-IDS: Advanced Autonomous Threat Defense (Version 6)

Home-IDS is a professional-grade, autonomous Intrusion Detection and Prevention System (IDS/IPS) engineered for edge networks and smart home environments. Moving beyond static blocklists, Home-IDS utilizes machine learning, behavioral heuristics, and multi-layered hardware isolation to detect, analyze, and neutralize sophisticated threats in real-time.

Designed for uncompromising security, it acts as a self-healing immune system for your network—capable of identifying Zero-Day malware, Domain Generation Algorithms (DGAs), and lateral movement, while strictly guarding against false positives through dynamic, AI-driven trust caching.

## 🌟 Advanced Professional-Grade Features

### 🕵️ Hypothesis & Evidence Engine (HEE)
Version 5 introduces a deterministic, graph-based decision engine. Instead of relying on a flat arithmetic risk score, the system collects structural network facts (e.g., `high_entropy`, `dns_tunneling`, `covert_beaconing`) into an Evidence Store and evaluates them against strict threat hypotheses (e.g., `EXFILTRATION`, `C2_BEACONING`). This drastically improves accuracy and explainability.

### 🤖 Autonomous Local AI SOC (Ollama)
Home-IDS natively integrates with **Ollama (LLaMA 3.1)** running locally on your hardware. When a threat triggers an alert, the HEE exports the entire evidence graph as JSON and feeds it to the local LLM. The LLM operates as a Tier 2 SOC Analyst, autonomously investigating the alert, summarizing the payload, and appending executive analysis directly to your Telegram alerts. A deterministic reputation guardrail prevents the AI from hallucinating benign verdicts for known malicious IPs.

### 🧠 Temporal Machine Learning (CL-AFPE)
Employs a custom LightGBM classifier and IsolationForest models to autonomously learn the baseline behavior of your specific network. Version 5 injects time-of-day contextual awareness (`time_sin`, `time_cos`) into the ML pipeline, allowing the AI to understand diurnal rhythms and eliminate false positives during non-standard hours. Safe domains are automatically immunized via a 14-day rolling trust cache.

### 💥 Autonomous Hardware-Level Containment
Upon detecting a critical threat or lateral internal network scan, Home-IDS executes a latched, multi-tier isolation protocol:
*   **Layer 2 (ARP/NDP Dual-Stack Tarpitting)**: Instantly neutralizes the infected device locally using Scapy to forge ARP/NDP responses, severing its ability to communicate with other devices on the LAN.
*   **Layer 3 (Router WAN Isolation)**: Integrates via TR-064 API directly with Fritz!Box routers to instantly sever the infected device's connection to the internet, terminating Command & Control (C2) beaconing.
*   **Layer 7 (DNS Sinkholing)**: Automatically updates Pi-hole blocklists to sinkhole malicious infrastructure network-wide.

### 📱 Interactive SecOps via Telegram
Provides a fully interactive Security Operations Center (SecOps) interface directly via Telegram. Receive 1-sentence AI executive summaries alongside detailed, separated vectors of DNS and L4 Network activity. Approve hardware isolation or manually immunize False Positives with a single tap using interactive inline buttons.

### 🔍 Multi-Vector Threat Intelligence Correlation
Fuses high-volume network metadata from Zeek (Bro) with DNS logs from Pi-hole. It correlates port activity, traffic payloads, and DNS queries across a sliding temporal window to calculate holistic threat confidence.

### 📊 Prometheus & Grafana Observability
Full integration with Prometheus metrics and Grafana, providing enterprise-level visibility into network health, HEE decision states, threat distribution, and autonomous mitigations across your entire infrastructure.
