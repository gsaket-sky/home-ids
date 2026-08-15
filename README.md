# 🛡️ Home-IDS: Advanced Autonomous Threat Defense (Version 7)

**Home-IDS Version 7** is a professional-grade, autonomous Intrusion Detection and Prevention System (IDS/IPS) engineered for edge networks and smart home environments. Moving far beyond static blocklists, Home-IDS utilizes a state-of-the-art **Dual-Brain Architecture** to detect, analyze, and neutralize sophisticated threats in real-time, while autonomously learning to ignore false positives.

Designed for uncompromising security, it acts as a self-healing immune system for your network—capable of identifying Zero-Day malware, Domain Generation Algorithms (DGAs), and lateral movement.

---

## 🌟 The Dual-Brain Architecture

Version 7 introduces a revolutionary split-brain processing pipeline that combines raw speed with deep cognitive reasoning.

### 🧠 Brain 1: The Statistical Engine (Real-Time Pipeline)
The core detection loop operates entirely in-memory and asynchronously. It fuses high-volume network metadata from **Zeek (Bro)** with DNS logs from **Pi-hole**. 
- Evaluates thousands of packets per second with **zero network latency**.
- Uses a deterministic, graph-based **Hypothesis & Evidence Engine (HEE)**. Instead of a flat risk score, it collects structural network facts (e.g., `high_entropy`, `dns_tunneling`, `covert_beaconing`) and evaluates them against strict threat hypotheses (e.g., `EXFILTRATION`).
- Employs a custom LightGBM classifier to evaluate baseline temporal context (`time_sin`, `time_cos`) and diurnal rhythms.

### 🕵️ Brain 2: The Cognitive Analyst (Local LLM SOC)
While Brain 1 reacts in milliseconds, Brain 2 thinks in seconds. Home-IDS natively integrates with **Ollama (LLaMA 3.1)** running locally on your hardware as a background daemon.
- **Batch Analysis:** A dedicated background scheduler (`scheduler.py`) wakes up periodically to batch-process recent alerts.
- **Deep Reasoning:** It acts as a Tier 2 SOC Analyst, ingesting JSON evidence graphs, identifying attack chains, and writing executive summaries.
- **Hallucination Protection:** A deterministic guardrail system validates all AI decisions against actual OTX Threat Intelligence, physically preventing the LLM from hallucinating benign verdicts for known malicious IPs.

---

## 🧬 Autonomous Evolution & Self-Healing

Home-IDS gets smarter over time without any user intervention. It features two fully autonomous evolutionary loops:

### 1. Autotuning (Threshold Calibration)
The background daemon runs a daily `autotune` cron job that analyzes your network's unique standard deviation of risk scores over a 7-day rolling window. It automatically adjusts the mathematical alert thresholds in your configuration to perfectly fit your environment, silently reducing noise.

### 2. Self-Healing False Positives
When the **Cognitive Analyst (Brain 2)** reviews an alert and determines it to be a benign anomaly (e.g., a Smart TV uploading diagnostic telemetry), it doesn't just send you a report. 
- It actively extracts the benign domains.
- It dynamically injects them into the live `safe_host_patterns` configuration.
- The real-time pipeline (Brain 1) seamlessly reloads this configuration into memory without dropping a single packet. 
**The system literally patches its own ruleset to heal false positives forever.**

---

## 💥 Multi-Tier Hardware Containment

Upon detecting a critical threat, Home-IDS executes a latched, multi-tier isolation protocol:
*   **Layer 2 (ARP/NDP Dual-Stack Tarpitting)**: Instantly neutralizes the infected device locally using Scapy to forge ARP/NDP responses, severing its ability to communicate with other devices on the LAN.
*   **Layer 3 (Router WAN Isolation)**: Integrates via TR-064 API directly with Fritz!Box routers to instantly sever the infected device's connection to the internet, terminating C2 beaconing.
*   **Layer 7 (DNS Sinkholing)**: Automatically updates Pi-hole blocklists to sinkhole malicious infrastructure network-wide.

---

## 📊 Enterprise Observability

- **SecOps via Telegram:** Receive interactive, 1-sentence AI executive summaries. Approve hardware isolation or manually immunize devices with a single tap using inline buttons.
- **Markdown Reports:** The background daemon generates daily, beautifully formatted Markdown reports detailing top domains and all cognitive threat analysis.
- **Prometheus & Grafana:** Full integration with Prometheus metrics and Loki logs, providing enterprise-level visibility into HEE decision states, AI confidence intervals, and autonomous mitigations across your entire infrastructure.

For detailed configuration, architecture charts, and metric definitions, see the [USER_MANUAL.md](USER_MANUAL.md).
