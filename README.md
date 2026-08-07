🛡️ Home-IDS: Advanced Autonomous Threat Defense
Home-IDS is a professional-grade, autonomous Intrusion Detection and Prevention System (IDS/IPS) engineered for edge networks and smart home environments. Moving beyond static blocklists, Home-IDS utilizes machine learning, behavioral heuristics, and multi-layered hardware isolation to detect, analyze, and neutralize sophisticated threats in real-time.

Designed for uncompromising security, it acts as a self-healing immune system for your network—capable of identifying Zero-Day malware, Domain Generation Algorithms (DGAs), and lateral movement, while strictly guarding against false positives through dynamic, AI-driven trust caching.

🌟 Advanced Professional-Grade Features
🧠 Machine Learning False Positive Engine (CL-AFPE): Employs a custom LightGBM classifier to autonomously learn the baseline behavior of your specific network. It dynamically differentiates between benign telemetry (like CDNs or smart home "chattiness") and genuine threats, automatically immunizing safe domains via a 14-day rolling trust cache.

💥 Autonomous Hardware-Level Containment: Upon detecting a critical threat or lateral internal network scan, Home-IDS executes a latched, multi-tier isolation protocol:

Layer 2 (ARP/NDP Dual-Stack Tarpitting): Instantly neutralizes the infected device locally using Scapy to forge ARP/NDP responses, severing its ability to communicate with other devices on the LAN.
Layer 3 (Router WAN Isolation): Integrates via TR-064 API directly with Fritz!Box routers to instantly sever the infected device's connection to the internet, terminating Command & Control (C2) beaconing.
Layer 7 (DNS Sinkholing): Automatically updates Pi-hole blocklists to sinkhole malicious infrastructure network-wide.
🤖 Interactive Human-in-the-Loop (HITL) Telegram SecOps: Provides a fully interactive Security Operations Center (SecOps) interface directly via Telegram. Receive detailed, separated vectors of DNS and L4 Network activity, complete with real-time risk scores and AI confidence ratings. Approve hardware isolation or manually immunize False Positives with a single tap using interactive inline buttons.

🔍 Multi-Vector Threat Intelligence Correlation: Fuses high-volume network metadata from Zeek (Bro) with DNS logs from Pi-hole. It correlates port activity, traffic payloads, and DNS queries across a sliding 5-minute temporal window to calculate a holistic, contextualized Risk Score for every device on the network.

🌐 Zero-Day & DGA Detection Pipeline: Identifies highly randomized, machine-generated domains indicative of modern malware and botnets, catching threats that evade traditional static threat intelligence feeds.

📊 Prometheus & Grafana Observability: Full integration with Prometheus metrics and Grafana, providing enterprise-level visibility into network health, risk scores, threat distribution, and autonomous mitigations across your entire infrastructure.
