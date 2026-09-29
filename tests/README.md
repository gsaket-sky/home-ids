# Home IDS Testing Suite

This folder contains the validation scripts used to ensure the Network Detection & Response (NDR) platform operates flawlessly.

There are two primary test scripts. **Please read carefully to understand when and how to run each.**

---

## 1. `regression_tester.py` (The Offline Engine Tester)
This script acts as a mathematical unit test. It imports the internal AI classes (like `DecisionEngine` and `StateManager`) and tests them directly without relying on the network or the main service.

- **What it does:**
  - Evaluates the core AI decision engine against 6 complex edge cases to ensure risk scores evaluate precisely from 0.0 to 10.0.
  - Pings the Threat Intelligence APIs (AbuseIPDB, VirusTotal) to ensure their output formats haven't broken.
  - Tests the state-management system's ability to survive warm restarts without file corruption.
- **When to run it:** 
  - After making code changes to `.py` logic, tweaking machine learning mathematics, or altering `config.json`.
- **State Requirement:** 
  - The main `soc.service` **can be STOPPED or RUNNING**. It doesn't matter, as this script tests the code independently in an isolated sandbox.
- **How to run:**
  ```bash
  python3 tests/regression_tester.py
  ```

---

## 2. `live_system_tester.py` (The Live Mock-IP Injector)
This script acts as a live-fire drill. It does *not* import any internal python classes. Instead, it generates fake Zeek logs and directly injects them into the live log stream to test the end-to-end pipeline.

- **What it does:**
  - Creates 5 dummy IPs (`192.168.77.251` - `.255`).
  - Injects formatted malicious traffic (Honeypot hits, Geofencing violations, Threat Intel hits, Layer-2 MAC spoofing, and DGA DNS domains) into `/opt/zeek/logs/current/`.
  - Asserts that your running pipeline detected them and assigned a Risk Score of 10.0 in `state/alerts.json`.
  - Automatically triggers the FastAPI webhook to cleanly Un-Isolate the dummy IPs so your router doesn't get cluttered.
- **When to run it:**
  - When you want to confirm that the entire production ecosystem (Zeek -> Python Pipeline -> Webhooks -> Router) is working perfectly together.
- **State Requirement:** 
  - The main `soc.service` **MUST BE RUNNING**. If the main script is stopped, this test will fail because nothing will process the injected logs.
- **How to run:**
  *(Requires root privileges to write to Zeek directories)*
  ```bash
  sudo python3 tests/live_system_tester.py
  ```
