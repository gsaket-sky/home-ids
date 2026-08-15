import os
import sys
import json
import time
import urllib.request
import urllib.error

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

print("==========================================================")
print("🧨 LIVE SYSTEM TESTER: MULTI-STAGE INJECTION & TIMING")
print("==========================================================")

def load_config():
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'config.json'), 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        sys.exit(1)

cfg = load_config()
static = cfg.get("static_requires_restart", {})
dynamic = cfg.get("dynamic_live_reload", {})

zeek_log_dir = static.get("zeek_log_dir", "/opt/zeek/logs/current")
if os.name == 'nt' and zeek_log_dir.startswith("/opt"):
    zeek_log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'mock_zeek_logs'))

os.makedirs(zeek_log_dir, exist_ok=True)
alerts_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', static.get("alert_json_path", "state/alerts.json")))
muted_log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'state', 'autonomous_muted.jsonl'))

import random

# Generate a random base block for IPs (e.g. 100-240) to avoid in-memory 5-minute suppression cooldowns 
# between repeated test runs without restarting the service.
rb = random.randint(100, 240)

# We use Dummy IPs that don't exist, preventing real disconnects.
threats = {
    "Stage 1 - Honeypot Probe": {"ip": f"192.168.1.{rb}", "expected_risk": 10.0, "should_suppress": False},
    "Stage 1 - Geofencing (RU)": {"ip": f"192.168.1.{rb+1}", "expected_risk": 10.0, "should_suppress": False},
    "Stage 1 - Threat Intel Hit": {"ip": f"192.168.1.{rb+2}", "expected_risk": 10.0, "should_suppress": False},
    "Stage 1 - ARP Spoofing": {"ip": f"192.168.1.{rb+3}", "expected_risk": 10.0, "should_suppress": False},
    "ML Engine / Stage 2 - DGA Domain": {"ip": f"192.168.1.{rb+4}", "expected_risk": 6.0, "should_suppress": False},
    "Stage 3 - FP Engine (Telemetry)": {"ip": f"192.168.1.{rb+5}", "expected_risk": 0.0, "should_suppress": True}
}

now = time.time()
conn_log = os.path.join(zeek_log_dir, "conn.log")
dhcp_log = os.path.join(zeek_log_dir, "dhcp.log")
dns_log = os.path.join(zeek_log_dir, "dns.log")

print(f"Injecting logs at TS {now:.1f}")

# 1. Inject Honeypot Probe (Stage 1)
honeypot_ip = dynamic.get("honeypot_ips", ["192.168.1.200"])[0]
with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CHoney1", "id.orig_h": threats["Stage 1 - Honeypot Probe"]["ip"], "id.orig_p": 4444, "id.resp_h": honeypot_ip, "id.resp_p": 22, "proto": "tcp", "conn_state": "S0"}) + "\n")

with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CGeo1", "id.orig_h": threats["Stage 1 - Geofencing (RU)"]["ip"], "id.orig_p": 5555, "id.resp_h": "194.58.112.174", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}) + "\n")

# Dynamically pick a malicious Threat Intel IP that is currently loaded in the system cache
ti_cache_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "state", "ti_cache", "ip_intel.json")
malicious_ti_ip = "185.153.196.23" # fallback
if os.path.exists(ti_cache_path):
    try:
        with open(ti_cache_path, "r") as f:
            intel_data = json.load(f)
            if intel_data and isinstance(intel_data, dict):
                # Just pick the first IP in the cache
                malicious_ti_ip = next(iter(intel_data.keys()))
    except: pass

with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CTi1", "id.orig_h": threats["Stage 1 - Threat Intel Hit"]["ip"], "id.orig_p": 6666, "id.resp_h": malicious_ti_ip, "id.resp_p": 80, "proto": "tcp", "conn_state": "SF"}) + "\n")

def inject_pihole_dns(ts: float, client_ip: str, domain: str, reply_type: int = 2):
    try:
        import sqlite3
        conn = sqlite3.connect("/etc/pihole/pihole-FTL.db", timeout=10)
        # Try inserting into query_storage (Pi-hole v6)
        conn.execute("INSERT INTO query_storage (timestamp, type, status, domain, client, forward, additional_info, reply_type) VALUES (?, 1, 2, ?, ?, '', '', ?)", 
                     (int(ts), domain, client_ip, reply_type))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        # Fallback to older Pi-hole v5 schema where queries is a real table
        try:
            conn = sqlite3.connect("/etc/pihole/pihole-FTL.db", timeout=10)
            try:
                conn.execute("INSERT INTO queries (timestamp, type, status, domain, client, forward, additional_info, reply_type) VALUES (?, 1, 2, ?, ?, '', '', ?)", 
                             (int(ts), domain, client_ip, reply_type))
            except sqlite3.OperationalError:
                conn.execute("INSERT INTO queries (timestamp, type, status, domain, client, forward, additional_info) VALUES (?, 1, 2, ?, ?, '', '')", 
                             (int(ts), domain, client_ip))
            conn.commit()
            conn.close()
        except Exception as e2:
            print(f"⚠️ Failed to inject mock DNS into Pi-hole DB (fallback): {e2}")
    except Exception as e:
        print(f"⚠️ Failed to inject mock DNS into Pi-hole DB: {e}")

# 2. Inject DGA Domain (Stage 2) - Must be >12 chars
inject_pihole_dns(now, threats["ML Engine / Stage 2 - DGA Domain"]["ip"], "xkqzjyvwqzjyvw.com", reply_type=2)

# 3. Inject FP Engine (Stage 3) - Microsoft Telemetry, BUT simulate high risk via 25 queries so it triggers an alert
for i in range(25):
    inject_pihole_dns(now + (i * 0.1), threats["Stage 3 - FP Engine (Telemetry)"]["ip"], "telemetry.microsoft.com", reply_type=4)

# 4. Inject Layer-2 ARP Spoofing (Stage 1)
with open(dhcp_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now - 30, "mac": "aa:bb:cc:dd:ee:01", "client_addr": threats["Stage 1 - ARP Spoofing"]["ip"]}) + "\n")
    f.write(json.dumps({"ts": now, "mac": "aa:bb:cc:dd:ee:99", "client_addr": threats["Stage 1 - ARP Spoofing"]["ip"]}) + "\n")
with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CArp", "id.orig_h": threats["Stage 1 - ARP Spoofing"]["ip"], "id.resp_h": "8.8.8.8"}) + "\n")

# 5. Inject ML Engine Anomaly (Stage 2 DGA)
# Burst of DGA-like domains to trigger DNS baseline anomaly and fall to Stage 2 LGBM
for i in range(15):
    inject_pihole_dns(now + (i*0.1), threats["ML Engine / Stage 2 - DGA Domain"]["ip"], f"xkqz289dfj10dj-{i}.ru", reply_type=2)

# 6. Inject FP Engine Stage 3 Anomaly (Safe Vendor Telemetry)
# Burst of telemetry domains to trigger anomaly, but should be suppressed by Stage 3 FastEmbed
for i in range(15):
    inject_pihole_dns(now + (i*0.1), threats["Stage 3 - FP Engine (Telemetry)"]["ip"], "telemetry.sentry.io", reply_type=4)

print(f"✅ Successfully injected mock logs to {zeek_log_dir}")
print("⏳ Waiting up to 15 minutes for the live pipeline, ML Engine, and Ollama to process...")

# Evaluation Loop
max_wait = 900
start_wait = time.time()
ollama_timeout = False

while True:
    time.sleep(2)
    elapsed = time.time() - start_wait
    
    # Read alerts
    alerts = []
    if os.path.exists(alerts_path):
        with open(alerts_path, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        a = json.loads(line)
                        if a.get("timestamp", 0) >= now - 5:
                            alerts.append(a)
                    except: pass
    
    # Read suppressed
    suppressed = []
    if os.path.exists(muted_log_path):
        with open(muted_log_path, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        a = json.loads(line)
                        if a.get("ts_unix", a.get("timestamp", 0)) >= now - 5:
                            suppressed.append(a)
                    except: pass

    # Maps
    alerts_only = [a for a in alerts if a.get("type") != "ollama_transparency"]
    alert_map = {a.get("device", {}).get("ip", ""): a for a in alerts_only if a.get("device", {}).get("ip")}
    suppress_map = {a.get("device", {}).get("ip", ""): a for a in suppressed if a.get("device", {}).get("ip")}
    
    # Check completion
    all_done = True
    for name, data in threats.items():
        ip = data["ip"]
        if data["should_suppress"]:
            if ip not in suppress_map:
                all_done = False
                break
        else:
            if ip not in alert_map:
                all_done = False
                break
                
    if all_done:
        print(f"✅ All events processed in {elapsed:.1f} seconds!")
        break
    
    if elapsed > max_wait:
        print(f"⚠️ Timed out after {max_wait} seconds waiting for events.")
        ollama_timeout = True
        break
    
    if int(elapsed) % 15 == 0:
        print(f"   ... still waiting ({int(elapsed)}s elapsed) ...")

print("\n[Validation Results & Latency]")
all_passed = True
test_results = []

for name, data in threats.items():
    ip = data["ip"]
    expected = data["expected_risk"]
    should_suppress = data["should_suppress"]
    
    if should_suppress:
        if ip in suppress_map:
            s_time = suppress_map[ip].get("ts_unix", suppress_map[ip].get("timestamp", now))
            latency = max(0, s_time - now)
            print(f"  ✅ {name} -> SUPPRESSED correctly by FP Engine. Risk: 0.0 | Latency: {latency:.1f}s (IP: {ip})")
            test_results.append(f"✅ {name} (Suppressed in {latency:.1f}s)")
        else:
            actual_risk = alert_map.get(ip, {}).get("risk", alert_map.get(ip, {}).get("risk_score", 0.0))
            print(f"  ❌ {name} -> FAILED! Was NOT suppressed. Risk: {actual_risk} (IP: {ip})")
            test_results.append(f"❌ {name} (Failed - Not Suppressed)")
            all_passed = False
    else:
        actual_alert = alert_map.get(ip)
        actual_risk = actual_alert.get("risk", actual_alert.get("risk_score", 0.0)) if actual_alert else 0.0
        has_ollama = ip in transparency_map
        
        a_time = actual_alert.get("timestamp", now) if actual_alert else now
        o_time = transparency_map[ip].get("timestamp", now) if has_ollama else now
        
        latency_alert = max(0, a_time - now)
        latency_ollama = max(0, o_time - now)
        
        if actual_risk >= expected:
            ollama_status = f"Ollama Summary: YES ({latency_ollama:.1f}s)" if has_ollama else "Ollama Summary: NO"
            print(f"  ✅ {name} -> Detected! Risk: {actual_risk:.1f} | Alert: {latency_alert:.1f}s | {ollama_status} (IP: {ip})")
            if has_ollama:
                test_results.append(f"✅ {name} (Alert: {latency_alert:.1f}s, Ollama: {latency_ollama:.1f}s)")
            else:
                test_results.append(f"❌ {name} (Alert OK, Ollama Failed)")
                all_passed = False
        else:
            print(f"  ❌ {name} -> FAILED! Risk: {actual_risk:.1f}, Expected: {expected:.1f} (IP: {ip})")
            test_results.append(f"❌ {name} (Failed Risk: {actual_risk:.1f})")
            all_passed = False

tg_status = "Skipped"

print("\n[Validating External API Integrations]")
telegram_token = cfg.get("static_requires_restart", {}).get("telegram_token", "")
telegram_chat_id = cfg.get("static_requires_restart", {}).get("telegram_chat_id", "")
if telegram_token:
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{telegram_token}/getMe", method='GET')
        with urllib.request.urlopen(req, timeout=5) as resp:
            tg_data = json.loads(resp.read().decode('utf-8'))
            if tg_data.get("ok"):
                print("  ✅ Telegram API -> Online and Authenticated")
                tg_status = "✅ Online"
            else:
                print("  ❌ Telegram API -> FAILED (Invalid Token)")
                all_passed = False
                tg_status = "❌ Failed"
    except Exception as e:
        print(f"  ❌ Telegram API -> FAILED ({e})")
        all_passed = False
        tg_status = "❌ Failed"
else:
    print("  ⚠️ Telegram API -> Skipped (No token configured)")

webhook_status = "✅ Online"
print("\n[Cleaning Up IPS / Releasing Webhook]")
webhook_port = static.get("fastapi_port", 8010)
for name, data in threats.items():
    ip = data["ip"]
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{webhook_port}/api/ipc/release_get?target={ip}", method='GET')
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass # Released gracefully
    except Exception as e:
        print(f"  ⚠️ Warning: Could not cleanly release {ip}: {e}")
        webhook_status = "❌ Failed"

report_lines = ["🧪 <b>Home-IDS Live Test Report</b>\n", "<b>Threat Detection & AFPE:</b>"]
for res in test_results:
    report_lines.append(res)
report_lines.append(f"\n<b>Integrations:</b>\nTelegram API: {tg_status}\nLocal Webhook: {webhook_status}")

if all_passed and not ollama_timeout and webhook_status == "✅ Online":
    print("\n==========================================================")
    print("🏆 ALL STAGE 1, 2, 3 AND OLLAMA INTEGRATIONS PASSED PERFECTLY!")
    print("==========================================================")
    report_lines.insert(1, "🎉 <b>STATUS: ALL PASSED</b>\n")
else:
    print("\n==========================================================")
    print("⚠️ SOME TESTS FAILED OR TIMED OUT.")
    print("==========================================================")
    report_lines.insert(1, "⚠️ <b>STATUS: ISSUES DETECTED</b>\n")

if telegram_token and telegram_chat_id:
    try:
        msg_text = "\n".join(report_lines)
        data = json.dumps({"chat_id": telegram_chat_id, "text": msg_text, "parse_mode": "HTML"}).encode('utf-8')
        req = urllib.request.Request(f"https://api.telegram.org/bot{telegram_token}/sendMessage", data=data, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass
        print("📲 Successfully sent test report to Telegram.")
    except Exception as e:
        print(f"⚠️ Failed to send report to Telegram: {e}")

if not all_passed or ollama_timeout or webhook_status != "✅ Online":
    sys.exit(1)
