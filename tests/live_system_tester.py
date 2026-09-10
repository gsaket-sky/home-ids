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
    import yaml
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'config.yaml'), 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        sys.exit(1)

cfg = load_config()

# Load .env variables so the tester has access to secrets
def _load_env():
    env_path = os.path.join(os.path.dirname(__file__), '..', cfg.get("dynamic_live_reload", {}).get("env_file", ".env"))
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("Environment="): line = line[12:]
                if not line or line.startswith("#") or "=" not in line: continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k not in os.environ: os.environ[k] = v.strip().strip("'\"")
_load_env()
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
conn_log = os.path.join(zeek_log_dir, "test_conn.log")
dhcp_log = os.path.join(zeek_log_dir, "test_dhcp.log")
dns_log = os.path.join(zeek_log_dir, "test_dns.log")

print("⏳ Waiting 35 seconds for pipeline (FastEmbed/Models) to initialize before injecting logs...")
time.sleep(35)
now = time.time()
test_start_ts = now
print(f"Injecting logs at TS {now:.1f}")

# 1. Inject Honeypot Probe (Stage 1)
honeypot_ip = dynamic.get("honeypot_ips", ["192.168.1.200"])[0]
with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CHoney1", "id.orig_h": threats["Stage 1 - Honeypot Probe"]["ip"], "id.orig_p": 4444, "id.resp_h": honeypot_ip, "id.resp_p": 22, "proto": "tcp", "conn_state": "S0"}) + "\n")

with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CGeo1", "id.orig_h": threats["Stage 1 - Geofencing (RU)"]["ip"], "id.orig_p": 5555, "id.resp_h": "194.58.112.174", "id.resp_p": 443, "proto": "tcp", "conn_state": "SF"}) + "\n")

# Dynamically pick a malicious Threat Intel IP that is currently loaded in the system cache
ti_cache_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "state", "ti_cache", "combined.json.gz")
malicious_ti_ip = "185.153.196.23" # fallback
if os.path.exists(ti_cache_path):
    try:
        import gzip
        with gzip.open(ti_cache_path, "rt", encoding="utf-8") as f:
            payload = json.load(f)
            if payload and "ips" in payload and payload["ips"]:
                if isinstance(payload["ips"], dict):
                    malicious_ti_ip = next(iter(payload["ips"].keys()))
                elif isinstance(payload["ips"], list):
                    malicious_ti_ip = payload["ips"][0]
    except Exception:
        pass

with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CTi1", "id.orig_h": threats["Stage 1 - Threat Intel Hit"]["ip"], "id.orig_p": 6666, "id.resp_h": malicious_ti_ip, "id.resp_p": 80, "proto": "tcp", "conn_state": "SF"}) + "\n")

def inject_pihole_dns_batch(records: list):
    import sqlite3
    for _ in range(5):
        try:
            conn = sqlite3.connect("/etc/pihole/pihole-FTL.db", timeout=20)
            try:
                # Pi-hole v6 Schema: Requires mapping strings to domain_by_id and client_by_id
                v6_records = []
                for r in records:
                    ts, client_ip, domain_str, reply_type = int(r[0]), r[1], r[2], r[3]
                    
                    conn.execute("INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?)", (domain_str,))
                    domain_id = conn.execute("SELECT id FROM domain_by_id WHERE domain = ?", (domain_str,)).fetchone()[0]
                    
                    conn.execute("INSERT OR IGNORE INTO client_by_id (ip, name) VALUES (?, ?)", (client_ip, client_ip))
                    client_id = conn.execute("SELECT id FROM client_by_id WHERE ip = ?", (client_ip,)).fetchone()[0]
                    
                    v6_records.append((ts, domain_id, client_id, reply_type))
                    
                conn.executemany("INSERT INTO query_storage (timestamp, type, status, domain, client, forward, additional_info, reply_type) VALUES (?, 1, 2, ?, ?, NULL, NULL, ?)", 
                                 v6_records)
            except sqlite3.OperationalError:
                # Pi-hole v5 Schema
                try:
                    # Pi-hole v5.15+ (has reply_type in queries table)
                    conn.executemany("INSERT INTO queries (timestamp, type, status, domain, client, forward, additional_info, reply_type) VALUES (?, 1, 2, ?, ?, '', '', ?)", 
                                     [(int(r[0]), r[2], r[1], r[3]) for r in records])
                except sqlite3.OperationalError:
                    # Legacy Pi-hole v5 Schema (No reply_type)
                    conn.executemany("INSERT INTO queries (timestamp, type, status, domain, client, forward, additional_info) VALUES (?, 1, ?, ?, ?, '', '')", 
                                     [(int(r[0]), 3 if r[3] in (2, 3) else 2, r[2], r[1]) for r in records])
            conn.commit()
            conn.close()
            return
        except sqlite3.OperationalError:
            import time
            time.sleep(1)
        except Exception as e:
            print(f"⚠️ Failed to batch inject mock DNS into Pi-hole DB: {e}")
            break

# 1. Warmup ML Engine (Inject 1000 distinct IPs to satisfy _WARMUP_GLOBAL = 1000)
# We use .0.0/16 local IPs so they pass the trackable_local_ip check
warmup_records = [(now - 60, f"172.16.{(i//250)%256}.{i%250 + 1}", "google.com", 2) for i in range(1010)]
# Split into chunks of 200 for Pi-hole injection to avoid SQLite limits
for i in range(0, len(warmup_records), 200):
    inject_pihole_dns_batch(warmup_records[i:i+200])

print("⏳ Waiting 10 seconds for ML Engine background training to complete...")
import time
time.sleep(10)
now = time.time()
    
# 2. Inject DGA Domain (Stage 2) - Must be >12 chars and high entropy (>4.0)
# "qwertyuiopasdfghjklzxcvbnm" has 26 distinct characters, entropy = log2(26) = 4.7
high_ent_domain = "qwertyuiopasdfghjklzxcvbnm.com"
inject_pihole_dns_batch([(now, threats["ML Engine / Stage 2 - DGA Domain"]["ip"], high_ent_domain, 2)])

# 3. Inject FP Engine (Stage 3) - Microsoft Telemetry, BUT simulate high risk via 600 queries so it triggers an alert
telemetry_ms = [(now + (i * 0.001), threats["Stage 3 - FP Engine (Telemetry)"]["ip"], "telemetry.microsoft.com", 4) for i in range(600)]
inject_pihole_dns_batch(telemetry_ms)

# 4. Inject Layer-2 ARP Spoofing (Stage 1)
with open(dhcp_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now - 30, "mac": "aa:bb:cc:dd:ee:01", "client_addr": threats["Stage 1 - ARP Spoofing"]["ip"]}) + "\n")
    f.write(json.dumps({"ts": now, "mac": "aa:bb:cc:dd:ee:99", "client_addr": threats["Stage 1 - ARP Spoofing"]["ip"]}) + "\n")
with open(conn_log, "a") as f:
    f.write("\n" + json.dumps({"ts": now, "uid": "CArp", "id.orig_h": threats["Stage 1 - ARP Spoofing"]["ip"], "id.resp_h": "8.8.8.8"}) + "\n")

# 5. Inject ML Engine Anomaly (Stage 2 DGA)
# Burst of DGA-like domains with massive NXDOMAINs to trigger global baseline anomaly even if bespoke ml_warmup_samples isn't met
dga_burst = [(now + (i * 0.001), threats["ML Engine / Stage 2 - DGA Domain"]["ip"], f"qwertyuiopasdfghjklzxcvbnm-{i}.ru", 3 if i % 2 == 0 else 2) for i in range(600)]
inject_pihole_dns_batch(dga_burst)

# 6. Inject FP Engine Stage 3 Anomaly (Safe Vendor Telemetry)
# Massive spike of legitimate telemetry to trigger Anomaly Model
telemetry_sentry = [(now + (i * 0.1), threats["Stage 3 - FP Engine (Telemetry)"]["ip"], "telemetry.sentry.io", 4) for i in range(600)]
inject_pihole_dns_batch(telemetry_sentry)

print(f"✅ Successfully injected mock logs to {zeek_log_dir}")
print("⏳ Waiting up to 60 seconds for the live pipeline and ML Engine to process...")

# Evaluation Loop
max_wait = 60
start_wait = time.time()

alerts_path = static.get("alert_json_path", "alerts.json")
if not os.path.isabs(alerts_path):
    alerts_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', alerts_path))
print(f"DEBUG: Using alerts_path: {alerts_path}")

# Clear previous test data
if os.path.exists(alerts_path):
    print(f"DEBUG: Removing existing {alerts_path}")
    os.remove(alerts_path)

while True:
    time.sleep(2)
    elapsed = time.time() - start_wait
    
    # Read alerts
    alerts = []
    if os.path.exists(alerts_path):
        with open(alerts_path, "r") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    a = json.loads(line)
                    print(f"[DEBUG] Read alert with timestamp: {a.get('timestamp')} (test_start_ts={test_start_ts})")
                    if a.get("timestamp", 0) >= test_start_ts - 5:
                        alerts.append(a)
                except json.JSONDecodeError:
                    pass
    
    # Print debug info on the LAST iteration before timeout
    if elapsed > max_wait - 3:
        print(f"[DEBUG] Found {len(alerts)} alerts. Keys in alert_map: {[a.get('device', {}).get('ip') for a in alerts]}")
    
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
        a_time = actual_alert.get("timestamp", now) if actual_alert else now
        
        latency_alert = max(0, a_time - now)
        
        if actual_risk >= expected:
            print(f"  ✅ {name} -> Detected! Risk: {actual_risk:.1f} | Alert: {latency_alert:.1f}s (IP: {ip})")
            test_results.append(f"✅ {name} (Alert: {latency_alert:.1f}s)")
        else:
            print(f"  ❌ {name} -> FAILED! Risk: {actual_risk:.1f}, Expected: {expected:.1f} (IP: {ip})")
            test_results.append(f"❌ {name} (Failed Risk: {actual_risk:.1f})")
            all_passed = False

tg_status = "Skipped"

print("\n[Validating External API Integrations]")
telegram_token = os.environ.get("TELEGRAM_TOKEN", cfg.get("static_requires_restart", {}).get("telegram_token", ""))
telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", cfg.get("static_requires_restart", {}).get("telegram_chat_id", ""))
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

webhook_port = static.get("fastapi_port", 8010)
webhook_status = "✅ Online"
api_token = os.environ.get("API_SECRET_TOKEN", cfg.get("static_requires_restart", {}).get("fritz_api_token", ""))

print("\n[Validating Webhook & Mitigation Endpoints]")
try:
    # Test Router Block
    req = urllib.request.Request(f"http://127.0.0.1:{webhook_port}/api/ipc/block_get?target=192.168.1.199&token={api_token}", method='GET')
    with urllib.request.urlopen(req, timeout=15) as resp:
        if json.loads(resp.read().decode('utf-8')).get("status") == "success":
            print("  ✅ Router Webhook Block -> Passed")
        else:
            print("  ❌ Router Webhook Block -> Failed")
            webhook_status = "❌ Failed"
            all_passed = False
    
    # Test Router Release
    req = urllib.request.Request(f"http://127.0.0.1:{webhook_port}/api/ipc/release_get?target=192.168.1.199&token={api_token}", method='GET')
    with urllib.request.urlopen(req, timeout=15) as resp:
        if json.loads(resp.read().decode('utf-8')).get("status") == "success":
            print("  ✅ Router Webhook Release -> Passed")
        else:
            print("  ❌ Router Webhook Release -> Failed")
            webhook_status = "❌ Failed"
            all_passed = False
            
    # Test Pi-hole Block
    req = urllib.request.Request(f"http://127.0.0.1:{webhook_port}/api/ipc/block_domain_get?target=test-block-domain.com&token={api_token}", method='GET')
    with urllib.request.urlopen(req, timeout=15) as resp:
        if json.loads(resp.read().decode('utf-8')).get("status") == "success":
            print("  ✅ Pi-hole Webhook Block -> Passed")
        else:
            print("  ❌ Pi-hole Webhook Block -> Failed")
            webhook_status = "❌ Failed"
            all_passed = False
            
    # Test Pi-hole Release
    req = urllib.request.Request(f"http://127.0.0.1:{webhook_port}/api/ipc/release_domain_get?target=test-block-domain.com&token={api_token}", method='GET')
    with urllib.request.urlopen(req, timeout=15) as resp:
        if json.loads(resp.read().decode('utf-8')).get("status") == "success":
            print("  ✅ Pi-hole Webhook Release -> Passed")
        else:
            print("  ❌ Pi-hole Webhook Release -> Failed")
            webhook_status = "❌ Failed"
            all_passed = False
            
except urllib.error.HTTPError as e:
    err_body = e.read().decode('utf-8')
    print(f"  ❌ Webhook Integration Tests -> FAILED (HTTP {e.code}: {err_body})")
    webhook_status = "❌ Failed"
    all_passed = False
except Exception as e:
    print(f"  ❌ Webhook Integration Tests -> FAILED ({e})")
    webhook_status = "❌ Failed"
    all_passed = False

print("\n[Cleaning Up IPS / Releasing Webhook]")
for name, data in threats.items():
    ip = data["ip"]
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{webhook_port}/api/ipc/release_get?target={ip}&token={api_token}", method='GET')
        with urllib.request.urlopen(req, timeout=15) as resp:
            pass # Released gracefully
    except Exception as e:
        print(f"  ⚠️ Warning: Could not cleanly release {ip}: {e}")
        webhook_status = "❌ Failed"

report_lines = ["🧪 <b>Home-IDS Live Test Report</b>\n", "<b>Threat Detection & AFPE:</b>"]
for res in test_results:
    report_lines.append(res)
report_lines.append(f"\n<b>Integrations:</b>\nTelegram API: {tg_status}\nLocal Webhook: {webhook_status}")

if all_passed and webhook_status == "✅ Online":
    print("\n==========================================================")
    print("🏆 ALL STAGE 1, 2, AND 3 INTEGRATIONS PASSED PERFECTLY!")
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

if not all_passed or webhook_status != "✅ Online":
    sys.exit(1)
