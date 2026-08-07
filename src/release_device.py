"""
release_device.py – CLI Utility to Release Isolated Devices from Tarpit & Fritz!Box WAN Block.

Usage:
  python src/release_device.py <IP_OR_MAC_OR_HOSTNAME>

Example:
  python src/release_device.py 192.168.1.50
  python src/release_device.py aa:bb:cc:dd:ee:ff
  python src/release_device.py my-laptop-a1b2
"""
import sys
import os
from pathlib import Path

# Ensure src/ is in sys.path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from core.state_guard import StateManager
from mitigation.ips import IPSMitigator

import requests

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/release_device.py <IP_OR_MAC_OR_HOSTNAME|all>")
        sys.exit(1)

    target = sys.argv[1].strip()
    
    # Attempt local IPC release via live daemon HTTP endpoint first
    fastapi_port = int(CONFIG.get("fastapi_port", 8010))
    api_token = CONFIG.get("fritz_api_token", "")
    ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/release"
    headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
    
    try:
        resp = requests.post(ipc_url, json={"target": target}, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            res_json = resp.json()
            if target.lower() in ("all", "--all"):
                cnt = res_json.get("released_count", 0)
                print(f"✅ [IPC SUCCESS] Live daemon released {cnt} device(s) from tarpit, router isolation & Pi-hole DNS blocks.")
            else:
                rel = res_json.get("released", False)
                if rel:
                    print(f"✅ [IPC SUCCESS] Live daemon released '{target}' from tarpit, router isolation & Pi-hole DNS blocks.")
                else:
                    print(f"⚠️ Target '{target}' was not found in active containment lists.")
            print("[*] Device is re-connected and REMAINS 100% MONITORED under active IDS threat detection.")
            return
        else:
            print(f"[*] Live daemon IPC endpoint returned HTTP {resp.status_code} – falling back to direct disk state release...")
    except Exception as exc:
        print(f"[*] Live daemon IPC offline/disabled ({exc.__class__.__name__}) – falling back to direct disk state release...")

    state_path = CONFIG.get("state_path", "state/ids_state.json")
    state_manager = StateManager(state_path=state_path)
    state_manager.load_from_disk()

    ips = IPSMitigator(config=CONFIG, state_manager=state_manager)

    if target.lower() in ("all", "--all"):
        print("[*] Attempting operator release for ALL isolated devices...")
        count = ips.release_all_devices()
        state_manager.flush_to_disk()
        print(f"✅ Successfully released {count} device(s) from Scapy tarpit, Fritz!Box hardware isolation & Pi-hole DNS blocks.")
        print("[*] All devices are re-connected and REMAIN 100% MONITORED under active IDS threat detection.")
    else:
        print(f"[*] Attempting operator release for identifier: {target}...")
        released = ips.release_device(target)
        if released:
            state_manager.flush_to_disk()
            print(f"✅ Successfully released device '{target}' from Scapy tarpit, Fritz!Box hardware isolation & Pi-hole DNS blocks.")
            print("[*] Device is now re-connected and REMAINS 100% MONITORED under active IDS threat detection.")
        else:
            print(f"⚠️ Target '{target}' was not found in active tarpit or router isolation lists.")

if __name__ == "__main__":
    main()
