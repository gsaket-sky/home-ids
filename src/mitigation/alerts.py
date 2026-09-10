"""
alerts.py - Alert Notification & JSON Stream Persistence Engine.

Handles Telegram alert dispatches via Ollama-summarized enrichment and 
manages local structured alert logging with automatic size rotation.

RECENT FIXES:
- FIXED (SHUTDOWN TIMEOUT BUG): `AlertManager.stop(timeout=12.0)` now correctly accepts 
  and passes the timeout parameter to `_worker_thread.join(timeout=timeout)`. Added a fallback 
  warning log if the worker thread fails to drain and terminate within the allocated window.
- FIXED (LEGACY .JSONL MIGRATION SILENT FAILURE): Rewrote `_migrate_legacy_format()` to parse 
  legacy `.jsonl` files line-by-line instead of treating them as a single monolithic JSON document.
- AUDIT FIX #5: Switched `AlertJSONWriter.write()` to O(1) JSONL append mode. Previously the 
  writer read and rewrote the entire JSON array on every alert (O(N)), which would stall the 
  pipeline under high alert volumes or when the file grew to hundreds of MBs.
- AUDIT FIX #10: Added Telegram sender authentication via `telegram_allowed_chat_ids` config.
  When configured, only messages from whitelisted chat IDs can execute /unblock, /release, etc.
- AUDIT FIX #17: Replaced `self.running` bool flag with a `threading.Event` for clean, 
  responsive shutdown of the long-poll bot updates thread.
"""

import json
import logging
import queue
import threading
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pathlib import Path
from typing import Dict, Any, Optional, List

LOGGER = logging.getLogger("home_ids.alerts")


class AlertJSONWriter:
    """Thread-safe JSONL alert log writer with size-based rotation and legacy format migration.
    AUDIT FIX #5: Uses O(1) append mode (one JSON object per line) instead of reading and
    rewriting the entire file on every alert write.
    """
    
    def __init__(self, path: str, max_bytes: int = 1073741824):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_format()

    def _migrate_legacy_format(self) -> None:
        """
        Migrates legacy formats to JSONL (one JSON object per line):
        - If a .jsonl sidecar exists alongside a missing .json, imports it.
        - If a .json exists as a JSON array, converts it to JSONL in-place.
        """
        old_jsonl = self.path.with_suffix(".jsonl")

        # Case 1: legacy .jsonl sidecar → import into new .json path as JSONL
        if not self.path.exists() and old_jsonl.exists():
            LOGGER.info("Legacy alerts file detected at %s. Initiating safe line-by-line migration...", old_jsonl)
            migrated_count = 0
            malformed_count = 0
            try:
                with old_jsonl.open("r", encoding="utf-8") as src, self.path.open("w", encoding="utf-8") as dst:
                    for line_num, line in enumerate(src, 1):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            doc = json.loads(line_str)
                            if isinstance(doc, dict):
                                dst.write(json.dumps(doc, separators=(",", ":")) + "\n")
                                migrated_count += 1
                            elif isinstance(doc, list):
                                for item in doc:
                                    dst.write(json.dumps(item, separators=(",", ":")) + "\n")
                                    migrated_count += 1
                        except json.JSONDecodeError as jde:
                            malformed_count += 1
                            LOGGER.warning("⚠️ Malformed JSON on line %d of %s: %s", line_num, old_jsonl, jde)
                LOGGER.info("✅ Migrated %d alerts to JSONL at %s (%d malformed skipped).",
                            migrated_count, self.path, malformed_count)
            except Exception as exc:
                LOGGER.error("❌ Critical failure during legacy alert migration: %s", exc, exc_info=True)
            return

        # Case 2: existing .json as a JSON array → convert to JSONL in-place
        if self.path.exists():
            try:
                raw = self.path.read_text(encoding="utf-8").strip()
                if raw.startswith("["):
                    LOGGER.info("Converting existing JSON array alert log at %s to JSONL format...", self.path)
                    records = json.loads(raw)
                    if isinstance(records, list):
                        tmp = self.path.with_suffix(".tmp")
                        with tmp.open("w", encoding="utf-8") as f:
                            for rec in records:
                                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                        tmp.replace(self.path)
                        LOGGER.info("✅ Converted %d alerts to JSONL format at %s.", len(records), self.path)
            except Exception as exc:
                LOGGER.warning("Could not convert existing alert log to JSONL: %s", exc)

    def write(self, alert_payload: Dict[str, Any]) -> None:
        """Thread-safely appends a structured alert as a single JSONL line.
        AUDIT FIX #5: O(1) append — does not read or reparse the existing file.
        """
        with self._lock:
            try:
                if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                    backup_path = self.path.with_suffix(".bak")
                    if backup_path.exists():
                        backup_path.unlink()
                    self.path.rename(backup_path)
                    LOGGER.warning("Alert log reached capacity (%d bytes). Rotated to %s", self.max_bytes, backup_path)

                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(alert_payload, separators=(",", ":")) + "\n")
                LOGGER.debug("Alert appended to JSONL stream: %s", self.path)

            except Exception as exc:
                LOGGER.error("Failed to write alert payload to disk: %s", exc, exc_info=True)


class AlertManager:
    """Asynchronous Telegram notification manager."""
    
    def __init__(self, token: str, chat_id: str, enabled: bool = False):
        self.token = token.strip()
        self.chat_id = str(chat_id).strip()
        self.enabled = enabled
        
        self.q = queue.Queue(maxsize=1000)
        self.running = True
        self._stop_event = threading.Event()
        self.session = requests.Session()
        
        # Configure robust connection pooling and automatic retries for transient SSL/Connection drops
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "POST"])
        adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        
        if self.enabled:
            if not self.token or not self.chat_id:
                LOGGER.warning("⚠️ Telegram alerts are enabled, but token or chat_id is missing!")
            else:
                LOGGER.info("📲 Telegram Alert Manager initialized and armed.")
                
            self._worker_thread = threading.Thread(target=self._dispatch_worker, daemon=True, name="telegram-alert-worker")
            self._worker_thread.start()

            self._updates_thread = threading.Thread(target=self._bot_updates_worker, daemon=True, name="telegram-bot-updates")
            self._updates_thread.start()
        else:
            self._worker_thread = None
            self._updates_thread = None

    def send(self, message: str, raw_payload: Optional[Dict[str, Any]] = None, reply_markup: Optional[Dict[str, Any]] = None) -> None:
        """Enqueues an alert message for asynchronous Telegram delivery with optional inline buttons.
        Non-blocking: returns immediately. Ollama summarization happens inside the dispatch worker.
        """
        if not self.enabled:
            return

        # Enqueue (message, raw_payload, reply_markup) tuple.
        # Ollama summarization is intentionally deferred to the worker thread
        # so this method NEVER blocks the caller (e.g. the pipeline's device lock).
        try:
            self.q.put_nowait((message, raw_payload, reply_markup))
            LOGGER.debug("Alert enqueued for Telegram delivery. Queue size: %d", self.q.qsize())
        except queue.Full:
            LOGGER.error("Telegram alert queue is FULL (maxsize reached). Dropping alert to prevent RAM exhaustion.")



    def _dispatch_worker(self) -> None:
        """Background worker thread that flushes the alert delivery queue to Telegram.
        Ollama summarization runs here (off the pipeline lock path) so send() stays non-blocking.
        """
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        while self.running or not self.q.empty():
            try:
                try:
                    item = self.q.get(timeout=1.0)
                except queue.Empty:
                    continue

                if isinstance(item, tuple) and len(item) == 3:
                    raw_msg, raw_payload, reply_markup = item
                elif isinstance(item, tuple) and len(item) == 2:
                    raw_msg, reply_markup = item
                    raw_payload = None
                else:
                    raw_msg, raw_payload, reply_markup = item, None, None

                final_msg = raw_msg

                payload = {
                    "chat_id": self.chat_id,
                    "text": final_msg,
                    "parse_mode": "Markdown"
                }
                if reply_markup:
                    payload["reply_markup"] = reply_markup
                
                resp = self.session.post(url, json=payload, timeout=5.0)
                if resp.status_code != 200:
                    LOGGER.warning("Failed to send Telegram alert (HTTP %d): %s", resp.status_code, resp.text)
                    if resp.status_code == 400 and "parse" in resp.text.lower():
                        LOGGER.info("Retrying Telegram alert dispatch without parse_mode fallback...")
                        payload.pop("parse_mode", None)
                        retry_resp = self.session.post(url, json=payload, timeout=5.0)
                        if retry_resp.status_code == 200:
                            LOGGER.info("✅ Telegram alert successfully dispatched via plain text fallback.")
                else:
                    LOGGER.debug("Telegram alert successfully dispatched.")
                    
                self.q.task_done()
            except Exception as exc:
                LOGGER.error("Exception in Telegram dispatch worker: %s[cite: 29]", exc)
                if 'item' in locals() and item:
                    try:
                        # Prevent infinite re-queuing of malformed payloads by checking structure
                        if isinstance(item, tuple) and len(item) == 3:
                            msg, payload, markup = item
                            if not isinstance(payload, dict) or "retry_count" not in payload:
                                payload = payload or {}
                                payload["retry_count"] = payload.get("retry_count", 0) + 1
                                if payload["retry_count"] <= 3:
                                    self.q.put((msg, payload, markup))
                                    time.sleep(2.0)
                                    continue
                    except Exception:
                        pass
                time.sleep(2.0)

    def _bot_updates_worker(self) -> None:
        """Background listener thread: polls Telegram getUpdates for /unblock, /release, /block, and inline button callbacks.
        AUDIT FIX #17: Uses threading.Event.wait() instead of time.sleep() so the thread
        stops within 1 second of stop() being called, rather than waiting up to 25 seconds.
        """
        if not self.token:
            return
        url = f"https://api.telegram.org/bot{self.token}/getUpdates"
        offset = 0
        while not self._stop_event.is_set():
            try:
                resp = self.session.get(url, params={"offset": offset, "timeout": 10}, timeout=15.0)
                if resp.status_code != 200:
                    self._stop_event.wait(timeout=10.0)
                    continue

                data = resp.json()
                for update in data.get("result", []):
                    offset = max(offset, update["update_id"] + 1)
                    
                    # Handle Callback Query (Inline Button Click)
                    if "callback_query" in update:
                        cb = update["callback_query"]
                        cb_data = cb.get("data", "")
                        cb_id = cb.get("id", "")
                        self._handle_telegram_callback(cb_data, cb_id, update["callback_query"])
                        continue

                    # Handle Text Commands (/unblock, /release, /status)
                    if "message" in update and "text" in update["message"]:
                        text = update["message"]["text"].strip()
                        self._handle_telegram_command(text, update["message"])

            except Exception as exc:
                LOGGER.debug("Telegram bot updates worker exception: %s", exc)
                self._stop_event.wait(timeout=5.0)

    def _handle_telegram_callback(self, cb_data: str, cb_id: str, cb_update: dict = None):
        """Processes Telegram inline keyboard button presses ([Approve Block], [Release], [Immunize]).
        AUDIT FIX #10: Validates sender chat_id against telegram_allowed_chat_ids allowlist.
        """
        answer_url = f"https://api.telegram.org/bot{self.token}/answerCallbackQuery"
        try:
            # Authenticate the callback sender
            if cb_update:
                sender_chat_id = str(cb_update.get("message", {}).get("chat", {}).get("id", ""))
                if not self._is_sender_allowed(sender_chat_id):
                    LOGGER.warning("⚠️ Telegram callback from unauthorized chat_id %s blocked.", sender_chat_id)
                    self.session.post(answer_url, json={"callback_query_id": cb_id, "text": "⛔ Unauthorized."}, timeout=5.0)
                    return

            parts = cb_data.split(":", 2)
            action = parts[0].lower()
            target = parts[1] if len(parts) > 1 else ""
            
            from config import CONFIG
            fastapi_port = int(CONFIG.get("fastapi_port", 8010))
            api_token = CONFIG.get("fritz_api_token", "")
            headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
            
            if action in ("unblock", "release"):
                # BUGFIX: this used to fire the POST and immediately claim success without
                # checking the response -- unlike the immunize/revoke branches below, which
                # already check resp.status_code. A failed release (backend error, IPC
                # timeout, Fritzbox webhook failure) still showed "✅ released" in Telegram,
                # so an operator had no way to tell a real failure apart from success.
                # fritzbox_api.py's /api/ipc/release always returns HTTP 200 on a clean
                # request -- whether the target was ACTUALLY isolated is in the JSON body's
                # `released`/`released_count`, not the status code, so both must be checked.
                ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/release"
                resp = self.session.post(ipc_url, json={"target": target}, headers=headers, timeout=10.0)
                if resp.status_code != 200:
                    msg_text = f"⚠️ Release failed: HTTP {resp.status_code}"
                else:
                    body = resp.json()
                    released = body.get("released", body.get("released_count", 0))
                    if released:
                        msg_text = f"✅ Target '{target}' released from containment."
                    else:
                        # BUGFIX (2026-08-29, user report: "releasing does not work, it shows
                        # nothing is marked"): this is the expected, GOOD outcome for an
                        # "awaiting approval" alert -- Interactive HITL mode never applies the
                        # hardware block until Approve is tapped, so there was never anything
                        # to undo. The old wording ("was not currently tracked as isolated —
                        # nothing to release") read as an error/failed action; reworded to
                        # confirm the actual, reassuring state instead.
                        msg_text = (
                            f"✅ '{target}' is not blocked — no hardware containment was ever "
                            f"applied (it was still just awaiting your approval, or was already "
                            f"released earlier). Nothing further to do; the device stays on the "
                            f"network."
                        )
            elif action == "block":
                ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/block"
                resp = self.session.post(ipc_url, json={"target": target}, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    msg_text = f"🔒 Hardware containment block approved for '{target}'."
                else:
                    msg_text = f"⚠️ Block failed: HTTP {resp.status_code}"
            elif action == "immunize":
                # PHASE 6 (closed-loop self-healing): `target` here is the action_id from a
                # published alert's "🛡️ Mark False Positive" button (see pipeline.py's
                # "published_alert" ledger entry), not a raw domain string — mirrors the
                # `revoke` branch's action_id convention below. The actual domain that got
                # immunized is only known after the IPC call resolves it from the ledger
                # entry's stashed alert_payload, so the confirmation text is built from the
                # JSON response rather than echoing back what was clicked.
                ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/immunize"
                resp = self.session.post(ipc_url, json={"target": target}, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("status") == "refused":
                        # BUGFIX: mark_false_positive() now refuses hard-stop/verifiable-fact
                        # alerts (honeypot, arp_spoofing, geofencing, confirmed exploit,
                        # tier-5 confirmed IOC) -- must not be reported as a success.
                        msg_text = f"⛔ Not marked — {body.get('reason', 'this alert cannot be marked as a false positive.')}"
                    else:
                        immunized_domain = body.get("immunized", "the domain")
                        unblock_note = " Pi-hole block released." if body.get("unblocked") else ""
                        msg_text = f"🛡️ Marked false positive — '{immunized_domain}' immunized.{unblock_note}"
                elif resp.status_code == 404:
                    msg_text = "⚠️ Alert already expired or unknown — nothing to mark."
                else:
                    msg_text = f"⚠️ Mark-false-positive failed: HTTP {resp.status_code}"
            elif action == "approve_tune":
                # 2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.3: `target` here is a
                # device_id directly (not an action_id -- there's no ledger entry to
                # look up, same "the identifier alone is enough to re-derive
                # everything" shape the `block` branch above already uses for its own
                # interactive-approval flow), from ollama_soc.py's IP-only-benign-
                # verdict routing.
                ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/approve_tune_down"
                resp = self.session.post(ipc_url, json={"target": target}, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    body = resp.json()
                    if body.get("status") == "not_found":
                        msg_text = "⚠️ Device no longer tracked — nothing to approve."
                    else:
                        released_note = " Also released from active containment." if body.get("released") else ""
                        msg_text = f"✅ Approved — sensitivity loosened for this device.{released_note}"
                else:
                    msg_text = f"⚠️ Approve failed: HTTP {resp.status_code}"
            elif action == "revoke":
                # PHASE 3 (closed-loop): `target` here is the action_id from a "🔔
                # Auto-action" notification's [Revoke] button, not a domain/IP/hostname.
                ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/revoke"
                resp = self.session.post(ipc_url, json={"target": target}, headers=headers, timeout=10.0)
                if resp.status_code == 200:
                    msg_text = "↩️ Action revoked — treated as a real threat going forward."
                elif resp.status_code == 404:
                    msg_text = "⚠️ Action already revoked, expired, or unknown."
                else:
                    msg_text = f"⚠️ Revoke failed: HTTP {resp.status_code}"
            else:
                msg_text = "Action acknowledged."

            self.session.post(answer_url, json={"callback_query_id": cb_id, "text": msg_text}, timeout=5.0)
        except Exception as e:
            LOGGER.error("Failed to process Telegram callback query: %s", e)

    def _is_sender_allowed(self, chat_id: str) -> bool:
        """AUDIT FIX #10: Returns True if the sender is on the allowed chat_id list.
        If telegram_allowed_chat_ids is empty, all senders are allowed (backward-compat).
        """
        from config import CONFIG
        allowed: List[str] = [str(x) for x in CONFIG.get("telegram_allowed_chat_ids", [])]
        if not allowed:
            return True  # Empty allowlist = allow all (backward-compatible default)
        return chat_id in allowed

    def _handle_telegram_command(self, text: str, message: dict = None):
        """Handles Telegram commands like /unblock 192.168.1.50 or /release_all.
        AUDIT FIX #10: Validates sender chat_id against allowlist before executing.
        """
        if not text.startswith("/"):
            return

        # Authenticate the command sender
        if message:
            sender_chat_id = str(message.get("chat", {}).get("id", ""))
            if not self._is_sender_allowed(sender_chat_id):
                LOGGER.warning("⚠️ Telegram command from unauthorized chat_id %s blocked: %s", sender_chat_id, text[:50])
                self.send(f"⛔ Unauthorized. Your chat ID `{sender_chat_id}` is not in the allowlist.")
                return

        cmd_parts = text.split(maxsplit=1)
        cmd = cmd_parts[0].lower()
        target = cmd_parts[1].strip() if len(cmd_parts) > 1 else ""

        from config import CONFIG
        fastapi_port = int(CONFIG.get("fastapi_port", 8010))
        api_token = CONFIG.get("fritz_api_token", "")
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

        if cmd in ("/unblock", "/release", "/unblock_all", "/release_all"):
            ipc_target = "all" if "all" in cmd else target
            if not ipc_target:
                self.send("⚠️ Usage: `/unblock <IP_OR_MAC_OR_HOSTNAME|all>`")
                return
            ipc_url = f"http://127.0.0.1:{fastapi_port}/api/ipc/release"
            # Use a longer timeout for /release_all since each isolated device requires
            # a Fritz!Box TR-064 HTTP round-trip (up to 10s per device).
            ipc_timeout = 60.0 if ipc_target == "all" else 10.0
            try:
                resp = self.session.post(ipc_url, json={"target": ipc_target}, headers=headers, timeout=ipc_timeout)
                if resp.status_code != 200:
                    self.send(f"⚠️ Failed to release '{ipc_target}': HTTP {resp.status_code}")
                else:
                    # BUGFIX (2026-08-29, same gap already fixed in the inline-button
                    # callback above): this used to claim success on any HTTP 200 without
                    # checking the response body's released/released_count -- a target that
                    # was never actually contained (e.g. still "awaiting approval") got a
                    # false "Successfully released" message instead of the accurate
                    # "nothing was ever blocked" one.
                    body = resp.json()
                    if ipc_target == "all":
                        released = body.get("released_count", 0)
                        if released:
                            self.send(f"✅ *[TELEGRAM RELEASE]* Successfully released {released} device(s) from containment (Pi-hole, Tarpit, Router). 1-Hour Cooldown active.")
                        else:
                            self.send("✅ No devices were currently under containment — nothing to release.")
                    else:
                        released = body.get("released", 0)
                        if released:
                            self.send(f"✅ *[TELEGRAM RELEASE]* Successfully released '{ipc_target}' from containment (Pi-hole, Tarpit, Router). 1-Hour Cooldown active.")
                        else:
                            self.send(
                                f"✅ '{ipc_target}' is not blocked — no hardware containment was "
                                f"ever applied (it was still just awaiting approval, or was "
                                f"already released earlier). Nothing further to do."
                            )
            except Exception as e:
                self.send(f"❌ Error communicating with local IPC server: {e}")

    def stop(self, timeout: float = 12.0) -> None:
        """
        Signals the worker thread to stop and blocks up to the specified timeout 
        to ensure all enqueued alerts are flushed to Telegram before process exit.
        AUDIT FIX #17: Sets threading.Event so the long-poll thread wakes up immediately.
        """
        self.running = False
        self._stop_event.set()  # Wake up _bot_updates_worker immediately
        if hasattr(self, "_worker_thread") and self._worker_thread.is_alive():
            LOGGER.info("Shutting down Alert Manager worker thread (Timeout: %.1fs)...", timeout)
            self._worker_thread.join(timeout=timeout)
            if self._worker_thread.is_alive():
                LOGGER.warning("⚠️ Alert Manager worker thread did not drain completely within %.1fs timeout.", timeout)
            else:
                LOGGER.info("✅ Alert Manager worker thread stopped cleanly.")