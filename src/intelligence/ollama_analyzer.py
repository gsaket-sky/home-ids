import threading
import queue
import requests
import json
import time
import logging
from typing import Dict, Any

LOGGER = logging.getLogger(__name__)

class OllamaAnalyzer:
    """Asynchronous background worker for interrogating Ollama and logging to Grafana (Loki)."""
    
    def __init__(self, ollama_url: str, ollama_model: str, ollama_api_key: str, alert_file_logger, metrics):
        self.ollama_url = ollama_url.strip().rstrip("/")
        self.ollama_model = ollama_model.strip()
        self.ollama_api_key = ollama_api_key.strip()
        self.alert_file_logger = alert_file_logger
        self.metrics = metrics
        
        self.q = queue.Queue(maxsize=1000)
        self.running = True
        self._stop_event = threading.Event()
        self.thread = threading.Thread(target=self._worker, daemon=True, name="OllamaAnalyzerThread")
        self.thread.start()
        
    def analyze(self, alert_payload: Dict[str, Any]):
        """Queue an alert for background AI interrogation. Non-blocking."""
        if not self.ollama_url:
            return
        try:
            self.q.put_nowait(alert_payload)
        except queue.Full:
            LOGGER.error("OllamaAnalyzer queue is full. Dropping transparency request.")
            
    def _worker(self):
        while self.running and not self._stop_event.is_set():
            try:
                payload = self.q.get(timeout=2.0)
            except queue.Empty:
                continue
                
            self._process_payload(payload)
            self.q.task_done()
            
    def _process_payload(self, payload: Dict[str, Any]):
        """Queries local Ollama instance and logs the reasoning for Grafana transparency."""
        try:
            system_prompt = (
                "You are an autonomous Tier 2 SOC Analyst for a Home Intrusion Detection System. "
                "Analyze the provided JSON alert payload. "
                "Provide a detailed executive summary explaining the potential risk to the user and your exact reasoning. "
                "Do not include markdown or formatting, just the plain text sentence."
            )
            prompt_text = f"Alert Payload:\n{json.dumps(payload, indent=2)}"
            
            headers = {}
            if self.ollama_api_key:
                headers["Authorization"] = f"Bearer {self.ollama_api_key}"
            
            resp = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.ollama_model, 
                    "system": system_prompt,
                    "prompt": prompt_text, 
                    "stream": False
                },
                headers=headers,
                timeout=300.0
            )
            
            if resp.status_code == 200:
                response_text = resp.json().get("response", "").strip()
                
                device_ip = payload.get("device", {}).get("ip", "unknown")
                transparency_log = {
                    "type": "ollama_transparency",
                    "component": "realtime_analyzer",
                    "device": {"ip": device_ip},
                    "timestamp": time.time(),
                    "model": self.ollama_model,
                    "prompt": prompt_text,
                    "response": response_text
                }
                self.alert_file_logger.write(transparency_log)
                LOGGER.debug("Ollama transparency log injected into alerts.json")
            else:
                LOGGER.warning(f"Ollama API returned HTTP {resp.status_code}: {resp.text}")
                
        except Exception as exc:
            LOGGER.warning("Ollama transparency generation failed (Timeout or connection error): %s", exc)

    def stop(self, timeout=5.0):
        self.running = False
        self._stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)
