"""
metrics_server.py -- the engine's Prometheus endpoint (:9105) with a short render cache and a cheap health path.

Open item A2 (2026-10-01): rendering the engine's ~3,300 series took 9-10 s wall on .94 under load, and the endpoint
was rendered three times a minute -- twice for Prometheus and once for the Docker healthcheck, which only needed to
know the port answers. prometheus_client's own server renders on every request. This one:

  /healthz   answers "ok" without rendering anything (what the compose healthcheck now calls)
  /metrics   (any other path) renders at most once per CACHE_TTL_SECONDS per format; concurrent scrapes during a
             render wait for that one render instead of starting their own
  ?name[]=   filtered scrapes bypass the cache and use prometheus_client's own code path unchanged

Prometheus attaches its own scrape timestamp, so a body up to CACHE_TTL_SECONDS old is indistinguishable from one
rendered on demand at the 30 s scrape interval.
"""
import threading
import time
from typing import Callable, Dict, Optional, Tuple
from wsgiref.simple_server import make_server

from prometheus_client import REGISTRY
from prometheus_client.exposition import ThreadingWSGIServer, _SilentHandler, _bake_output, choose_encoder

CACHE_TTL_SECONDS = 20.0


class CachedMetricsApp:
    def __init__(self, registry=REGISTRY, ttl_seconds: float = CACHE_TTL_SECONDS,
                 clock: Callable[[], float] = time.monotonic):
        self.registry = registry
        self.ttl = float(ttl_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[float, bytes]] = {}   # content type -> (rendered at, body)
        self.renders = 0

    def body_for(self, accept_header: str) -> Tuple[str, bytes]:
        encoder, content_type = choose_encoder(accept_header or "")
        hit = self._cache.get(content_type)
        if hit and self._clock() - hit[0] < self.ttl:
            return content_type, hit[1]
        with self._lock:
            hit = self._cache.get(content_type)          # another request may have rendered while we waited
            if hit and self._clock() - hit[0] < self.ttl:
                return content_type, hit[1]
            body = encoder(self.registry)
            self.renders += 1
            self._cache[content_type] = (self._clock(), body)
            return content_type, body

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        if path == "/healthz":
            start_response("200 OK", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"ok\n"]
        if path == "/favicon.ico":
            start_response("200 OK", [])
            return [b""]
        query = environ.get("QUERY_STRING", "")
        if query:
            from urllib.parse import parse_qs
            status, headers, output = _bake_output(self.registry, environ.get("HTTP_ACCEPT", ""),
                                                    environ.get("HTTP_ACCEPT_ENCODING", ""), parse_qs(query), False)
            start_response(status, headers)
            return [output]
        content_type, body = self.body_for(environ.get("HTTP_ACCEPT", ""))
        start_response("200 OK", [("Content-Type", content_type)])
        return [body]


def start_cached_metrics_server(port: int, addr: str = "0.0.0.0", registry=REGISTRY,
                                ttl_seconds: float = CACHE_TTL_SECONDS) -> Tuple[object, threading.Thread]:
    """Drop-in for prometheus_client.start_http_server(port): same bind address default, daemon thread."""
    app = CachedMetricsApp(registry, ttl_seconds)
    httpd = make_server(addr, port, app, ThreadingWSGIServer, handler_class=_SilentHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="metrics-http")
    thread.start()
    return httpd, thread
