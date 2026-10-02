"""A2 (2026-10-01): the engine's /metrics endpoint renders at most once per TTL per format; /healthz never renders."""
import socket
import sys
import threading
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from prometheus_client import CollectorRegistry, Gauge  # noqa: E402

from core.metrics_server import CachedMetricsApp, start_cached_metrics_server  # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _server(ttl=20.0):
    reg = CollectorRegistry()
    g = Gauge("t_cache_gauge", "x", ["device"], registry=reg)
    g.labels("d1").set(1)
    port = _free_port()
    httpd, _ = start_cached_metrics_server(port, addr="127.0.0.1", registry=reg, ttl_seconds=ttl)
    return httpd, port, g


def _get(port, path="/metrics", accept=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if accept:
        req.add_header("Accept", accept)
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.headers.get("Content-Type"), r.read().decode()


def test_repeated_scrapes_share_one_render():
    httpd, port, _ = _server()
    try:
        for _ in range(5):
            _, body = _get(port)
            assert 't_cache_gauge{device="d1"} 1.0' in body
        assert httpd.get_app().renders == 1
    finally:
        httpd.shutdown()


def test_openmetrics_and_text_are_cached_separately():
    httpd, port, _ = _server()
    try:
        ct_text, _ = _get(port)
        ct_om, body = _get(port, accept="application/openmetrics-text; version=1.0.0")
        assert "openmetrics" in ct_om and "openmetrics" not in ct_text
        assert body.rstrip().endswith("# EOF")
        assert httpd.get_app().renders == 2
    finally:
        httpd.shutdown()


def test_healthz_never_renders():
    httpd, port, _ = _server()
    try:
        for _ in range(3):
            assert _get(port, "/healthz")[1] == "ok\n"
        assert httpd.get_app().renders == 0
    finally:
        httpd.shutdown()


def test_cache_expires():
    now = [0.0]
    reg = CollectorRegistry()
    g = Gauge("t_exp", "x", registry=reg)
    app = CachedMetricsApp(reg, ttl_seconds=10.0, clock=lambda: now[0])
    g.set(1)
    assert b"t_exp 1.0" in app.body_for("")[1]
    g.set(2)
    now[0] = 5.0
    assert b"t_exp 1.0" in app.body_for("")[1]       # still cached
    now[0] = 11.0
    assert b"t_exp 2.0" in app.body_for("")[1]       # re-rendered
    assert app.renders == 2


def test_concurrent_scrapes_during_a_render_wait_for_it():
    reg = CollectorRegistry()
    started, release = threading.Event(), threading.Event()

    class Slow:
        def collect(self):
            started.set()
            release.wait(5)
            return []

    reg.register(Slow())
    app = CachedMetricsApp(reg, ttl_seconds=30.0)
    results = []
    threads = [threading.Thread(target=lambda: results.append(app.body_for(""))) for _ in range(4)]
    for t in threads:
        t.start()
    started.wait(5)
    release.set()
    for t in threads:
        t.join(5)
    assert len(results) == 4 and app.renders == 1


def test_filtered_scrape_bypasses_the_cache():
    httpd, port, _ = _server()
    try:
        _, body = _get(port, "/metrics?name[]=t_cache_gauge")
        assert "t_cache_gauge" in body
        assert httpd.get_app().renders == 0
    finally:
        httpd.shutdown()
