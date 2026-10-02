"""One password for the whole appliance.

The console/web UI, the engine's API, Pi-hole (admin + the engine's own access) and Grafana all use the
SAME password, set in one place (the web UI's account page) and stored in one file:

    <state dir>/secrets/shared_password        (plaintext -- Pi-hole and Grafana are logged into with it, so a
                                                hash is not enough; the folder is private to the appliance)

Readers are cheap (the file is re-read only when it changes). The web UI writes it; the engine reads it.
`propagate()` pushes a new value to the apps that keep their own copy (Pi-hole, Grafana) using the OLD
password to log in -- best effort, each app independent, results reported per app.

Trade-off, accepted by the owner (2026-09-30): one password means anyone who learns it from one app gets
into all of them. Use a long random value.
"""
import logging
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("home_ids.shared_password")

MIN_LENGTH = 8
_LOCK = threading.Lock()
_CACHE: Dict[str, tuple] = {}     # path -> (mtime_ns, value)


def _default_state_dir() -> Path:
    from config import CONFIG
    return Path(CONFIG.get("state_path", "state/ids_state.json")).parent


def path(state_dir: Optional[str] = None) -> Path:
    base = Path(state_dir) if state_dir else _default_state_dir()
    return base / "secrets" / "shared_password"


def get(state_dir: Optional[str] = None) -> str:
    """The shared password, or "" when none has been set. Cached until the file changes."""
    p = path(state_dir)
    try:
        st = p.stat()
    except OSError:
        return ""
    key = str(p)
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] == st.st_mtime_ns:
            return hit[1]
    try:
        value = p.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError:
        return ""
    with _LOCK:
        _CACHE[key] = (st.st_mtime_ns, value)
    return value


def is_set(state_dir: Optional[str] = None) -> bool:
    return bool(get(state_dir))


def matches(candidate: str, state_dir: Optional[str] = None) -> bool:
    """Constant-time comparison against the shared password. False when none is set."""
    shared = get(state_dir)
    return bool(shared) and bool(candidate) and secrets.compare_digest(candidate.encode("utf-8"), shared.encode("utf-8"))


def set(new_password: str, state_dir: Optional[str] = None) -> None:  # noqa: A001 - module API
    if not new_password or len(new_password) < MIN_LENGTH:
        raise ValueError(f"password must be at least {MIN_LENGTH} characters")
    if "\n" in new_password or "\r" in new_password:
        raise ValueError("password must not contain line breaks")
    p = path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o660)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(new_password)
    try:
        os.chmod(tmp, 0o660)
    except OSError:
        pass
    os.replace(tmp, p)
    with _LOCK:
        _CACHE.pop(str(p), None)


# ---------------------------------------------------------------------------------- propagation

def _pihole_change(old: str, new: str, api_url: str, session: Any, timeout: float) -> str:
    base = (api_url or "").rstrip("/")
    if not base:
        return "skipped: pihole_api_url not configured"
    r = session.post(f"{base}/api/auth", json={"password": old}, timeout=timeout)
    s = (r.json() or {}).get("session", {}) if r.status_code == 200 else {}
    sid = s.get("sid")
    if not s.get("valid"):
        raise RuntimeError("login with the current password was refused")
    headers = {"sid": sid} if sid else {}      # no sid: Pi-hole has no password yet (open API)
    r = session.patch(f"{base}/api/config", json={"config": {"webserver": {"api": {"password": new}}}},
                      headers=headers, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"Pi-hole refused the change (HTTP {r.status_code})")
    return "changed"


def _grafana_change(old: str, new: str, grafana_url: str, user: str, session: Any, timeout: float) -> str:
    base = (grafana_url or "").rstrip("/")
    if not base:
        return "skipped: grafana_url not configured"
    try:
        r = session.put(f"{base}/api/user/password", json={"oldPassword": old, "newPassword": new, "confirmNew": new},
                        auth=(user, old), timeout=timeout)
    except Exception as exc:
        # Grafana is an optional add-on (compose profile "dashboards", off by default since 2026-10-01): nothing
        # listening is "not installed", not a refusal -- it must not roll back the password change for every app.
        if "Connection refused" in str(exc) or exc.__class__.__name__ in ("ConnectionError", "NewConnectionError"):
            return "skipped: Grafana not running (optional dashboards add-on)"
        raise
    if r.status_code == 200:
        return "changed"
    if r.status_code in (401, 403):
        raise RuntimeError("login with the current password was refused")
    raise RuntimeError(f"Grafana refused the change (HTTP {r.status_code})")


def bootstrap_passwords() -> Dict[str, str]:
    """What each app was first started with (docker/.env values, passed to the web UI container). Used once, when
    the password is set for the first time, so a fresh install ends up with ONE password everywhere."""
    out = {}
    for app, var in (("pihole", "PIHOLE_BOOTSTRAP_PASSWORD"), ("grafana", "GRAFANA_BOOTSTRAP_PASSWORD")):
        if os.environ.get(var):
            out[app] = os.environ[var]
    return out


def propagate(old_password: Any, new_password: str, config: Optional[Dict[str, Any]] = None,
              session: Optional[Any] = None, timeout: float = 10.0,
              only: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Push `new_password` to Pi-hole and Grafana, logging in with `old_password` -- one string for both, or a
    {"pihole": ..., "grafana": ...} dict when they differ (first-time setup). Never raises: returns
    [{"app", "ok", "detail"}]. The engine and the web UI read the shared file directly, so they need no push.
    `only` limits it to some apps (used to roll back the ones that already changed)."""
    import requests
    if config is None:
        from config import CONFIG
        config = CONFIG
    sess = session or requests
    results: List[Dict[str, Any]] = []

    def old_for(app: str) -> str:
        return old_password.get(app, "") if isinstance(old_password, dict) else old_password

    steps = (
        ("pihole", lambda: _pihole_change(old_for("pihole"), new_password, config.get("pihole_api_url", ""), sess, timeout)),
        ("grafana", lambda: _grafana_change(old_for("grafana"), new_password, config.get("grafana_url", "http://127.0.0.1:3000"),
                                            config.get("grafana_admin_user", "admin"), sess, timeout)),
    )
    for app, fn in steps:
        if only is not None and app not in only:
            continue
        try:
            results.append({"app": app, "ok": True, "detail": fn()})
        except Exception as exc:
            LOGGER.warning("Could not change the %s password: %s", app, exc)
            results.append({"app": app, "ok": False, "detail": str(exc)})
    return results
