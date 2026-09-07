# Config API — write-back for the console UI

## What this is

A read/write HTTP API over config.yaml's LIVE-tunable values, plus the console UI
(`web/console.html`) it backs, so a config edit made from another device on the LAN
actually reaches the running `home_ids` service instead of only existing in a browser
tab. Added because the console was, until this change, a standalone mockup with no way
to persist anything.

Files:
- `src/middleware/config_schema.py` — the hand-authored metadata (section, type,
  description, suggested default, restart-required-or-not) for every editable key.
- `src/middleware/routers/config_api.py` — the FastAPI endpoints.
- `src/config.py` — one small addition, `LiveConfig.revert_override()`.
- `web/console.html` — served at `GET /console` by `src/middleware/main_api.py`.
- `tests/test_config_api.py` — direct-call tests (see that file's own docstring for why
  no TestClient/httpx).

## Why it never touches config.yaml

`requirements.txt`'s PHASE 13 cleanup note documents a deliberate, existing invariant:
*"Nothing in this codebase writes to config.yaml at runtime anymore"* — ruamel.yaml was
removed once the one thing that used to write to config.yaml (an old, wrongly-targeted
`save_config_key()`) was itself removed. Reintroducing a YAML writer for this feature
would reverse that decision for a comparatively low-value gain, since `src/config.py`
already has a live-override mechanism built for a different purpose (the weekly
autotune job self-calibrating `fp_combined_suppress_threshold`):

- `state/config_overrides.json` — `{"<key>": {"value", "baseline", "set_at", "set_by",
  "reason"}}`, read by `LiveConfig._load_overrides()` (`src/config.py`), written today
  by `src/scripts/train_fp_classifier.py`'s `_write_config_override()`.
- This API writes into the **same file, same format** (`set_by: "console_ui"` instead
  of the autotune job's own value), and calls `CONFIG._load_overrides()` itself right
  after writing so a PATCH takes effect within that request instead of waiting on the
  watcher's 5s poll.
- `config.yaml` stays the single, hand-authored, git-diffable baseline. `baseline` in
  each override entry is exactly that config.yaml-derived value, captured once at the
  key's first-ever override and never overwritten by a later edit to the same key.

## Restart-required keys are read-only here

`config.py`'s `_STATIC_KEYS` is the set it will actively reject a live-reload mutation
for. But two more keys are *effectively* restart-only despite not being in that set,
because their own consumer reads them exactly once at object-construction time rather
than on every use:

| Key | Read once at | File |
|---|---|---|
| `lateral_movement_ports` | `ZeekFeatureExtractor.__init__` | `src/core/pipeline.py:477` |
| `local_confirmed_intel_ttl_seconds` | `AutonomousFPEngine.__init__` (`LocalConfirmedIntel(...)`) | `src/intelligence/fp_engine.py:262` |

These two are `config_schema.RUNTIME_RESTART_KEYS`. `config_schema.is_restart_required(key)`
is `key in _STATIC_KEYS or key in RUNTIME_RESTART_KEYS` — the API's PATCH/DELETE
endpoints refuse both sets with a 400; GET still returns their current value so the UI
can show them, just without an edit control.

A third pair, `reactive_capture_zeek_memory_limit_mb` / `reactive_capture_suricata_memory_limit_mb`,
was checked the same way against `src/extractors/fritzbox_capture.py:561-562` (both read
fresh via `config.get()` on every capture burst — genuinely LIVE) specifically because an
earlier draft of this plan asserted, incorrectly, that config.yaml's own `[RESTART]`
comment on them was stale. On actually re-reading config.yaml and config.yaml.example
during implementation, both already say `[LIVE]` for these two keys — that mismatch was
a memory error made while drafting the plan, not a real bug in either file. No edit was
made to config.yaml or config.yaml.example; `config_schema.py` lists both keys as
editable, which was already correct.

## Secrets are never exposed by this API

`telegram_token`, `telegram_chat_id`, `otx_api_key`, `abuseipdb_api_key`,
`virustotal_api_key`, `pihole_api_password`, `fritz_password`, `fritz_api_token` come
from `.env`, not config.yaml, and are deliberately absent from `CONFIG_SCHEMA` — never
returned by `GET /api/config`, never editable, regardless of who's authenticated. They
are also all in `_STATIC_KEYS`, so a PATCH would be refused even if a schema row existed
for one — the exclusion from the schema is the belt to that suspenders (not exposed in
a GET response at all, not just blocked on write).

## `device_type_overrides` and `scheduler.*` are special-cased

`device_type_overrides` (hostname-substring → type) is a dict, not a scalar/list/enum,
so it has its own endpoints (`PATCH`/`DELETE /api/config/device_type_overrides/{pattern}`)
that read-modify-write the whole merged dict as one override entry, rather than the
generic per-key endpoints. The console's Device Detail "assign type" control and the
Config tab's `network_and_devices` panel both call these same two endpoints.

`scheduler.ollama_soc.enabled` and its five siblings are genuinely nested
(`config.yaml`'s `scheduled_jobs.scheduler` is itself a dict of dicts, so
`CONFIG.get("scheduler")` returns the whole nested structure — there's no flat
`"scheduler.ollama_soc.enabled"` key in `LiveConfig._config` to read or override
directly). `GET /api/config` resolves these dotted paths for **display only**;
`PATCH`/`DELETE` explicitly reject any key containing a `.` with a 400. Building the
generic nested-dict merge-write these would need (the same shape as
`device_type_overrides`, but for an open-ended dotted path) was scoped out of this pass
rather than shipped half-tested — a reasonable follow-up if these six fields turn out
to be worth editing from the UI.

## Known, accepted risk: cross-process write race

`state/config_overrides.json` can now be written by **two** independent processes: this
API (human-driven, occasional) and `train_fp_classifier.py`'s weekly cron (autonomous).
Neither this API's writer nor the existing autotune writer takes a cross-process file
lock — both do read-modify-write with only an in-process lock (this API's own
`threading.Lock`; the cron job has no concurrent writers within itself). A write from
both at nearly the same moment could lose one side's change. This is a real but
low-probability race (a weekly cron vs. an occasional manual edit), consistent with how
every other writer of this file already behaves — not solved here. If this ever
matters in practice, the fix is a real cross-process file lock (e.g. `msvcrt`/`fcntl`
depending on platform) around both writers, not just this one.

## Auth and reaching the console from another device

`GET /console` (the page itself) is unauthenticated — static markup, no secrets
embedded. Every API call the page makes goes through `middleware.auth.verify_token`,
the same bearer-token check `/isolate`, `/hosts`, and the other existing endpoints
already use: loopback requests are exempted, everything else needs
`Authorization: Bearer <fritz_api_token>` (the same secret as `API_SECRET_TOKEN` in
`.env`). The console prompts for this once (on first 403) and remembers it in that
browser's `localStorage` — nothing is sent anywhere except back to this same server.

Reaching it from another device: `fastapi_bind_host: "0.0.0.0"` (already set in this
deployment's config.yaml) is what makes the FastAPI process listen beyond loopback in
the first place — this feature doesn't change that, it rides on it. Open
`http://<server-ip>:8010/console` from any device on the LAN.

## Scope

Only the **Config** tab is wired to this API. Devices / Threat Hunt / Evidence Graph
keep sample data (now visibly labeled "SAMPLE DATA" in the UI) — building real backends
for those means exposing `src/v13/ops/threat_hunt.py` and `decision_replay.py` over
HTTP and querying the actual device/evidence-graph state, which is a separate, larger
piece of work.
