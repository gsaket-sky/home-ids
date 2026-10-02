# Configuration API

A read/write HTTP API over the engine's live-tunable settings. The expert console and the web interface's settings
pages both use it, so a change made from any device on the LAN reaches the running engine at once.

| Part | File |
|---|---|
| Metadata for every editable key (section, type, description, default, whether a restart is needed) | `src/middleware/config_schema.py` |
| Endpoints | `src/middleware/routers/config_api.py` |
| Override loading and reverting | `src/config.py` (`LiveConfig`) |
| Tests | `tests/test_config_api.py` |

## Endpoints

| Method | Path | Does |
|---|---|---|
| `GET` | `/api/config` | Every editable key with its current value, its `config.yaml` baseline, who changed it and when, and whether it needs a restart |
| `PATCH` | `/api/config/{key}` | Sets a live value (validated against the schema) |
| `DELETE` | `/api/config/{key}` | Reverts a key to its `config.yaml` value |
| `PATCH` | `/api/config/device_type_overrides/{pattern}` | Sets a device-type override (hostname pattern → type) |
| `DELETE` | `/api/config/device_type_overrides/{pattern}` | Removes one |

## Overrides, not edits

`config.yaml` is written by people only, and the running system never edits it. Every live change goes to
`state/config_overrides.json`:

```json
{"<key>": {"value": ..., "baseline": ..., "set_at": ..., "set_by": "console_ui", "reason": ...}}
```

`baseline` is the `config.yaml` value captured the first time the key was overridden. The API reloads overrides
straight after writing, so a change applies within the same request. The health manager uses the same file for its
temporary resource-saving switches, which it reverts as pressure falls. Thresholds learned by the autotuner are
versioned separately in the graph's `threshold_history` (see the Engineering Manual, section 10), so automatic
learning and human settings never overwrite each other.

## Device-type overrides apply everywhere at once

Saving or removing a device-type override touches a sync signal file. On its next loop (about 2 seconds) the engine
re-applies every override to every known device, so idle devices change type immediately as well.

## Restart-only keys are read-only

Keys that are read once at start-up are shown but cannot be edited here (the endpoints answer 400). These are:

- static keys, including every secret;
- `lateral_movement_ports`, `local_confirmed_intel_ttl_seconds`, `hardware_profile`, `service_ports` and
  `metrics_port`.

Scheduled-job settings are nested (`scheduled_jobs.scheduler.<job>.enabled`). They are shown for reference and are
edited in `config.yaml`, where the scheduler reads them.

## Secrets are never exposed

API keys, the Telegram token and chat ID, router and Pi-hole credentials, and the shared password come from the
secrets file or the integrations store. They are absent from the schema, so they are never returned or editable here.
The web interface's Integrations page manages them separately and never shows a saved secret again.

## Authentication

Requests from the host itself are trusted, unless they arrive through a reverse proxy. Every other request needs the
shared password (the same one as the web interface and Pi-hole) or the engine's API token, as a bearer token. The
console page asks once and keeps the credential only in that browser.

## Known limit

Overrides are written read-modify-write with an in-process lock. Two processes writing at the same instant (a
console edit and a health-manager switch) could lose one change. The window is small and the next write corrects it.
A cross-process file lock would close it completely.

## Related

The console's read-only data endpoints (devices, evidence graph, alerts, threat hunting) are documented in
[CONSOLE_DATA_API.md](CONSOLE_DATA_API.md).
