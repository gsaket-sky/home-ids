# Deployment notes

This repository is a reference implementation published for reading, and is **not licensed for running** (see
[LICENSE](../LICENSE)). These notes only describe what the system depends on, so the design documents make sense.

**Components:** a Zeek sensor (JSON logs, with `policy/protocols/conn/mac-logging.zeek` loaded — see the deployment
dependency in [ENGINEERING_MANUAL.md](ENGINEERING_MANUAL.md#2-sensing), section 2); a Pi-hole instance (DNS telemetry and blocking);
a Python 3 environment with the packages in `requirements.txt`; optionally a router integration for hardware-level
isolation and capture, a local language-model server, and Suricata for signature scanning of captured traffic.

**Configuration** is a hand-written `config.yaml` (see `config.yaml.example`), a secrets file, and the live override
layer described in [CONFIG_API.md](CONFIG_API.md). The units under `systemd/` show how the engine and its scheduler
are meant to be supervised.

There is no installer, no packaged image, and no support.
