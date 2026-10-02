# Console Data API

The read-only endpoints behind the expert console's Devices, Threat Hunt, Evidence Graph and Alerts views. Settings
are written through the separate [Configuration API](CONFIG_API.md). Authentication is the same: requests from the
host are trusted, and everything else needs the shared password or the engine API token.

| Endpoint | Purpose |
|---|---|
| `GET /api/devices`, `GET /api/devices/{id}` | Device identity and latest verdict |
| `GET /api/devices/{id}/top_domains` | Reports that per-device all-time domain totals are not available (see below) |
| `GET /api/hunt/devices_touching` | Every device that ever contacted a destination |
| `GET /api/hunt/decision_timeline/{id}` | The full evidence timeline behind one decision |
| `GET /api/hunt/device_history/{id}` | One device's decisions over time |
| `POST /api/hunt/replay/{id}` | Re-runs a past decision's real evidence through the current decision code and shows whether the verdict would change |
| `GET /api/graph` | The evidence-graph canvas: recent decisions and everything connected to them. `limit` (1–200), optional `device_id` |
| `GET /api/graph/alerts` | Fired, suppressed and logged-only alerts. `limit`, `offset`, optional `status` and `device_id` |
| `GET /api/graph/alerts/search` | Semantic search over alert explanations. `q` (required), optional `device_id`, `since`, `until`, `limit` (1–100) |

## Where each value comes from

- **Verdict, risk and confidence** come from the device's most recent decision in the evidence graph. The live
  working state does not store a "current verdict".
- **Identity** (hostname, MAC, known addresses, TLS and DHCP fingerprints) comes from the engine's live device state.
  For devices that have left the live working set, it comes from the graph.
- **Device type** is read from the device's graph metadata (`metadata_json["device_type"]`), where the live engine
  writes it. The devices table column is a fallback.

## Alerts are graph nodes

Every cycle that reaches SUSPICIOUS or above writes an `alert_event` (status FIRED, SUPPRESSED_AUTONOMOUS or
LOGGED_ONLY) linked to its decision. `incidents` and `operator_actions` sit alongside it. `GET /api/graph` draws each
alert as a node with a companion **explanation** node, so the canvas reads as one story:
device → evidence → decision → alert → explanation.

**Plain-language explanation.** One short paragraph per alert covers:

- the device;
- what was noticed;
- the destination, by name, owner and country (never a raw address);
- the winning hypothesis;
- the counter-argument (the best benign hypothesis and its score);
- what happened as a result.

The same text leads the Telegram message, fills the graph's explanation node, and appears in both alert endpoints.

**Destinations are always named.** A destination is resolved to a local device's hostname, a known domain, or an
external address's reverse-DNS name, network owner and country. The `kind` field (`local_device`, `domain`,
`external_ip`) lets the console style it.

## Bounded semantic search

Each alert's explanation is embedded once, when the alert is written, with the same small local embedding model the
false-positive engine uses. A search must be scoped to a time window, optionally narrowed to one device, and may
compare at most 5,000 candidates. A wider search gets a clear 422 answer, not a silently truncated result. The API
process embeds the query with its own lazily loaded copy of the model, read from the same local model cache.

## Built to stay fast on a busy network

- **One connection per request.** Each request opens its own SQLite connection to the graph and closes it afterwards.
  WAL mode lets any number of readers run alongside the engine's single writer. Schema checks run once per process,
  not per request.
- **Evidence per decision is capped.** The canvas shows the 15 most recent supporting items of each decision, with
  the total (`evidence_total`, `evidence_truncated`), so a decision backed by tens of thousands of items still loads
  quickly and says how much is hidden. Both the limit and the count run in SQL, on an index.
- **Evidence lookups are indexed.** Decision timelines and replays fetch a decision's evidence by id, never by
  scanning everything the device has produced.
- **Device state is cached.** It is cached with invalidation on file change, for these read-only endpoints only.
  Containment endpoints always use fresh state.
- **Overview data is cached.** Overview and dashboard data are served stale-while-revalidate and warmed at start-up.

## Device filter

`device_id` on `/api/graph` scopes the canvas to one device's own recent decisions (indexed by device and time), so
an older alert on a busy network can always be found. Every alert row in the console has a "View in graph" button
that opens it there.

## Not available: all-time top domains per device

The graph stores evidence, not every DNS query, so it cannot count a device's routine traffic. The daily top
destinations report uses Pi-hole's own 24-hour query log. A per-device, all-time total would need a new persistent
aggregation, so the endpoint reports "not available" rather than a number computed from the wrong source.

## Live log level

`log_level` applies immediately whenever it changes, whether in `config.yaml` or through the Configuration API,
including when an override is reverted.
