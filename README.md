# ce-monitor

The operator's security console for CE — a light HTTP service that collects abuse flags from the
hub's detector and renders them in an admin-only "police HQ" dashboard.

It is intentionally minimal: axum + tokio + serde, no libp2p, no wasmtime, no database server. The
flag log is a durable, bounded, append-only JSONL file. ce-monitor runs beside the relay and never
touches the `ce` node directly — the hub pushes flags to it over HTTP, and the operator reads them.

## What it does

1. **`POST /ingest`** — receives one `FlagEvent` from the hub's abuse detector. Gated by the header
   `x-ce-monitor-token` matching `CE_MONITOR_INGEST_TOKEN`. The event is appended durably (fsync) to
   `flags.jsonl` and the unseen counter is incremented.
2. **Admin console** — `GET /` (and `/admin`) serve a single-page dark "security console". The page
   holds the operator's device key in `localStorage`, fetches a challenge, signs it, and sends the
   device-signed headers on every data call. ce-monitor is a **relying party of ce-auth**: it forwards
   those headers to ce-auth's `POST /verify` and admits iff `{ok:true}`. The page renders the flag
   log as a structured, filterable table:
   - **WHO** — `node_id` (Ed25519 pubkey hex, or `ip:<addr>` for unsigned nodes) + source `ip`
   - **WHERE** — chosen node / endpoint / func (pulled from the sample)
   - **WHEN** — timestamp, newest first
   - **WHY** — heuristic tag + human reason + severity
   - Filter by heuristic / severity / node. A **red unseen-count dot** pulses while there are
     unacknowledged flags and clears on **mark seen**.
3. **`GET /admin/challenge`** — proxies ce-auth's `GET /challenge?aud=ce-monitor` verbatim so the
   console never needs ce-auth's address. 503 if ce-auth is unreachable.
4. **`GET /admin/flags?since=&heuristic=&severity=&node=`** — device-auth-gated JSON feed powering
   the UI. `since` is an exclusive sequence cursor for incremental polling.
5. **`GET /admin/unseen`** / **`POST /admin/seen`** — read / clear the unseen watermark.

ce-monitor holds **no device registry and no in-process crypto**. Device enrollment, claim, request,
approve and revoke all live in **ce-auth** (`auth.ce-net.com`). A device enrolled there == the
operator == trusted by ce-monitor.

## Admin auth (relying party of ce-auth)

Every admin request carries the device-signed headers `x-ce-device-id`, `x-ce-auth`, `x-ce-aud`,
`x-ce-nonce`, `x-ce-ts`. ce-monitor forwards them to ce-auth:

```
POST {CE_AUTH_URL}/verify  { aud: "ce-monitor", deviceId, sig, nonce, ts }  -> { ok, role, deviceId }
```

- `{ok:true}` → admitted (200).
- `{ok:false}` or missing headers → 401.
- ce-auth unreachable → **503, fail-closed** (an auth outage never admits).

If this device isn't enrolled, the console shows a clean "manage your devices at auth.ce-net.com"
screen with the device id — there is no claim/approve UI in ce-monitor anymore.

## Environment

| Var | Default | Purpose |
|---|---|---|
| `CE_MONITOR_INGEST_TOKEN` | _(unset → /ingest rejects all)_ | Shared secret the hub sends as `x-ce-monitor-token`. |
| `CE_AUTH_URL` | `http://127.0.0.1:8972` | Base URL of ce-auth, the device-auth authority for the console. |
| `PORT` | `8971` | Listen port. |
| `CE_MONITOR_DATA_DIR` | `./ce-monitor-data` | Directory holding `flags.jsonl`. |

If `CE_MONITOR_INGEST_TOKEN` is unset, `/ingest` refuses every request (fail-closed). If ce-auth is
unreachable, every admin surface returns 503 (fail-closed).

## Durability & bounds

- Flags are appended one JSON object per line to `flags.jsonl`, fsync'd on each write, and replayed
  on boot — so the log **survives restart**.
- The active log rotates to `flags.jsonl.1` (one generation kept) once it passes 16 MiB, keeping
  disk usage bounded. The most recent flags stay resident in memory for the admin feed.

## FlagEvent contract

```json
{
  "ts": 1700000000,
  "node_id": "<ed25519 pubkey hex, or 'ip:'+ip if unsigned>",
  "ip": "203.0.113.7",
  "heuristic": "H2",
  "reason": "repeat-signature: count_primes x47 in 5m — mining shape",
  "severity": "low|med|high",
  "sample": { "func": "count_primes", "endpoint": "/tasks" }
}
```

## How the hub pushes flags

The hub's detector fires flags best-effort, non-blocking — it must never delay task dispatch:

```
POST {CE_MONITOR_URL}/ingest          # CE_MONITOR_URL default http://127.0.0.1:8971
x-ce-monitor-token: {CE_MONITOR_INGEST_TOKEN}
body: <one FlagEvent>
```

Errors are ignored (fire-and-forget). ce-monitor is a sink, not a dependency.

## Run

```bash
CE_MONITOR_INGEST_TOKEN=… CE_AUTH_URL=http://127.0.0.1:8972 PORT=8971 \
  cargo run --release
```

## Test

```bash
cargo test
```

Covers: `/ingest` rejects a bad token (401) and accepts + stores a good one; the admin endpoints
delegate to ce-auth's `/verify` (mock verifier) — `{ok:true}` admits (200), `{ok:false}` is 401,
ce-auth-down is 503, and the device-signed headers are forwarded verbatim; `/admin/challenge`
proxies ce-auth (and 503s when it is down); `mark seen` clears the unseen count only when admitted;
the log survives restart; filters apply.

## Deploy (on the relay, behind nginx, admin-only)

ce-monitor listens on `127.0.0.1:8971`. Put it behind the relay's nginx so only the operator reaches
it. Example location block (restrict by IP / basic-auth in addition to the in-app admin token):

```nginx
location /watch/ {
    # allow <your-ip>; deny all;          # optional network-level lockdown
    proxy_pass         http://127.0.0.1:8971/;
    proxy_set_header   Host $host;
    proxy_set_header   X-Forwarded-For $remote_addr;
}
```

Run it under systemd alongside `ce-relay` and `ce-hub`:

```ini
[Unit]
Description=ce-monitor security console
After=network.target

[Service]
Environment=CE_MONITOR_INGEST_TOKEN=…
Environment=CE_AUTH_URL=http://127.0.0.1:8972
Environment=PORT=8971
Environment=CE_MONITOR_DATA_DIR=/var/lib/ce-monitor
ExecStart=/usr/local/bin/ce-monitor
Restart=always

[Install]
WantedBy=multi-user.target
```

The console is **admin-only** by design — there is no public surface. Admin access is gated by
ce-auth device-auth (point `CE_AUTH_URL` at the local ce-auth sidecar); keep the ingest token secret
and prefer additional network-level restriction at nginx.
