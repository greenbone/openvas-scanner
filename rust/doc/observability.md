# Observability

openvasd exposes Prometheus metrics and meaningful health probes for production monitoring.

## Metrics Endpoint

Enable the `/metrics` endpoint with the `--enable-metrics` flag or the `ENABLE_METRICS=true`
environment variable:

```bash
openvasd --enable-metrics
```

By default, `/metrics` follows the global authentication setting (API key or mTLS).
You can override this with `--metrics-auth`:

```bash
# Expose /metrics without authentication (for internal scrape configs)
openvasd --enable-metrics --metrics-auth false

# Require authentication for /metrics
openvasd --enable-metrics --metrics-auth true
```

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'openvasd'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: /metrics
    # If authentication is enabled, add the API key header:
    # bearer_token: 'your-api-key'
```

## Metric Catalog

| Metric | Type | Labels | Description |
|---|---|---|---|
| `openvasd_scans_started_total` | counter | — | Total scans started |
| `openvasd_scans_completed_total` | counter | `status` | Scans that reached a terminal state (`succeeded`, `failed`, `stopped`) |
| `openvasd_scans_active` | gauge | — | Currently running scans |
| `openvasd_vt_executions_total` | counter | `result` | VT executions by outcome (`ok`, `error`, `timeout`) |
| `openvasd_vt_execution_seconds` | histogram | `stage` | VT execution duration by scheduling stage |
| `openvasd_feed_state` | gauge | `type` | Feed state: 0=unknown, 1=syncing, 2=synced |
| `openvasd_feed_last_sync_timestamp` | gauge | — | Unix timestamp of last successful feed sync |
| `openvasd_results_total` | counter | `type` | Results emitted by type (`alarm`, `log`, `error`, `hostdetail`, ...) |
| `openvasd_db_active_connections` | gauge | — | Active database connections |
| `openvasd_db_query_seconds` | histogram | `op` | Database query duration |
| `openvasd_http_requests_total` | counter | `method`, `status` | HTTP requests handled |
| `openvasd_http_request_seconds` | histogram | `method` | HTTP request duration |
| `openvasd_http_active` | gauge | — | In-flight HTTP requests |

## Health Probes

openvasd provides three health endpoints:

### `/health/alive`
Returns 200 if the HTTP server is responsive. Returns 503 if the server is
overloaded (too many connections).

### `/health/ready`
Returns 200 when the feed has reached `Synced` state, meaning the scanner is
ready to accept and execute scans. Returns 503 while the feed is loading or
syncing. Use this for Kubernetes readiness probes:

```yaml
readinessProbe:
  httpGet:
    path: /health/ready
    port: 3000
  initialDelaySeconds: 10
  periodSeconds: 10
```

### `/health/started`
Returns 200 once the feed has been synced at least once. Use this for Kubernetes
startup probes:

```yaml
startupProbe:
  httpGet:
    path: /health/started
    port: 3000
  failureThreshold: 30
  periodSeconds: 10
```
