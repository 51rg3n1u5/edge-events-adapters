# edge-events-adapters

Parsers/adapters that convert common log sources into `events.jsonl` (schema v0) for `triage-events`.

## Targets (initial)
- NGINX/Apache access logs
- AWS ALB access logs

## Run (dev)

### Auto-discovery (default)

Auto flow:
1) tries `nginx -T` to extract `access_log` paths
2) falls back to common `/var/log/nginx|apache2|httpd` globs
3) if still nothing, tries journald (`journalctl -u nginx --since "24 hours ago"`) and parses any access-log style lines

```bash
PYTHONPATH=src python3 -m edge_events_adapters nginx \
  --asset edge-1 \
  --out events.jsonl \
  --discovery-report discovery_report.json
```

### Explicit inputs (override auto-discovery)

```bash
PYTHONPATH=src python3 -m edge_events_adapters nginx \
  --in /var/log/nginx/access.log \
  --in /var/log/nginx/access.log.1.gz \
  --asset edge-1 \
  --out events.jsonl
```
