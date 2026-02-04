# edge-events-adapters

Parsers/adapters that convert common log sources into `events.jsonl` (schema v0) for `triage-events`.

## Targets
- Web access logs (NGINX/Apache)
- AWS ALB access logs

## Run (dev)

### Auto-discovery (default)

Auto flow:
1) tries `nginx -T` to extract `access_log` paths
2) falls back to common `/var/log/nginx|apache2|httpd` globs
3) if still nothing, tries journald (`journalctl -u nginx --since "24 hours ago"`) and parses any access-log style lines

### Web access logs (auto by default)

```bash
# Zero-config default
PYTHONPATH=src python3 -m edge_events_adapters web --asset edge-1 --out events.jsonl

# Optional: widen/narrow journald lookback
PYTHONPATH=src python3 -m edge_events_adapters web --asset edge-1 --out events.jsonl --since "24 hours ago"

# Optional: explicit paths override auto-discovery
PYTHONPATH=src python3 -m edge_events_adapters web \
  --in /var/log/nginx/access.log \
  --in /var/log/nginx/access.log.1.gz \
  --asset edge-1 \
  --out events.jsonl
```

### AWS ALB access logs

```bash
# Explicit
PYTHONPATH=src python3 -m edge_events_adapters alb --asset edge-aws --out alb.events.jsonl --in /path/to/alb.log

# Auto-discovery under current directory (or add --root)
PYTHONPATH=src python3 -m edge_events_adapters alb --asset edge-aws --out alb.events.jsonl
```

### Firewall / flow logs (best-effort)

```bash
# Explicit
PYTHONPATH=src python3 -m edge_events_adapters firewall --asset edge-1 --out fw.events.jsonl --in /path/to/fw.log

# Auto-discovery under current directory (or add --root)
PYTHONPATH=src python3 -m edge_events_adapters firewall --asset edge-1 --out fw.events.jsonl
```

Supports:
- JSON lines (common key variants)
- key=value syslog-ish lines (`src=... dst=... dpt=... action=...`)
- CEF lines (best-effort)
- CSV with common column names (src/dst/port/action)

A discovery report is written next to the output by default:
- `*.jsonl` → `*.discovery.json`
