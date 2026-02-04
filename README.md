# edge-events-adapters

Parsers/adapters that convert common log sources into `events.jsonl` (schema v0) for `triage-events`.

## Targets (initial)
- NGINX/Apache access logs
- AWS ALB access logs

## Run (dev)

```bash
PYTHONPATH=src python3 -m edge_events_adapters nginx --in /var/log/nginx/access.log --asset edge-1 --out events.jsonl
```
