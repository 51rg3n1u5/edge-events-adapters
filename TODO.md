# TODO (edge-events-adapters)

High-signal backlog for offline/on-prem log adapters.

## Now / next
- [ ] Improve DNS timestamp parsing (support RFC3164 timestamps so dnsmasq lines don’t get “now()”).
- [ ] Use file mtime as fallback timestamp (instead of now) for app/syslog/dns collectors.
- [ ] Add rsyslog/syslog-ng config parsing to discover custom remote file destinations.
- [ ] Add unit tests for syslog/dns/app parsing (sample lines → expected JSONL).

## Parsing quality
- [ ] Expand syslog auth parsing (sudo, su, PAM, failed ssh variants).
- [ ] Expand DNS parsing (BIND variants, querylog formats, AAAA/TXT/SRV).
- [ ] Reduce false positives further (qname heuristics, private-resolver chatter).

## Coverage
- [ ] Add more Linux product log roots (e.g., /var/log/sonatype/nexus, /var/opt/jfrog/artifactory, etc.).
- [ ] Optional: add Docker/container log discovery (journald + /var/lib/docker/containers/*/*.log) with strong bounds.

## Usability
- [ ] Add “triage summary” command (top talkers, new qnames, auth fails) purely offline.
