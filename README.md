# ContScope

**Lightweight, self-hosted Docker container and Linux server monitoring over SSH.**

ContScope is a local-first, read-only web dashboard for sysadmins and DevOps. It uses SSH to inspect remote servers and Docker containers without installing permanent monitoring agents on the hosts.

## Initial prototype

- Register multiple SSH hosts and switch between a combined overview and each host.
- Assign a local display name and optional description to each container from the web UI. The original Docker container name stays unchanged; metadata is persisted locally and linked to the server + Docker container name.
- Display Linux CPU utilization, load average, RAM usage, root disk usage, uptime, and network throughput rates.
- List Docker containers, current status (including healthchecks when configured) and CPU, RAM and network snapshots reported by Docker.
- Refresh manually or every 30 seconds.
- Open the last 200 lines of a container's Docker logs from the Details button (limited to 128 KiB).
- Periodic (90-second) bounded scanning for case-insensitive whole-word `error`, `fatal`, `panic`, and `exception` in recent running-container logs. Shows up to 200 distinct local alerts; log scan cursor persisted across app restarts.
- English responsive web UI, HTTP Basic authentication, and a persistent local JSON server list.
- Read-only remote inspection: no restart, stop or delete controls.
- **Advanced diagnostics are on demand**: top CPU-consuming processes (ps), filesystem/Docker disk use (df, docker system df), interface traffic and established connection counts (procfs, ss), recent Docker events and individual container inspect details. All results are bounded and request-triggered, not collected continuously.
- The front page stays focused on fast health, utilization and container status. Per-server diagnostics are behind buttons.

**Limitations:** current version does not yet provide historical charts, external notifications, advanced log rules or Kubernetes/Podman integration. There is no monitoring or history collection when the local container is stopped. The SSH user must have access to the Docker daemon for Docker data.

## Local setup

Requires Docker Engine + Compose, an SSH key authorized on each remote Linux host and a verified `known_hosts` file.

```bash
git clone https://github.com/ttavares369/ContScope.git
cd ContScope
cp .env.example .env
# Edit .env to use a long random password (16+ characters)
mkdir -p ssh
# Provide a dedicated key ssh/id_ed25519 and verified ssh/known_hosts.
# Keep secrets outside Git; neither the SSH directory nor .env should be committed.
docker compose up -d --build
```

The web UI is bound to **http://127.0.0.1:8080** by default. Authenticate with the configured environment username/password, then register the remote servers. Mount SSH keys and known_hosts from the `ssh/` directory. The private key must be accessible to the unprivileged container process (UID 1000); protect its permissions accordingly. SSH host-key checking is mandatory; do not blindly trust output from `ssh-keyscan`.

**Security:** Docker socket privileges are effectively root-equivalent on the remote host. This prototype requires a remote account allowed to use Docker; do not assume that this account is read-only solely because ContScope sends read-only commands. Do not expose this UI publicly without a trusted TLS/authentication gateway and further security review. The dashboard currently returns SSH error messages which may contain server configuration details, so use only in a trusted local environment.

## Development

```bash
export CONTSCOPE_USER=admin
export CONTSCOPE_PASSWORD='replace-with-a-long-random-password'
go test ./...
go run .
```

## License

MIT.

## Progressive troubleshooting

The home view emphasizes a short set of prioritized findings (CPU over 90%, memory over 90%, root disk over 85%, unhealthy/restarting containers, SSH and Docker data availability). Each finding includes its observed evidence and a suggested **read-only** next diagnostic; no automatic corrective actions are taken. Warnings are heuristics and are not proof of root cause. Stopped containers are not automatically labeled broken because they may be intentional jobs. Deep diagnostics are loaded only on demand and initially show a short, expandable list; users request further detail themselves.

This early implementation does not yet predict future failures or guarantee proactive alerts when the local machine is powered off. Trends, configured thresholds, alert acknowledgment and contextual container-log drill-down remain future work.

## Lightweight architecture

One statically compiled Go backend serves the web UI and handles SSH sessions. It has no Prometheus, Grafana, external database, Node.js runtime, or permanent remote collector. Advanced diagnostics are requested explicitly and constrained with fixed read-only scripts, timeouts, and output limits. Network peer summaries may contain remote IP addresses; Docker logs may contain sensitive information, so limit UI access to trusted users. 

## Log alert limitations

The scanner checks up to 200 **running** containers per host every 90 seconds, examines at most 300 log lines per container (up to 768 KiB of aggregate output), and attempts a 15-minute maximum lookback after downtime. The initial scan looks back a few seconds, not through historical logs. This is an in-dashboard *best-effort* warning, **not guaranteed lossless detection**: bursts, log drivers without `docker logs` support, inaccessible Docker sockets, large log volumes, or stopped hosts can cause missed matches. Matches are text heuristics, not proof of an actual service failure; false positives are expected. The local dashboard must be running to scan. Keep independent endpoint/uptime alerting.

The `error`, `fatal`, `panic` and `exception` expressions are currently predefined. External notifications and custom rules are not yet implemented. Container log text may contain sensitive information; only grant trusted users access to the dashboard.

## Local troubleshooting and optional support

ContScope classifies common error messages locally with lightweight deterministic Go rules (storage pressure, memory, networking, DNS, TLS, permissions, file descriptors, process failures and timeouts). It displays a cautious explanation and suggested next check, with the original log hidden behind an expandable section. These suggestions are hypotheses and do not diagnose root causes on their own. No external AI API is required or contacted.

The optional **Get expert help** link opens https://www.jupiterti.com/servicos in a separate browser tab. It is an external professional-services link, not part of monitoring. ContScope never automatically sends logs, metrics, identifiers, SSH details or technical reports to Jupiter TI. Opening an external website normally exposes standard connection metadata (such as the visitor's IP) to that site.

We may add an explicitly opt-in BYOK AI integration in a future release; it must allow users to inspect and redact a request before any data leaves the local app. The software remains useful offline and never permits autonomous remote changes.

## Licensing

The current development branch uses the Apache License, Version 2.0. Previous published MIT-licensed revisions remain MIT-licensed; their attribution is preserved in NOTICE and Git history. Commercial support is optional and does not change access to open-source features.

## Request professional assistance

The optional **Get expert help** button opens a local review dialog for email contact at **tiago@jupiterti.com**. Select a configured host and explicitly choose **Prepare report**; by default the report includes only a bounded diagnostic snapshot and no raw log excerpts. An optional checkbox includes up to ten recent error excerpts (server-side best-effort secret/email/IP masking). The report is shown as editable JSON before you choose **Download JSON report**. **Compose email** opens your local mail application via `mailto:`; users attach the downloaded file themselves. The app does not send mail, upload reports, or send monitoring data to Jupiter TI. Automated redaction is not guaranteed to catch every secret; check carefully before emailing. The support link to the institutional website remains optional.

## Donations

The project welcomes voluntary support, but no payment provider or sponsorship URL has been activated or configured. A GitHub Sponsors link can be added once a valid sponsor account is created. Donation payments are not required for any feature.
