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

## Log alert limitations

The scanner checks up to 200 **running** containers per host every 90 seconds, examines at most 300 log lines per container (up to 768 KiB of aggregate output), and attempts a 15-minute maximum lookback after downtime. The initial scan looks back a few seconds, not through historical logs. This is an in-dashboard *best-effort* warning, **not guaranteed lossless detection**: bursts, log drivers without `docker logs` support, inaccessible Docker sockets, large log volumes, or stopped hosts can cause missed matches. Matches are text heuristics, not proof of an actual service failure; false positives are expected. The local dashboard must be running to scan. Keep independent endpoint/uptime alerting.

The `error`, `fatal`, `panic` and `exception` expressions are currently predefined. External notifications and custom rules are not yet implemented. Container log text may contain sensitive information; only grant trusted users access to the dashboard.
