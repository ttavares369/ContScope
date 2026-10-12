# ContScope

**Lightweight, self-hosted Docker container and Linux server monitoring over SSH.**

ContScope is a local-first, read-only web dashboard for sysadmins and DevOps. It uses SSH to inspect remote servers and Docker containers without installing permanent monitoring agents on the hosts.

## Initial prototype

- Register multiple SSH hosts and switch between a combined overview and each host.
- Display Linux load average, RAM usage, root disk usage, uptime, and network byte counters.
- List Docker containers, current status (including healthchecks when configured) and CPU, RAM and network snapshots reported by Docker.
- Refresh manually or every 30 seconds.
- English responsive web UI, HTTP Basic authentication, and a persistent local JSON server list.
- Read-only remote inspection: no restart, stop or delete controls.

**Limitations:** current version does not yet show host CPU utilization percentage, Docker logs, history, network throughput rates, active alert notifications or Kubernetes/Podman integration. There is no monitoring or history collection when the local container is stopped. The SSH user must have access to the Docker daemon for Docker data.

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
