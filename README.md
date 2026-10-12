# ContScope

![ContScope logo](assets/contscope-logo.svg)


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

**Limitations:** current version does not yet provide historical charts, external notifications beyond opt-in Telegram log-error alerts, advanced log rules or Kubernetes/Podman integration. There is no monitoring or history collection when the local container is stopped. The SSH user must have access to the Docker daemon for Docker data. Password authentication may be disabled by the monitored host's SSH policy.

## Quick start

Once a versioned image has been published to the GitHub Container Registry, download the matching `compose.release.yaml` as `compose.yaml` and run:

```bash
docker compose up
```

On its **first** run, ContScope creates an `admin` account, prints a random password and the local URL `http://localhost:8080` in the container logs. No manual password or master key is needed. The dashboard stays bound to loopback, so on a remote VPS use SSH tunneling or an HTTPS proxy. The first password is displayed only at account creation. **Important:** Docker log collectors and terminal scrollback may retain it, so protect logs and change/revoke the password when necessary.

For detached installations, use `docker compose up -d` followed by `docker compose logs contscope` to see the initial password. Subsequent restarts do not print it again. If you lose access, run:

```bash
docker compose exec contscope /usr/local/bin/contscope reset-admin
```

The admin verification data, encrypted SSH credentials, tags and the automatically generated encryption key remain in the persistent Docker volume. Back up this volume securely. To build from source instead of pulling a registry image, run `docker compose -f compose.dev.yaml up --build`.

After login, choose **Add server**, enter the SSH host, port and username, then select a password or upload a private key. Independently confirm the remote SSH host fingerprint, test the connection and save.

**Security:** The SSH account's access to Docker may grant root-equivalent privileges on the remote host; monitoring requests are read-only but that does not make the SSH account itself read-only. The local HTTP UI is not suitable for exposure on a public network without HTTPS and appropriate access controls.

## Development

```bash
export CONTSCOPE_USER=admin
export CONTSCOPE_PASSWORD='replace-with-a-long-random-password'
go test ./...
go run .
```

## License

Apache License 2.0. Earlier MIT-licensed revisions retain their original license.

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

## Product identity and About

The ContScope header and favicon use a compact container-and-target SVG mark inspired by the selected brand concept; the full vector logo is included at `assets/contscope-logo.svg`. The **About** dialog shows the version, commit hash, build date, Apache 2.0 license, GitHub repository, optional donation status and professional support contact. Donation buttons will be activated only after a real funding destination is configured.

Image releases can embed build data with `docker build --build-arg VERSION=beta --build-arg VCS_REF=$(git rev-parse --short HEAD) --build-arg BUILD_DATE=$(date -u +%FT%TZ) .`. Development builds show `dev` / `unknown` rather than claiming a published release.

## SSH onboarding security boundaries

Host discovery via `ssh-keyscan` only displays a **candidate** host key. The user must verify its SHA256 fingerprint out of band before trusting it. A successful connection test is required prior to saving and is cryptographically bound to the exact settings for five minutes. The application stores credentials encrypted with AES-256-GCM using a randomly generated local key stored inside the private Docker volume. A 32-byte random key is generated automatically on first run. Credentials are never returned to the browser by a GET endpoint; private keys/passwords are transported to the local API only during explicit setup/test/save requests. Protect the browser connection, the `.env` file, the Docker volume, and any copies of the uploaded private key. Do not upload passphrase-encrypted private keys yet; support for them is planned. The private key material is used transiently and the application does not install anything on monitored hosts.

## Telegram alerts (optional)

Open **Telegram alerts** in the dashboard. Create a bot with Telegram's @BotFather, open a conversation with the bot or add it to the desired group, enter its **Bot token** and numeric **Chat ID**, then use **Send test message**. Enable notifications and save. Bot credentials are encrypted locally; the existing token is never returned to the browser. A per-server/container/category cooldown (default 30 minutes, configurable between 5 and 1440) limits notifications, and alerts are sent only for newly detected log error signatures. Telegram sends over HTTPS from the ContScope instance only when enabled. Only the selected server name, container ID abbreviation and error category are sent; raw logs are never sent. This is best-effort monitoring; logs may be missed due to rate limits, outages or large log volume. The settings and SSH credentials are stored in the same persistent volume. Telegram is a third-party provider, so the information in alert messages leaves the local instance when enabled.

## Organize servers with color tags

Use **Organize servers with colors** to create reusable color-coded tags such as Company A, Company B, AWS, Azure, production or staging. Up to eight tags can be assigned to each registered server, and a tag may be reused across servers. The dashboard shows the tags next to server names, supports tag filters, and groups the full overview by each server's first (primary) tag. An **Untagged** group keeps new servers visible. Tags can be edited or deleted without changing the remote hosts or their SSH credentials. Tag names and colors are stored locally in the same persistent application volume.

## Versioned Docker images (planned first beta)

`compose.dev.yaml` is the development Compose file and builds directly from source. Both the default `compose.yaml` and `compose.release.yaml` pull a ready-to-run image from `ghcr.io/ttavares369/contscope`. The release pipeline in `.github/workflows/publish.yml` publishes **linux/amd64** and **linux/arm64** automatically on updates to `main` with tag `beta`, and also on `v*` release tags belonging to `main`. The release tag is baked into the About panel together with its Git SHA and UTC build date. The release Compose pins a version rather than following `latest`, to avoid surprise upgrades. The default `beta` image becomes available once the publishing workflow on `main` succeeds and the GHCR package is public.

After the image exists, download the versioned release Compose file as `compose.yaml` and run `docker compose up` to see the first-run admin credentials. Use the `CONTSCOPE_IMAGE_TAG` variable to select a released version. The port binds to loopback by default. For access from other computers, configure an HTTPS reverse proxy; do not expose the basic-auth UI over cleartext HTTP. Always back up the persistent volume (both credentials and the locally generated encryption key are stored there). No remote host needs the ContScope agent installed.

## Change the admin password

Select **Change password** in the ContScope dashboard. Enter the current password, a new password of 14–256 characters, and confirmation. A successful change immediately invalidates the previous password for new HTTP requests; your browser may retain HTTP Basic authentication credentials until its tab or browser session is closed. Passwords are never logged or returned by the API. The password change is only available for the automatically managed admin account. When `CONTSCOPE_USER` and `CONTSCOPE_PASSWORD` environment overrides are used, change the values in the deployment environment instead. The emergency CLI command `docker compose exec contscope /usr/local/bin/contscope reset-admin` remains available for local account recovery.
