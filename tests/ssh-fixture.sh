#!/usr/bin/env bash
set -euo pipefail
# Disposable loopback-only fixture for GitHub Actions. Does not use user servers.
fixture_dir="${RUNNER_TEMP:-/tmp}/contscope-ssh"
mkdir -p "$fixture_dir"
ssh-keygen -q -t ed25519 -N '' -f "$fixture_dir/client"
ssh-keygen -q -t ed25519 -N '' -f "$fixture_dir/host"
sudo mkdir -p /run/sshd
cat > "$fixture_dir/sshd_config" <<CONFIG
Port 22345
ListenAddress 127.0.0.1
HostKey $fixture_dir/host
PidFile $fixture_dir/sshd.pid
AuthorizedKeysFile $fixture_dir/client.pub
StrictModes no
PermitRootLogin prohibit-password
PasswordAuthentication no
UsePAM no
AllowUsers root
LogLevel ERROR
CONFIG
sudo /usr/sbin/sshd -f "$fixture_dir/sshd_config" -E "$fixture_dir/sshd.log"
docker run -d --name contscope-ssh-fixture alpine:3.21 sh -c 'echo "INFO ContScope test fixture"; sleep 600'
{
 echo "CONTSCOPE_TEST_SSH_PORT=22345"
 echo "CONTSCOPE_TEST_SSH_KEY=$fixture_dir/client"
} >> "$GITHUB_ENV"
