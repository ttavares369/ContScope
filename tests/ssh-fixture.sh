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
fixture_label=$(python3 -c 'print("X" * 60000)')
docker run -d --name contscope-ssh-fixture --label "contscope.fixture=$fixture_label" alpine:3.21 sh -c "echo 'INFO completed error:null'; echo 'INFO recorded error: retry scheduled'; echo 'INFO recovered error: transient downstream failure'; echo '[WARN] webhook failed, attempt: 1, error: dial tcp: lookup automation.example.test on 127.0.0.11:53: server misbehaving'; sleep 600"
{
 echo "CONTSCOPE_TEST_SSH_PORT=22345"
 echo "CONTSCOPE_TEST_SSH_KEY=$fixture_dir/client"
} >> "$GITHUB_ENV"
