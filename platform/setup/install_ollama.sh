#!/bin/sh
# Official pinned release, checked before extraction; dedicated local-only service.
set -eu
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Trusted Linux root required.' >&2; exit 1; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ollama_version"])' "$repo/platform/versions.json")
digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ollama_archive_sha256"])' "$repo/platform/versions.json")
url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ollama_download_url"])' "$repo/platform/versions.json")
target=/opt/agentguard/ollama-$version
unit=/etc/systemd/system/agentguard-model.service
if [ -e "$target" ] || [ -e "$unit" ]; then
    printf '%s\n' 'Existing installation needs operator review; refusing overwrite.' >&2
    exit 1
fi
command -v zstd >/dev/null || { printf '%s\n' 'Install signed distro zstd first.' >&2; exit 1; }
install -d -m 0700 /var/lib/agentguard/downloads
archive=/var/lib/agentguard/downloads/ollama-$version.tar.zst
umask 077
curl --silent --show-error --fail --location --proto '=https' --tlsv1.2 \
    --retry 3 --retry-all-errors --continue-at - --speed-limit 1024 --speed-time 30 \
    "$url" -o "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status
install -d -m 0755 /opt/agentguard "$target"
tar --zstd -xf "$archive" -C "$target" --no-same-owner
chmod -R a+rX "$target"
cat > "$unit" <<EOF
[Unit]
Description=AgentGuard approved local model broker provider
After=network.target

[Service]
DynamicUser=yes
StateDirectory=agentguard-model
StateDirectoryMode=0700
Environment=HOME=/var/lib/agentguard-model
Environment=OLLAMA_MODELS=/var/lib/agentguard-model/models
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_NO_CLOUD=1
Environment=OLLAMA_CONTEXT_LENGTH=2048
Environment=OLLAMA_NUM_PARALLEL=1
ExecStart=$target/bin/ollama serve
Restart=on-failure
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
MemoryMax=6G
TasksMax=128

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$unit"
systemctl daemon-reload
# Start for this validation session; do not enable automatic boot startup.
systemctl start agentguard-model.service
systemctl is-active --quiet agentguard-model.service
printf '%s\n' "Installed verified Ollama $version; loopback-only service started."
