#!/bin/sh
# Signature-verified host sensor, isolated network namespace, no published ports.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Trusted rootful Linux host required.' >&2
    exit 1
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tetragon_image"])' "$repo/platform/versions.json")
release=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tetragon_release"])' "$repo/platform/versions.json")
install -d -m 0700 /var/lib/agentguard/sensor
umask 077
cosign verify \
    --certificate-identity "https://github.com/cilium/tetragon/.github/workflows/build-images-releases.yml@refs/tags/$release" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$image" > /var/lib/agentguard/sensor/image-verification.json
if docker container inspect agentguard-tetragon >/dev/null 2>&1; then
    actual=$(docker inspect --format '{{.Config.Image}}' agentguard-tetragon)
    managed=$(docker inspect --format '{{index .Config.Labels "agentguard.component"}}' agentguard-tetragon)
    if [ "$actual" != "$image" ] || [ "$managed" != host-sensor ]; then
        printf '%s\n' 'Existing sensor needs operator review; refusing replacement.' >&2
        exit 1
    fi
    docker start agentguard-tetragon
else
    docker pull "$image"
    docker run --detach --name agentguard-tetragon --pull=never --restart=no \
        --label agentguard.component=host-sensor --pid=host --cgroupns=host \
        --privileged --network=none \
        --mount type=bind,src=/sys/kernel/btf/vmlinux,dst=/var/lib/tetragon/btf,readonly \
        --mount type=bind,src=/sys/kernel,dst=/sys/kernel \
        "$image" /usr/bin/tetragon --metrics-server=127.0.0.1:2112 \
        --health-server-address=127.0.0.1:6789
fi
docker exec agentguard-tetragon tetra status
