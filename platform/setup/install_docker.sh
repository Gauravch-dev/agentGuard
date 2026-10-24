#!/bin/sh
# Reviewed lab-host setup from Docker's official Ubuntu apt instructions.
# Does not remove packages, grant Docker group access, or expose TCP ports.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'Run this script as root on the owned Ubuntu lab host.' >&2
    exit 1
fi
. /etc/os-release
if [ "$ID" != ubuntu ]; then
    printf '%s\n' 'Only Ubuntu is supported by this setup script.' >&2
    exit 1
fi
case "$VERSION_CODENAME" in
    jammy|noble|resolute|stonking) ;;
    *) printf '%s\n' 'Unsupported Ubuntu release; inspect vendor instructions first.' >&2; exit 1 ;;
esac
if command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is already installed; this script will not replace it.'
    docker version
    exit 0
fi
for old in docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc; do
    if dpkg-query -W -f='${Status}' "$old" 2>/dev/null | grep -q 'install ok installed'; then
        printf '%s\n' "Existing package $old requires operator review; no removal performed." >&2
        exit 1
    fi
done
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
if [ -e /etc/apt/sources.list.d/docker.sources ] || [ -e /etc/apt/keyrings/docker.asc ]; then
    printf '%s\n' 'Existing Docker apt configuration requires operator review; refusing overwrite.' >&2
    exit 1
fi
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
arch=$(dpkg --print-architecture)
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $VERSION_CODENAME
Components: stable
Architectures: $arch
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
version=$(apt-cache policy docker-ce | sed -n 's/^  Candidate: //p')
if [ -z "$version" ] || [ "$version" = '(none)' ]; then
    printf '%s\n' 'No signed Docker candidate is available for this host.' >&2
    exit 1
fi
printf 'Selected Docker version: %s\n' "$version"
apt-get install --yes --no-install-recommends "docker-ce=$version" "docker-ce-cli=$version" \
    containerd.io docker-buildx-plugin docker-compose-plugin
systemctl start docker
docker version
