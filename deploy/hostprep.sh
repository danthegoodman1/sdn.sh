#!/usr/bin/env bash
# Prepares an Ubuntu 24.04 machine for one fleet role: packages, sysctls,
# and the kernel features the agent depends on. Running it again changes
# nothing that is already right.
#
#   hostprep.sh cp|agent|relay|middle
#
# It fails loudly when the kernel lacks WireGuard or socket destruction
# (CONFIG_INET_DIAG_DESTROY), since an agent on such a kernel would either
# refuse to start or leave flows reaching whoever holds an address next.
set -euo pipefail

role=${1:-}
case "$role" in
cp | agent | relay | middle) ;;
*)
	echo "usage: $0 cp|agent|relay|middle" >&2
	exit 2
	;;
esac
if [ "$(id -u)" -ne 0 ]; then
	echo "hostprep: run as root" >&2
	exit 1
fi

say() { echo "hostprep[$role]: $*"; }
fail() {
	echo "hostprep[$role]: FAILED: $*" >&2
	exit 1
}

# Packages.
packages=(wireguard-tools nftables conntrack iproute2 iperf3 curl prometheus-node-exporter)
if [ "$role" = cp ]; then
	packages+=(postgresql prometheus)
fi
missing=()
for p in "${packages[@]}"; do
	dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
done
if [ ${#missing[@]} -gt 0 ]; then
	say "installing ${missing[*]}"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -q
	apt-get install -y -q --no-install-recommends "${missing[@]}"
fi
systemctl enable --now prometheus-node-exporter >/dev/null

# Sysctls. A relay's sockets ask for large buffers, which the kernel caps
# at rmem_max and wmem_max; the backlog absorbs bursts at line rate.
# Agents forward for internet egress, and the middle box forwards as a
# gateway.
conf=/etc/sysctl.d/90-sdn.conf
{
	echo "# Written by deploy/hostprep.sh for role $role."
	echo "net.core.rmem_max = 268435456"
	echo "net.core.wmem_max = 268435456"
	echo "net.core.rmem_default = 8388608"
	echo "net.core.wmem_default = 8388608"
	echo "net.core.netdev_max_backlog = 16384"
	case "$role" in
	agent | middle)
		echo "net.ipv4.ip_forward = 1"
		echo "net.ipv6.conf.all.forwarding = 1"
		;;
	esac
} >"$conf.new"
mv "$conf.new" "$conf"
sysctl -q -p "$conf"

# Kernel WireGuard, created in a scratch namespace so the check leaves
# nothing behind.
modprobe wireguard 2>/dev/null || {
	say "wireguard module missing; installing linux-modules-extra-$(uname -r)"
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q "linux-modules-extra-$(uname -r)" || true
	modprobe wireguard 2>/dev/null || true
}
probe=sdnprep-$$
ip netns add "$probe"
trap 'ip netns del "$probe" 2>/dev/null || true' EXIT
ip -n "$probe" link add wgcheck type wireguard 2>/dev/null ||
	fail "the kernel cannot create a WireGuard device"
say "kernel WireGuard: ok"

# Socket destruction: removing a peer destroys the sockets addressed to it
# with SOCK_DESTROY, which needs CONFIG_INET_DIAG_DESTROY.
config=/boot/config-$(uname -r)
if [ -r "$config" ]; then
	grep -q '^CONFIG_INET_DIAG_DESTROY=y' "$config" ||
		fail "$config lacks CONFIG_INET_DIAG_DESTROY=y; the agent refuses to run without it"
elif [ -r /proc/config.gz ]; then
	zgrep -q '^CONFIG_INET_DIAG_DESTROY=y' /proc/config.gz ||
		fail "/proc/config.gz lacks CONFIG_INET_DIAG_DESTROY=y; the agent refuses to run without it"
else
	# No config to read: kill a listening socket with ss -K and check
	# that it is gone.
	ip -n "$probe" link set lo up
	ip netns exec "$probe" python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",9)); s.listen(); time.sleep(30)' &
	listener=$!
	for _ in $(seq 50); do
		ip netns exec "$probe" ss -Hltn 'sport = :9' | grep -q . && break
		sleep 0.1
	done
	ip netns exec "$probe" ss -K -Hltn 'sport = :9' >/dev/null 2>&1 || true
	if ip netns exec "$probe" ss -Hltn 'sport = :9' | grep -q .; then
		kill "$listener" 2>/dev/null || true
		fail "ss -K cannot destroy a socket: the kernel lacks CONFIG_INET_DIAG_DESTROY"
	fi
	kill "$listener" 2>/dev/null || true
fi
say "socket destruction: ok"

mkdir -p /etc/sdn /var/lib/sdn
chmod 0755 /etc/sdn

# The control plane's database and secrets. Both stay on this machine:
# the units read them, and sdn-lab reads the token only through sdnctl.
if [ "$role" = cp ]; then
	systemctl enable --now postgresql >/dev/null
	umask 077
	[ -s /etc/sdn/admin-token ] || head -c 32 /dev/urandom | base64 | tr -d '/+=\n' >/etc/sdn/admin-token
	[ -s /etc/sdn/pg-password ] || head -c 32 /dev/urandom | base64 | tr -d '/+=\n' >/etc/sdn/pg-password
	password=$(cat /etc/sdn/pg-password)
	if runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname = 'sdn'" | grep -q 1; then
		runuser -u postgres -- psql -q -c "ALTER ROLE sdn LOGIN PASSWORD '$password'"
	else
		runuser -u postgres -- psql -q -c "CREATE ROLE sdn LOGIN PASSWORD '$password'"
	fi
	runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname = 'sdn'" | grep -q 1 ||
		runuser -u postgres -- psql -q -c "CREATE DATABASE sdn OWNER sdn"
	echo "SDN_STORE=postgres://sdn:$password@127.0.0.1:5432/sdn?sslmode=disable" >/etc/sdn/cp-store.env
	umask 022
	say "postgres role and database: ok"
	# sdn-cp serves its own metrics on :9090, Prometheus's default, so
	# Prometheus moves to loopback port 9099; reach it through an SSH
	# tunnel.
	mkdir -p /etc/prometheus/sdn
	args='ARGS="--web.listen-address=127.0.0.1:9099"'
	if [ "$(cat /etc/default/prometheus 2>/dev/null)" != "$args" ]; then
		echo "$args" >/etc/default/prometheus
		systemctl restart prometheus
	fi
	say "prometheus on 127.0.0.1:9099: ok"
fi

say "ready"
