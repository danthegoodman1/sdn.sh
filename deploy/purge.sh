#!/usr/bin/env bash
# Stops the fleet's daemons on this machine and removes what earlier runs
# left, so the next run starts clean. sdn-lab runs it before and after
# every plan.
#
# Deleting a namespace's name is not enough: a process still holding the
# namespace keeps its WireGuard device keepaliving, and that device can
# claim a relay direction. So this kills those processes first, and then
# any process holding an unnamed namespace that carries a WireGuard
# device.
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "purge: run as root" >&2
	exit 1
fi
status=0
check() { "$@" || { echo "purge: $* failed" >&2; status=1; }; }

for unit in sdn-agent sdn-relay sdn-cp; do
	if systemctl is-active --quiet "$unit" || systemctl is-failed --quiet "$unit"; then
		check systemctl stop "$unit"
		systemctl reset-failed "$unit" 2>/dev/null
	fi
done
# Benchmark processes sdn-lab started as transient units, and strays.
for unit in $(systemctl list-units --all --plain --no-legend 'sdnb-*' | awk '{print $1}'); do
	systemctl stop "$unit" 2>/dev/null
	systemctl reset-failed "$unit" 2>/dev/null
done
pkill -KILL -x sdn-bench
pkill -KILL -x iperf3
pkill -KILL -x hostbench

wg_devices() { ip "$@" -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1; }

# Namespaces the agent (sdn-), the plans (sdnb-) and hostbench (hb-) name.
for ns in $(ip netns list | awk '{print $1}'); do
	case "$ns" in
	sdn-* | sdnb-* | hb-*) ;;
	*) continue ;;
	esac
	for pid in $(ip netns pids "$ns" 2>/dev/null); do
		echo "killing $pid ($(cat /proc/"$pid"/comm 2>/dev/null)): it holds namespace $ns"
		kill -KILL "$pid" 2>/dev/null
	done
	# Deleting the devices first frees their UDP ports in this namespace.
	for dev in $(wg_devices -n "$ns"); do
		check ip -n "$ns" link del "$dev"
	done
	check ip netns del "$ns"
done

# Devices the gateway plan and hostbench made in this namespace.
for dev in $(wg_devices); do
	case "$dev" in
	sdnb* | hb-*) check ip link del "$dev" ;;
	esac
done

# Processes holding an unnamed namespace with a WireGuard device in it.
host=$(readlink /proc/1/ns/net)
declare -A seen
for p in /proc/[0-9]*; do
	pid=${p#/proc/}
	ns=$(readlink "$p/ns/net" 2>/dev/null) || continue
	[ "$ns" = "$host" ] && continue
	if [ -z "${seen[$ns]:-}" ]; then
		seen[$ns]=clean
		[ -n "$(nsenter -t "$pid" -n ip -o link show type wireguard 2>/dev/null)" ] && seen[$ns]=wireguard
	fi
	if [ "${seen[$ns]}" = wireguard ]; then
		echo "killing $pid ($(cat "$p/comm" 2>/dev/null)): it holds $ns, which carries a WireGuard device"
		kill -KILL "$pid" 2>/dev/null
	fi
done

rm -rf /var/lib/sdn/journal /var/lib/sdn/relay /run/sdn/agent.sock /etc/wireguard/sdnbgw-*.key
exit $status
