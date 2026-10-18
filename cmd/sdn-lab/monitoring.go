package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
)

// targetGroup is one entry of a Prometheus file_sd file.
type targetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// targets renders the file_sd files deploy/monitoring/prometheus.yml reads:
// one per daemon, and one for every machine's node_exporter.
func targets(f Fleet) (map[string][]byte, error) {
	groups := map[string][]targetGroup{}
	add := func(file string, in Instance, role Role, port int) {
		groups[file] = append(groups[file], targetGroup{
			Targets: []string{net.JoinHostPort(in.PrivateIP, strconv.Itoa(port))},
			Labels:  map[string]string{"node": in.Name, "role": string(role)},
		})
	}
	add("sdn-cp.json", f.CP, RoleCP, telemetryPort[RoleCP])
	add("node.json", f.CP, RoleCP, 9100)
	for _, in := range f.Agents {
		add("sdn-agent.json", in, RoleAgent, telemetryPort[RoleAgent])
		add("node.json", in, RoleAgent, 9100)
	}
	for _, in := range f.Relays {
		add("sdn-relay.json", in, RoleRelay, telemetryPort[RoleRelay])
		add("node.json", in, RoleRelay, 9100)
	}
	add("sdn-relay.json", f.Middle, RoleMiddle, telemetryPort[RoleMiddle])
	add("node.json", f.Middle, RoleMiddle, 9100)
	out := map[string][]byte{}
	for file, g := range groups {
		b, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		out[file] = append(b, '\n')
	}
	return out, nil
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	return slices.Sorted(maps.Keys(m))
}
