//wirenet:deterministic

package sim

import (
	"cmp"
	"maps"
	"slices"

	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// The oracle reads policy on its own, apart from the compiler: it decides
// one flow at a time straight from the rules, and finds ranges by asking at
// every port where some rule's range begins or ends.

// permits reports whether the rules let a flow from one service reach
// another, or the internet when to is empty: some allow names it and no deny
// does. A wildcard never matches the service on the rule's other side.
func permits(rules []store.Rule, from, to model.ServiceID, proto model.Proto, port uint16) bool {
	open := false
	for _, r := range rules {
		if !ruleNames(r, from, to) || !r.Proto.Matches(r.Ports, proto, port) {
			continue
		}
		if r.Deny {
			return false
		}
		open = true
	}
	return open
}

func ruleNames(r store.Rule, from, to model.ServiceID) bool {
	if to == "" {
		return r.To == "" && (r.From == from || r.From == model.AnyService)
	}
	return r.To != "" &&
		(r.From == from || r.From == model.AnyService && from != to) &&
		(r.To == to || r.To == model.AnyService && to != from)
}

// otherProbe stands for a protocol that is neither TCP nor UDP.
const otherProbe model.Proto = "icmp"

// starts lists in order every port where some rule's range begins or the
// port after one ends, so the rules answer alike from each start to the port
// before the next.
func starts(rules []store.Rule) []uint16 {
	set := map[uint16]bool{1: true}
	for _, r := range rules {
		if r.Ports.All() {
			continue
		}
		set[r.Ports.Lo] = true
		if r.Ports.Hi < 65535 {
			set[r.Ports.Hi+1] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// point is one flow the oracle asks about.
type point struct {
	proto model.Proto
	port  uint16
}

// points lists a flow for each stretch over which the rules answer alike.
func points(rules []store.Rule) []point {
	out := []point{{otherProbe, 0}}
	for _, p := range starts(rules) {
		out = append(out, point{model.TCP, p}, point{model.UDP, p})
	}
	return out
}

// reaches reports whether any flow at all may go from one service to
// another, asking at the rules' points.
func reaches(rules []store.Rule, pts []point, from, to model.ServiceID) bool {
	for _, p := range pts {
		if permits(rules, from, to, p.proto, p.port) {
			return true
		}
	}
	return false
}

// egressRules lists the egress the rules leave a service, in the form the
// agent installs it: one rule for any protocol when every flow is open, or
// else TCP and UDP ranges and the other protocols, sorted.
func egressRules(rules []store.Rule, from model.ServiceID) []kernel.EgressRule {
	ss := starts(rules)
	ranges := func(proto model.Proto) []model.PortRange {
		var out []model.PortRange
		for i, s := range ss {
			end := uint16(65535)
			if i+1 < len(ss) {
				end = ss[i+1] - 1
			}
			if !permits(rules, from, "", proto, s) {
				continue
			}
			if n := len(out); n > 0 && out[n-1].Hi+1 == s {
				out[n-1].Hi = end
				continue
			}
			out = append(out, model.PortRange{Lo: s, Hi: end})
		}
		return out
	}
	every := model.PortRange{Lo: 1, Hi: 65535}
	tcp, udp := ranges(model.TCP), ranges(model.UDP)
	other := permits(rules, from, "", otherProbe, 0)
	if slices.Equal(tcp, []model.PortRange{every}) && slices.Equal(udp, []model.PortRange{every}) && other {
		return []kernel.EgressRule{{Proto: model.AnyProto}}
	}
	var out []kernel.EgressRule
	for _, set := range []struct {
		proto  model.Proto
		ranges []model.PortRange
	}{{model.TCP, tcp}, {model.UDP, udp}} {
		for _, r := range set.ranges {
			if r == every {
				r = model.PortRange{}
			}
			out = append(out, kernel.EgressRule{Proto: set.proto, Ports: r})
		}
	}
	if other {
		out = append(out, kernel.EgressRule{Proto: model.OtherProto})
	}
	slices.SortFunc(out, func(a, b kernel.EgressRule) int {
		return cmp.Or(cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Ports.Lo, b.Ports.Lo), cmp.Compare(a.Ports.Hi, b.Ports.Hi))
	})
	return out
}
