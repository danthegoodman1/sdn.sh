//wirenet:deterministic

package compile

import (
	"cmp"
	"maps"
	"slices"

	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// Grant is a flow policy leaves open from one service to another, or to the
// internet when To is empty: the rules resolved, with every wildcard
// expanded and every deny applied.
type Grant struct {
	From  model.ServiceID
	To    model.ServiceID
	Proto model.Proto
	Ports model.PortRange
}

// Resolve turns a network's rules into grants. For each directed pair of
// services, and for each service's internet egress, a flow is granted when
// some allow names it and no deny does, so the rules' order never matters.
// model.AnyService matches every service but the one on the rule's other
// side, which keeps a service from reaching its own members unless a rule
// names it on both sides. A rule naming a service the network lacks matches
// nothing.
//
// Grants come sorted, and a pair's grants are disjoint: TCP and UDP port
// ranges, and model.OtherProto for every other protocol, or one grant for
// any protocol when nothing is taken out.
func Resolve(services []store.Service, rules []store.Rule) []Grant {
	ids := make([]model.ServiceID, len(services))
	for i, s := range services {
		ids[i] = s.ID
	}
	slices.Sort(ids)
	has := func(id model.ServiceID) bool {
		_, ok := slices.BinarySearch(ids, id)
		return ok
	}
	type pair struct{ from, to model.ServiceID }
	open := map[pair]*flows{}
	for _, r := range rules {
		if r.Deny {
			continue
		}
		for _, p := range expand(r, ids, has) {
			key := pair{p[0], p[1]}
			f, ok := open[key]
			if !ok {
				f = &flows{}
				open[key] = f
			}
			f.add(r.Proto, r.Ports)
		}
	}
	var out []Grant
	for _, p := range slices.SortedFunc(maps.Keys(open), func(a, b pair) int {
		return cmp.Or(cmp.Compare(a.from, b.from), cmp.Compare(a.to, b.to))
	}) {
		f := open[p]
		for _, r := range rules {
			if r.Deny && names(r, p.from, p.to) {
				f.remove(r.Proto, r.Ports)
			}
		}
		out = append(out, f.grants(p.from, p.to)...)
	}
	return out
}

// expand lists the directed pairs an allow names, each as {from, to}, with
// an empty to for egress.
func expand(r store.Rule, ids []model.ServiceID, has func(model.ServiceID) bool) [][2]model.ServiceID {
	var froms []model.ServiceID
	switch {
	case r.From == model.AnyService:
		froms = ids
	case has(r.From):
		froms = []model.ServiceID{r.From}
	}
	var out [][2]model.ServiceID
	for _, from := range froms {
		switch {
		case r.To == "":
			out = append(out, [2]model.ServiceID{from, ""})
		case r.To == model.AnyService:
			for _, to := range ids {
				if to != from {
					out = append(out, [2]model.ServiceID{from, to})
				}
			}
		case has(r.To) && (r.From != model.AnyService || r.To != from):
			out = append(out, [2]model.ServiceID{from, r.To})
		}
	}
	return out
}

// names reports whether a rule names the flows from one service to another,
// or to the internet when to is empty.
func names(r store.Rule, from, to model.ServiceID) bool {
	if to == "" {
		return r.To == "" && (r.From == from || r.From == model.AnyService)
	}
	side := func(s, self, other model.ServiceID) bool { return s == self || s == model.AnyService && self != other }
	return r.To != "" && side(r.From, from, to) && side(r.To, to, from)
}

// span is an inclusive range of ports.
type span struct{ lo, hi int }

const firstPort, lastPort = 1, 65535

func everyPort() span { return span{firstPort, lastPort} }

func spanOf(r model.PortRange) span {
	if r.All() {
		return everyPort()
	}
	return span{int(r.Lo), int(r.Hi)}
}

// spans is a sorted list of disjoint, non-adjacent spans.
type spans []span

func (s spans) add(n span) spans {
	var out spans
	for _, x := range s {
		switch {
		case x.hi+1 < n.lo || n.hi+1 < x.lo:
			out = append(out, x)
		default:
			n = span{min(n.lo, x.lo), max(n.hi, x.hi)}
		}
	}
	out = append(out, n)
	slices.SortFunc(out, func(a, b span) int { return cmp.Compare(a.lo, b.lo) })
	return out
}

func (s spans) remove(n span) spans {
	var out spans
	for _, x := range s {
		if x.hi < n.lo || n.hi < x.lo {
			out = append(out, x)
			continue
		}
		if x.lo < n.lo {
			out = append(out, span{x.lo, n.lo - 1})
		}
		if n.hi < x.hi {
			out = append(out, span{n.hi + 1, x.hi})
		}
	}
	return out
}

func (s spans) every() bool { return len(s) == 1 && s[0] == everyPort() }

// flows is a set of flows to one destination: TCP ports, UDP ports, and
// whether every other protocol is in.
type flows struct {
	tcp, udp spans
	other    bool
}

func (f *flows) add(p model.Proto, ports model.PortRange) {
	switch p {
	case model.TCP:
		f.tcp = f.tcp.add(spanOf(ports))
	case model.UDP:
		f.udp = f.udp.add(spanOf(ports))
	case model.AnyProto:
		f.tcp, f.udp, f.other = spans{everyPort()}, spans{everyPort()}, true
	}
}

func (f *flows) remove(p model.Proto, ports model.PortRange) {
	switch p {
	case model.TCP:
		f.tcp = f.tcp.remove(spanOf(ports))
	case model.UDP:
		f.udp = f.udp.remove(spanOf(ports))
	case model.AnyProto:
		*f = flows{}
	}
}

func (f *flows) grants(from, to model.ServiceID) []Grant {
	if f.tcp.every() && f.udp.every() && f.other {
		return []Grant{{From: from, To: to, Proto: model.AnyProto}}
	}
	var out []Grant
	for _, set := range []struct {
		proto model.Proto
		spans spans
	}{{model.TCP, f.tcp}, {model.UDP, f.udp}} {
		for _, s := range set.spans {
			g := Grant{From: from, To: to, Proto: set.proto}
			if s != everyPort() {
				g.Ports = model.PortRange{Lo: uint16(s.lo), Hi: uint16(s.hi)}
			}
			out = append(out, g)
		}
	}
	if f.other {
		out = append(out, Grant{From: from, To: to, Proto: model.OtherProto})
	}
	return out
}
