package compile

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
	"github.com/danthegoodman1/wirenet/internal/store"
)

const any = model.AnyService

func svcs(ids ...model.ServiceID) []store.Service {
	out := make([]store.Service, len(ids))
	for i, id := range ids {
		out[i] = store.Service{ID: id}
	}
	return out
}

func allow(from, to model.ServiceID, proto model.Proto, lo, hi uint16) store.Rule {
	return store.Rule{From: from, To: to, Proto: proto, Ports: model.PortRange{Lo: lo, Hi: hi}}
}

func deny(from, to model.ServiceID, proto model.Proto, lo, hi uint16) store.Rule {
	r := allow(from, to, proto, lo, hi)
	r.Deny = true
	return r
}

func show(gs []Grant) string {
	var b []string
	for _, g := range gs {
		to := string(g.To)
		if to == "" {
			to = "internet"
		}
		b = append(b, fmt.Sprintf("%s>%s %s/%s", g.From, to, g.Proto, g.Ports))
	}
	return strings.Join(b, " ")
}

func TestRulesResolveToTheFlowsTheyLeaveOpen(t *testing.T) {
	for _, c := range []struct {
		name     string
		services []store.Service
		rules    []store.Rule
		want     string
	}{
		{"a wildcard source reaches the service from every other",
			svcs("api", "db", "web"), []store.Rule{allow(any, "db", model.TCP, 5432, 5432)},
			"api>db tcp/5432 web>db tcp/5432"},
		{"a wildcard destination leaves out the source's own service",
			svcs("box", "mirror", "queue"), []store.Rule{allow("box", any, model.TCP, 443, 443)},
			"box>mirror tcp/443 box>queue tcp/443"},
		{"two wildcards pair every two services, never one with itself",
			svcs("a", "b", "c"), []store.Rule{allow(any, any, model.UDP, 53, 53)},
			"a>b udp/53 a>c udp/53 b>a udp/53 b>c udp/53 c>a udp/53 c>b udp/53"},
		{"a service reaches itself when a rule names it on both sides",
			svcs("box"), []store.Rule{allow("box", "box", model.TCP, 80, 80)},
			"box>box tcp/80"},
		{"a deny takes a service out of a wildcard",
			svcs("api", "billing", "box"), []store.Rule{allow(any, "billing", model.AnyProto, 0, 0), deny("box", "billing", model.AnyProto, 0, 0)},
			"api>billing any/*"},
		{"a deny before its allow still wins",
			svcs("api", "billing", "box"), []store.Rule{deny("box", "billing", model.AnyProto, 0, 0), allow(any, "billing", model.AnyProto, 0, 0)},
			"api>billing any/*"},
		{"a port denied out of any protocol leaves the rest of TCP, all of UDP and every other protocol",
			svcs("a", "b"), []store.Rule{allow("a", "b", model.AnyProto, 0, 0), deny("a", "b", model.TCP, 22, 22)},
			"a>b tcp/1-21 a>b tcp/23-65535 a>b udp/* a>b other/*"},
		{"a port denied out of a range splits it",
			svcs("a", "b"), []store.Rule{allow("a", "b", model.TCP, 1000, 2000), deny("a", "b", model.TCP, 1500, 1500)},
			"a>b tcp/1000-1499 a>b tcp/1501-2000"},
		{"denying a protocol the allow lacks changes nothing",
			svcs("a", "b"), []store.Rule{allow("a", "b", model.TCP, 80, 80), deny("a", "b", model.UDP, 0, 0)},
			"a>b tcp/80"},
		{"a wildcard deny spares a service's own explicit rule",
			svcs("a", "b"), []store.Rule{allow("a", "a", model.AnyProto, 0, 0), deny(any, "a", model.AnyProto, 0, 0)},
			"a>a any/*"},
		{"overlapping and adjacent allows merge",
			svcs("a", "b"), []store.Rule{allow("a", "b", model.TCP, 80, 80), allow("a", "b", model.TCP, 81, 90), allow("a", "b", model.TCP, 85, 100)},
			"a>b tcp/80-100"},
		{"allows that add up to every flow become one grant for any protocol",
			svcs("a", "b"), []store.Rule{allow("a", "b", model.TCP, 0, 0), allow("a", "b", model.UDP, 0, 0), allow("a", "b", model.AnyProto, 0, 0)},
			"a>b any/*"},
		{"a wildcard grants egress to every service, and a deny takes one back",
			svcs("api", "box"), []store.Rule{allow(any, "", model.TCP, 443, 443), deny("box", "", model.AnyProto, 0, 0)},
			"api>internet tcp/443"},
		{"a deny to a service leaves egress alone",
			svcs("api", "db"), []store.Rule{allow("api", "", model.TCP, 443, 443), deny("api", any, model.AnyProto, 0, 0)},
			"api>internet tcp/443"},
		{"a rule naming a service the network lacks matches nothing",
			svcs("a"), []store.Rule{allow("gone", "a", model.TCP, 80, 80), allow("a", "gone", model.TCP, 80, 80), allow("gone", "", model.TCP, 80, 80)},
			""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := show(Resolve(c.services, c.rules)); got != c.want {
				t.Fatalf("got  %s\nwant %s", got, c.want)
			}
		})
	}
}

// permitted decides one flow straight from the rules, the way SPEC.md states
// them: some allow names it and no deny does.
func permitted(rules []store.Rule, from, to model.ServiceID, proto model.Proto, port uint16) bool {
	matches := func(side, self, other model.ServiceID) bool {
		return side == self || side == model.AnyService && self != other
	}
	open := false
	for _, r := range rules {
		var named bool
		if to == "" {
			named = r.To == "" && (r.From == from || r.From == model.AnyService)
		} else {
			named = r.To != "" && matches(r.From, from, to) && matches(r.To, to, from)
		}
		if !named || !r.Proto.Matches(r.Ports, proto, port) {
			continue
		}
		if r.Deny {
			return false
		}
		open = true
	}
	return open
}

func granted(gs []Grant, from, to model.ServiceID, proto model.Proto, port uint16) int {
	n := 0
	for _, g := range gs {
		if g.From == from && g.To == to && g.Proto.Matches(g.Ports, proto, port) {
			n++
		}
	}
	return n
}

// TestResolutionAgreesWithEveryRuleReadDirectly draws random rule sets and
// checks every flow at every port boundary the rules make, where both sides
// can change, against permitted: exactly one grant admits each permitted
// flow, and none admits any other. Shuffling the rules changes nothing.
func TestResolutionAgreesWithEveryRuleReadDirectly(t *testing.T) {
	rng := prng.New(1)
	ids := []model.ServiceID{"a", "b", "c"}
	sides := []model.ServiceID{"a", "b", "c", any}
	protos := []model.Proto{model.TCP, model.UDP, model.AnyProto}
	for round := range 2000 {
		var rules []store.Rule
		for range 1 + rng.Index(6) {
			r := store.Rule{From: sides[rng.Index(len(sides))], To: sides[rng.Index(len(sides))], Proto: protos[rng.Index(len(protos))], Deny: rng.Percent(40)}
			if rng.Percent(20) {
				r.To = ""
			}
			if r.Proto != model.AnyProto && rng.Percent(70) {
				lo := uint16(1 + rng.Index(30))
				r.Ports = model.PortRange{Lo: lo, Hi: lo + uint16(rng.Index(10))}
			}
			rules = append(rules, r)
		}
		gs := Resolve(svcs(ids...), rules)
		shuffled := slices.Clone(rules)
		for i := len(shuffled) - 1; i > 0; i-- {
			j := rng.Index(i + 1)
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		if again := Resolve(svcs(ids...), shuffled); show(again) != show(gs) {
			t.Fatalf("round %d: order changed the grants:\n%s\n%s", round, show(gs), show(again))
		}
		ports := []uint16{1, 65535}
		for _, r := range rules {
			if !r.Ports.All() {
				ports = append(ports, r.Ports.Lo-1, r.Ports.Lo, r.Ports.Hi, r.Ports.Hi+1)
			}
		}
		for _, from := range ids {
			for _, to := range append(slices.Clone(ids), "") {
				for _, proto := range []model.Proto{model.TCP, model.UDP, "icmp"} {
					for _, port := range ports {
						if port == 0 {
							continue
						}
						want := permitted(rules, from, to, proto, port)
						if n := granted(gs, from, to, proto, port); n > 1 || (n == 1) != want {
							t.Fatalf("round %d: %s to %q over %s/%d: %d grants admit it, want permitted=%v\nrules %+v\ngrants %s",
								round, from, to, proto, port, n, want, rules, show(gs))
						}
					}
				}
			}
		}
	}
}
