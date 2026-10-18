//wirenet:deterministic

// Package nft models the one nftables table the agent installs in each
// interface's namespace, `table inet wirenet`:
//
//	map s_<service>_6 { typeof numgen random mod 1024 : ip6 daddr; }
//	map s_<service>_4 { typeof numgen random mod 1024 : ip daddr; }
//	set f_<service>_6 { type ipv6_addr; }   live source addresses
//	set f_<service>_4 { type ipv4_addr; }
//	chain services { type nat hook output priority dstnat; }
//	    ip6 daddr <service> tcp dport 5432 dnat ip6 to numgen random mod 1024 map @s_<service>_6
//	chain untranslated { type filter hook output priority filter; }
//	    ip6 daddr <service> reject
//	chain inbound { type filter hook input priority filter; policy drop; }
//	    iif lo accept; ct state established,related accept; ct state invalid drop
//	    ICMP errors accept
//	    ip6 saddr @f_<service>_6 tcp dport 5432 accept
//	chain clamp { type filter hook output priority mangle; }
//	    tcp flags syn tcp option maxseg size set rt mtu
//
// A packet to a service address that the services chain translated no longer
// carries that address when the untranslated chain sees it, so the reject
// catches only what found no translation: a service with no backends, or a
// port policy does not name. A client fails fast rather than hanging.
//
// A Ruleset is the table's content as data; Diff turns two of them into one
// Transaction, which nftables applies atomically; Apply plays a transaction
// over a ruleset as the kernel would; Translate and Admit decide a packet's
// fate, for the simulator.
package nft

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/danthegoodman1/wirenet/internal/model"
)

// Table is the table's name in the inet family.
const Table = "wirenet"

// Slots is the length of every slot map.
const Slots = 1024

// Family is an address family.
type Family int

const (
	IPv6 Family = 6
	IPv4 Family = 4
)

// FamilyOf returns an address's family.
func FamilyOf(a netip.Addr) Family {
	if a.Is4() {
		return IPv4
	}
	return IPv6
}

// Ruleset is everything the table holds.
type Ruleset struct {
	// Forward also translates in prerouting, for a namespace that forwards
	// for others, such as a gateway's.
	Forward bool `json:"forward,omitempty"`
	// Maps and Sets are sorted by name.
	Maps []Map `json:"maps,omitempty"`
	Sets []Set `json:"sets,omitempty"`
	// Rules are the chains' rules; they change only when policy or a
	// service's presence of backends does.
	Rules Rules `json:"rules"`
}

// Map is a service's slot map in one family: every slot's backend address.
type Map struct {
	Name   string       `json:"name"`
	Family Family       `json:"family"`
	Slots  []netip.Addr `json:"slots"`
}

// Set is the live source addresses of one service in one family.
type Set struct {
	Name   string       `json:"name"`
	Family Family       `json:"family"`
	Addrs  []netip.Addr `json:"addrs,omitempty"`
}

// Rules are the rules of every chain.
type Rules struct {
	// Translate holds a dnat rule per reachable service, family and port.
	Translate []Translate `json:"translate,omitempty"`
	// Reject lists service addresses whose untranslated packets are
	// rejected.
	Reject []netip.Addr `json:"reject,omitempty"`
	// Accept lists the inbound flows policy permits.
	Accept []Accept `json:"accept,omitempty"`
	// Shield names sets whose addresses take no new forwarded flow, only
	// replies: the development machines behind a gateway.
	Shield []string `json:"shield,omitempty"`
}

// Clone copies the rules.
func (r Rules) Clone() Rules {
	return Rules{
		Translate: slices.Clone(r.Translate),
		Reject:    slices.Clone(r.Reject),
		Accept:    slices.Clone(r.Accept),
		Shield:    slices.Clone(r.Shield),
	}
}

// Translate sends a service address's flows through a slot map.
type Translate struct {
	Addr  netip.Addr      `json:"addr"`
	Proto model.Proto     `json:"proto"`
	Ports model.PortRange `json:"ports"`
	Map   string          `json:"map"`
}

// Accept admits new flows from a set's addresses.
type Accept struct {
	Set    string          `json:"set"`
	Family Family          `json:"family"`
	Proto  model.Proto     `json:"proto"`
	Ports  model.PortRange `json:"ports"`
}

// MapName names a service's slot map in one family.
func MapName(svc model.ServiceID, f Family) string {
	return fmt.Sprintf("s_%s_%d", model.Short(string(svc)), f)
}

// SetName names a service's source set in one family.
func SetName(svc model.ServiceID, f Family) string {
	return fmt.Sprintf("f_%s_%d", model.Short(string(svc)), f)
}

// DeviceSetName names the set of the development machines a gateway fronts,
// in one family.
func DeviceSetName(f Family) string { return fmt.Sprintf("d_%d", f) }

// ParseName reports whether a name MapName, SetName or DeviceSetName made
// names a slot map, and its family.
func ParseName(name string) (isMap bool, f Family) {
	f = IPv6
	if strings.HasSuffix(name, "_4") {
		f = IPv4
	}
	return strings.HasPrefix(name, "s_"), f
}

// Normalize sorts a ruleset's parts, so equal rulesets compare equal.
func (r *Ruleset) Normalize() {
	slices.SortFunc(r.Maps, func(a, b Map) int { return cmp.Compare(a.Name, b.Name) })
	slices.SortFunc(r.Sets, func(a, b Set) int { return cmp.Compare(a.Name, b.Name) })
	for i := range r.Sets {
		slices.SortFunc(r.Sets[i].Addrs, netip.Addr.Compare)
		r.Sets[i].Addrs = slices.Compact(r.Sets[i].Addrs)
	}
	slices.SortFunc(r.Rules.Translate, func(a, b Translate) int {
		return cmp.Or(a.Addr.Compare(b.Addr), cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Ports.Lo, b.Ports.Lo), cmp.Compare(a.Ports.Hi, b.Ports.Hi))
	})
	slices.SortFunc(r.Rules.Reject, netip.Addr.Compare)
	r.Rules.Reject = slices.Compact(r.Rules.Reject)
	slices.SortFunc(r.Rules.Accept, func(a, b Accept) int {
		return cmp.Or(cmp.Compare(a.Set, b.Set), cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Ports.Lo, b.Ports.Lo), cmp.Compare(a.Ports.Hi, b.Ports.Hi))
	})
	slices.Sort(r.Rules.Shield)
	r.Rules.Shield = slices.Compact(r.Rules.Shield)
}

// Validate checks what nftables would otherwise accept and then misbehave
// on: a map with an empty slot, a family mismatch, or a rule naming a map or
// set the ruleset lacks.
func (r *Ruleset) Validate() error {
	maps := map[string]Map{}
	for _, m := range r.Maps {
		if len(m.Slots) != Slots {
			return fmt.Errorf("map %s holds %d slots, not %d", m.Name, len(m.Slots), Slots)
		}
		for i, a := range m.Slots {
			if !a.IsValid() || FamilyOf(a) != m.Family {
				return fmt.Errorf("map %s slot %d holds %v", m.Name, i, a)
			}
		}
		maps[m.Name] = m
	}
	sets := map[string]Set{}
	for _, s := range r.Sets {
		for _, a := range s.Addrs {
			if FamilyOf(a) != s.Family {
				return fmt.Errorf("set %s holds %v", s.Name, a)
			}
		}
		sets[s.Name] = s
	}
	for _, t := range r.Rules.Translate {
		m, ok := maps[t.Map]
		if !ok || m.Family != FamilyOf(t.Addr) {
			return fmt.Errorf("rule for %v names map %s, which is missing or of another family", t.Addr, t.Map)
		}
	}
	for _, a := range r.Rules.Accept {
		s, ok := sets[a.Set]
		if !ok || s.Family != a.Family {
			return fmt.Errorf("accept names set %s, which is missing or of another family", a.Set)
		}
	}
	for _, name := range r.Rules.Shield {
		if _, ok := sets[name]; !ok {
			return fmt.Errorf("shield names set %s, which is missing", name)
		}
	}
	return nil
}

// Clone returns a deep copy.
func (r *Ruleset) Clone() *Ruleset {
	if r == nil {
		return nil
	}
	c := &Ruleset{Forward: r.Forward}
	for _, m := range r.Maps {
		c.Maps = append(c.Maps, Map{Name: m.Name, Family: m.Family, Slots: slices.Clone(m.Slots)})
	}
	for _, s := range r.Sets {
		c.Sets = append(c.Sets, Set{Name: s.Name, Family: s.Family, Addrs: slices.Clone(s.Addrs)})
	}
	c.Rules = r.Rules.Clone()
	return c
}

// Map finds a map by name.
func (r *Ruleset) Map(name string) (*Map, bool) {
	i, ok := slices.BinarySearchFunc(r.Maps, name, func(m Map, n string) int { return cmp.Compare(m.Name, n) })
	if !ok {
		return nil, false
	}
	return &r.Maps[i], true
}

// Set finds a set by name.
func (r *Ruleset) Set(name string) (*Set, bool) {
	i, ok := slices.BinarySearchFunc(r.Sets, name, func(s Set, n string) int { return cmp.Compare(s.Name, n) })
	if !ok {
		return nil, false
	}
	return &r.Sets[i], true
}

// Equal reports whether two normalized rulesets hold the same content.
func Equal(a, b *Ruleset) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Forward != b.Forward || len(a.Maps) != len(b.Maps) || len(a.Sets) != len(b.Sets) || !rulesEqual(a.Rules, b.Rules) {
		return false
	}
	for i := range a.Maps {
		if a.Maps[i].Name != b.Maps[i].Name || a.Maps[i].Family != b.Maps[i].Family || !slices.Equal(a.Maps[i].Slots, b.Maps[i].Slots) {
			return false
		}
	}
	for i := range a.Sets {
		if a.Sets[i].Name != b.Sets[i].Name || a.Sets[i].Family != b.Sets[i].Family || !slices.Equal(a.Sets[i].Addrs, b.Sets[i].Addrs) {
			return false
		}
	}
	return true
}

func rulesEqual(a, b Rules) bool {
	return slices.Equal(a.Translate, b.Translate) && slices.Equal(a.Reject, b.Reject) && slices.Equal(a.Accept, b.Accept) &&
		slices.Equal(a.Shield, b.Shield)
}
