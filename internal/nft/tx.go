//wirenet:deterministic

package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/danthegoodman1/wirenet/internal/model"
)

// Transaction is one atomic change to the table. A Linux backend renders it
// as one nftables batch in the order Apply plays it.
type Transaction struct {
	// Replace rebuilds the table from nothing, for a namespace whose table
	// the agent has yet to see.
	Replace *Ruleset `json:"replace,omitempty"`
	// Forward says the table translates forwarded traffic too, so a rule
	// rewrite covers the forwarding chains.
	Forward bool `json:"forward,omitempty"`
	// Rules, when set, replaces every chain's rules. Rules are flushed
	// first and written last, so maps and sets they name exist in between.
	Rules   *Rules       `json:"rules,omitempty"`
	DelMaps []string     `json:"del_maps,omitempty"`
	DelSets []string     `json:"del_sets,omitempty"`
	AddMaps []Map        `json:"add_maps,omitempty"`
	AddSets []Set        `json:"add_sets,omitempty"`
	Slots   []SlotUpdate `json:"slots,omitempty"`
	SetAdd  []SetElems   `json:"set_add,omitempty"`
	SetDel  []SetElems   `json:"set_del,omitempty"`
}

// SlotUpdate gives one slot of a map a new backend: a delete and an add of
// one element, inside the transaction.
type SlotUpdate struct {
	Map  string     `json:"map"`
	Slot int        `json:"slot"`
	Addr netip.Addr `json:"addr"`
}

// SetElems adds or removes addresses of one set.
type SetElems struct {
	Set   string       `json:"set"`
	Addrs []netip.Addr `json:"addrs"`
}

// Empty reports whether the transaction changes nothing.
func (t *Transaction) Empty() bool {
	return t.Replace == nil && t.Rules == nil && len(t.DelMaps) == 0 && len(t.DelSets) == 0 &&
		len(t.AddMaps) == 0 && len(t.AddSets) == 0 && len(t.Slots) == 0 && len(t.SetAdd) == 0 && len(t.SetDel) == 0
}

// Diff returns the transaction that turns have into want. A nil have, whose
// content is unknown, yields a replacement.
func Diff(have, want *Ruleset) Transaction {
	if have == nil || have.Forward != want.Forward {
		return Transaction{Replace: want.Clone()}
	}
	t := Transaction{Forward: want.Forward}
	if !rulesEqual(have.Rules, want.Rules) {
		r := want.Rules.Clone()
		t.Rules = &r
	}
	for _, m := range have.Maps {
		if w, ok := want.Map(m.Name); !ok || w.Family != m.Family {
			t.DelMaps = append(t.DelMaps, m.Name)
		}
	}
	for _, m := range want.Maps {
		h, ok := have.Map(m.Name)
		if !ok || h.Family != m.Family {
			t.AddMaps = append(t.AddMaps, Map{Name: m.Name, Family: m.Family, Slots: slices.Clone(m.Slots)})
			continue
		}
		for slot, addr := range m.Slots {
			if h.Slots[slot] != addr {
				t.Slots = append(t.Slots, SlotUpdate{Map: m.Name, Slot: slot, Addr: addr})
			}
		}
	}
	for _, s := range have.Sets {
		if w, ok := want.Set(s.Name); !ok || w.Family != s.Family {
			t.DelSets = append(t.DelSets, s.Name)
		}
	}
	for _, s := range want.Sets {
		h, ok := have.Set(s.Name)
		if !ok || h.Family != s.Family {
			t.AddSets = append(t.AddSets, Set{Name: s.Name, Family: s.Family, Addrs: slices.Clone(s.Addrs)})
			continue
		}
		add, del := setDelta(h.Addrs, s.Addrs)
		if len(add) > 0 {
			t.SetAdd = append(t.SetAdd, SetElems{Set: s.Name, Addrs: add})
		}
		if len(del) > 0 {
			t.SetDel = append(t.SetDel, SetElems{Set: s.Name, Addrs: del})
		}
	}
	// Deleting a map or set a surviving rule still names would fail, so a
	// deletion always comes with a rule rewrite; Diff only produces one when
	// the rules changed, since rules name what they use.
	return t
}

// setDelta returns what to add to and remove from sorted have to make
// sorted want.
func setDelta(have, want []netip.Addr) (add, del []netip.Addr) {
	for _, a := range want {
		if _, ok := slices.BinarySearchFunc(have, a, netip.Addr.Compare); !ok {
			add = append(add, a)
		}
	}
	for _, a := range have {
		if _, ok := slices.BinarySearchFunc(want, a, netip.Addr.Compare); !ok {
			del = append(del, a)
		}
	}
	return add, del
}

// ErrMissing reports an update naming a map, set or element that the table
// lacks, which the kernel rejects.
var ErrMissing = errors.New("nft: no such object")

// Apply plays a transaction over have and returns the result, failing as the
// kernel would on an update naming something missing or a result whose
// rules name what it lacks. have is left unchanged.
func Apply(have *Ruleset, t Transaction) (*Ruleset, error) {
	if t.Replace != nil {
		out := t.Replace.Clone()
		out.Normalize()
		return out, out.Validate()
	}
	if have == nil {
		return nil, fmt.Errorf("%w: table", ErrMissing)
	}
	out := have.Clone()
	if t.Rules != nil {
		out.Rules = Rules{}
	}
	for _, name := range t.DelMaps {
		i := slices.IndexFunc(out.Maps, func(m Map) bool { return m.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("%w: map %s", ErrMissing, name)
		}
		out.Maps = slices.Delete(out.Maps, i, i+1)
	}
	for _, name := range t.DelSets {
		i := slices.IndexFunc(out.Sets, func(s Set) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("%w: set %s", ErrMissing, name)
		}
		out.Sets = slices.Delete(out.Sets, i, i+1)
	}
	for _, m := range t.AddMaps {
		if _, ok := out.Map(m.Name); ok {
			return nil, fmt.Errorf("nft: map %s exists", m.Name)
		}
		out.Maps = append(out.Maps, Map{Name: m.Name, Family: m.Family, Slots: slices.Clone(m.Slots)})
		out.Normalize()
	}
	for _, s := range t.AddSets {
		if _, ok := out.Set(s.Name); ok {
			return nil, fmt.Errorf("nft: set %s exists", s.Name)
		}
		out.Sets = append(out.Sets, Set{Name: s.Name, Family: s.Family, Addrs: slices.Clone(s.Addrs)})
		out.Normalize()
	}
	for _, u := range t.Slots {
		m, ok := out.Map(u.Map)
		if !ok || u.Slot < 0 || u.Slot >= len(m.Slots) {
			return nil, fmt.Errorf("%w: map %s slot %d", ErrMissing, u.Map, u.Slot)
		}
		m.Slots[u.Slot] = u.Addr
	}
	for _, e := range t.SetAdd {
		s, ok := out.Set(e.Set)
		if !ok {
			return nil, fmt.Errorf("%w: set %s", ErrMissing, e.Set)
		}
		s.Addrs = append(s.Addrs, e.Addrs...)
	}
	for _, e := range t.SetDel {
		s, ok := out.Set(e.Set)
		if !ok {
			return nil, fmt.Errorf("%w: set %s", ErrMissing, e.Set)
		}
		// The kernel fails the whole batch on deleting a missing element
		// (nft_del_setelem, nf_tables_api.c), unlike adding a present one.
		for _, a := range e.Addrs {
			if !slices.Contains(s.Addrs, a) {
				return nil, fmt.Errorf("%w: set %s element %v", ErrMissing, e.Set, a)
			}
		}
		s.Addrs = slices.DeleteFunc(s.Addrs, func(a netip.Addr) bool { return slices.Contains(e.Addrs, a) })
	}
	if t.Rules != nil {
		out.Rules = t.Rules.Clone()
	}
	out.Normalize()
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// Size counts the objects and elements a transaction writes, for metrics.
func (t *Transaction) Size() int {
	if t.Replace != nil {
		n := 1
		for _, m := range t.Replace.Maps {
			n += len(m.Slots)
		}
		for _, s := range t.Replace.Sets {
			n += len(s.Addrs) + 1
		}
		return n + len(t.Replace.Rules.Translate) + len(t.Replace.Rules.Reject) + len(t.Replace.Rules.Accept) + len(t.Replace.Rules.Shield) +
			len(t.Replace.Rules.Open)
	}
	n := len(t.DelMaps) + len(t.DelSets) + len(t.Slots)
	for _, m := range t.AddMaps {
		n += len(m.Slots) + 1
	}
	for _, s := range t.AddSets {
		n += len(s.Addrs) + 1
	}
	for _, e := range t.SetAdd {
		n += len(e.Addrs)
	}
	for _, e := range t.SetDel {
		n += len(e.Addrs)
	}
	if t.Rules != nil {
		n += len(t.Rules.Translate) + len(t.Rules.Reject) + len(t.Rules.Accept) + len(t.Rules.Shield) + len(t.Rules.Open)
	}
	return n
}

// TranslateOut returns where a new outbound flow's first packet goes: the
// backend in slot draw of the matching rule's map, or dst itself when no
// rule matches. draw is the slot numgen random picked.
func (r *Ruleset) TranslateOut(dst netip.Addr, proto model.Proto, port uint16, draw int) (netip.Addr, bool) {
	for _, t := range r.Rules.Translate {
		if t.Addr == dst && t.Proto.Matches(t.Ports, proto, port) {
			m, ok := r.Map(t.Map)
			if !ok {
				return dst, false
			}
			return m.Slots[draw%len(m.Slots)], true
		}
	}
	return dst, false
}

// Rejected reports whether an untranslated packet to dst is rejected.
func (r *Ruleset) Rejected(dst netip.Addr) bool {
	_, ok := slices.BinarySearchFunc(r.Rules.Reject, dst, netip.Addr.Compare)
	return ok
}

// Closed reports whether a new flow to dst, after translation, is rejected
// for lying in one of the network's prefixes outside its open set.
func (r *Ruleset) Closed(dst netip.Addr) bool {
	for _, o := range r.Rules.Open {
		if !o.Prefix.Contains(dst) {
			continue
		}
		s, ok := r.Set(o.Set)
		if !ok {
			return true
		}
		_, found := slices.BinarySearchFunc(s.Addrs, dst, netip.Addr.Compare)
		return !found
	}
	return false
}

// Admit reports whether the inbound chain accepts a new flow from src.
func (r *Ruleset) Admit(src netip.Addr, proto model.Proto, port uint16) bool {
	for _, a := range r.Rules.Accept {
		if a.Family != FamilyOf(src) || !a.Proto.Matches(a.Ports, proto, port) {
			continue
		}
		if s, ok := r.Set(a.Set); ok {
			if _, found := slices.BinarySearchFunc(s.Addrs, src, netip.Addr.Compare); found {
				return true
			}
		}
	}
	return false
}
