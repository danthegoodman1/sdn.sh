//go:build linux

package linux

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/nft"
)

// Chains of the agent's table. Rules live in the first four; the inbound
// chain's policy drops what no rule accepts.
var chainDefs = []struct {
	name     string
	kind     nftables.ChainType
	hook     *nftables.ChainHook
	priority *nftables.ChainPriority
	drop     bool
	forward  bool // exists only in a forwarding namespace
}{
	{"services", nftables.ChainTypeNAT, nftables.ChainHookOutput, nftables.ChainPriorityNATDest, false, false},
	{"untranslated", nftables.ChainTypeFilter, nftables.ChainHookOutput, nftables.ChainPriorityFilter, false, false},
	{"inbound", nftables.ChainTypeFilter, nftables.ChainHookInput, nftables.ChainPriorityFilter, true, false},
	{"clamp", nftables.ChainTypeFilter, nftables.ChainHookOutput, nftables.ChainPriorityMangle, false, false},
	{"services_fwd", nftables.ChainTypeNAT, nftables.ChainHookPrerouting, nftables.ChainPriorityNATDest, false, true},
	{"untranslated_fwd", nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityFilter, false, true},
	{"clamp_fwd", nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityMangle, false, true},
}

// nftWriter queues one transaction's operations on a connection.
type nftWriter struct {
	c       *nftables.Conn
	table   *nftables.Table
	chains  map[string]*nftables.Chain
	sets    map[string]*nftables.Set
	forward bool
}

func newWriter(c *nftables.Conn, forward bool) *nftWriter {
	w := &nftWriter{
		c:       c,
		table:   &nftables.Table{Name: nft.Table, Family: nftables.TableFamilyINet},
		chains:  map[string]*nftables.Chain{},
		sets:    map[string]*nftables.Set{},
		forward: forward,
	}
	for _, d := range chainDefs {
		ch := &nftables.Chain{Name: d.name, Table: w.table, Type: d.kind, Hooknum: d.hook, Priority: d.priority}
		if d.drop {
			p := nftables.ChainPolicyDrop
			ch.Policy = &p
		}
		w.chains[d.name] = ch
	}
	return w
}

// applyTransaction writes one transaction as one batch, so it applies whole
// or not at all.
func applyTransaction(c *nftables.Conn, tx nft.Transaction) error {
	forward := tx.Forward
	if tx.Replace != nil {
		forward = tx.Replace.Forward
	}
	w := newWriter(c, forward)
	if tx.Replace != nil {
		if err := w.replace(tx.Replace); err != nil {
			return err
		}
		return c.Flush()
	}
	if tx.Rules != nil {
		for _, d := range chainDefs {
			if !d.forward || forward {
				c.FlushChain(w.chains[d.name])
			}
		}
	}
	for _, name := range tx.DelMaps {
		c.DelSet(&nftables.Set{Table: w.table, Name: name})
	}
	for _, name := range tx.DelSets {
		c.DelSet(&nftables.Set{Table: w.table, Name: name})
	}
	for _, m := range tx.AddMaps {
		if err := w.addMap(m); err != nil {
			return err
		}
	}
	for _, s := range tx.AddSets {
		if err := w.addSet(s); err != nil {
			return err
		}
	}
	if err := w.slots(tx.Slots); err != nil {
		return err
	}
	for _, e := range tx.SetDel {
		if err := c.SetDeleteElements(w.set(e.Set), addrElems(e.Addrs)); err != nil {
			return err
		}
	}
	for _, e := range tx.SetAdd {
		if err := c.SetAddElements(w.set(e.Set), addrElems(e.Addrs)); err != nil {
			return err
		}
	}
	if tx.Rules != nil {
		if err := w.rules(*tx.Rules); err != nil {
			return err
		}
	}
	return c.Flush()
}

// replace deletes whatever table is there and builds the ruleset fresh, in
// the same batch: adding a table that exists is a no-op, so the delete
// always finds one.
func (w *nftWriter) replace(rs *nft.Ruleset) error {
	w.c.AddTable(w.table)
	w.c.DelTable(w.table)
	w.c.AddTable(w.table)
	for _, d := range chainDefs {
		if !d.forward || w.forward {
			w.c.AddChain(w.chains[d.name])
		}
	}
	for _, m := range rs.Maps {
		if err := w.addMap(m); err != nil {
			return err
		}
	}
	for _, s := range rs.Sets {
		if err := w.addSet(s); err != nil {
			return err
		}
	}
	return w.rules(rs.Rules)
}

func addrType(f nft.Family) nftables.SetDatatype {
	if f == nft.IPv4 {
		return nftables.TypeIPAddr
	}
	return nftables.TypeIP6Addr
}

// set returns a set or map by name, for element operations and lookups on
// sets this batch did not create. The name says which it is and its family.
func (w *nftWriter) set(name string) *nftables.Set {
	if s, ok := w.sets[name]; ok {
		return s
	}
	isMap, f := nft.ParseName(name)
	s := &nftables.Set{Table: w.table, Name: name, KeyType: addrType(f)}
	if isMap {
		s = &nftables.Set{Table: w.table, Name: name, IsMap: true, KeyType: nftables.TypeInteger,
			KeyByteOrder: binaryutil.NativeEndian, DataType: addrType(f)}
	}
	w.sets[name] = s
	return s
}

func (w *nftWriter) addMap(m nft.Map) error {
	s := &nftables.Set{
		Table: w.table, Name: m.Name, IsMap: true,
		KeyType: nftables.TypeInteger, KeyByteOrder: binaryutil.NativeEndian, DataType: addrType(m.Family),
	}
	elems := make([]nftables.SetElement, len(m.Slots))
	for i, a := range m.Slots {
		elems[i] = nftables.SetElement{Key: slotKey(i), Val: a.AsSlice()}
	}
	if err := w.c.AddSet(s, elems); err != nil {
		return fmt.Errorf("map %s: %w", m.Name, err)
	}
	w.sets[m.Name] = s
	return nil
}

func (w *nftWriter) addSet(set nft.Set) error {
	s := &nftables.Set{Table: w.table, Name: set.Name, KeyType: addrType(set.Family)}
	if err := w.c.AddSet(s, addrElems(set.Addrs)); err != nil {
		return fmt.Errorf("set %s: %w", set.Name, err)
	}
	w.sets[set.Name] = s
	return nil
}

// slots replaces changed slots: a delete and an add of each element, which
// one batch applies together.
func (w *nftWriter) slots(updates []nft.SlotUpdate) error {
	byMap := map[string][]nft.SlotUpdate{}
	var order []string
	for _, u := range updates {
		if _, ok := byMap[u.Map]; !ok {
			order = append(order, u.Map)
		}
		byMap[u.Map] = append(byMap[u.Map], u)
	}
	for _, name := range order {
		var del, add []nftables.SetElement
		for _, u := range byMap[name] {
			del = append(del, nftables.SetElement{Key: slotKey(u.Slot)})
			add = append(add, nftables.SetElement{Key: slotKey(u.Slot), Val: u.Addr.AsSlice()})
		}
		s := w.set(name)
		if err := w.c.SetDeleteElements(s, del); err != nil {
			return err
		}
		if err := w.c.SetAddElements(s, add); err != nil {
			return err
		}
	}
	return nil
}

// slotKey is numgen's output for a slot: a 32-bit integer in host order.
func slotKey(slot int) []byte {
	return binary.NativeEndian.AppendUint32(nil, uint32(slot))
}

func addrElems(addrs []netip.Addr) []nftables.SetElement {
	out := make([]nftables.SetElement, len(addrs))
	for i, a := range addrs {
		out[i] = nftables.SetElement{Key: a.AsSlice()}
	}
	return out
}

func (w *nftWriter) add(chain string, exprs ...expr.Any) {
	w.c.AddRule(&nftables.Rule{Table: w.table, Chain: w.chains[chain], Exprs: exprs})
}

// rules writes every chain's rules: the fixed ones, then policy's.
func (w *nftWriter) rules(r nft.Rules) error {
	w.add("inbound", append(ifname(expr.MetaKeyIIFNAME, "lo"), accept())...)
	w.add("inbound", append(ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), accept())...)
	// Neighbour discovery, which an egress link needs, is never tracked.
	for _, typ := range []byte{135, 136} {
		w.add("inbound", append(l4(unix.IPPROTO_ICMPV6),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, eq([]byte{typ}), accept())...)
	}
	w.add("inbound", append(ctState(expr.CtStateBitINVALID), drop())...)
	for _, a := range r.Accept {
		set := w.set(a.Set)
		exprs := family(a.Family)
		exprs = append(exprs, addrField(a.Family, true))
		exprs = append(exprs, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID})
		exprs = append(exprs, protoMatch(a.Proto, a.Ports)...)
		w.add("inbound", append(exprs, accept())...)
	}
	for _, t := range r.Translate {
		f := nft.FamilyOf(t.Addr)
		set := w.set(t.Map)
		exprs := family(f)
		exprs = append(exprs, addrField(f, false), eq(t.Addr.AsSlice()))
		exprs = append(exprs, protoMatch(t.Proto, t.Ports)...)
		exprs = append(exprs,
			&expr.Numgen{Register: 1, Modulus: nft.Slots, Type: unix.NFT_NG_RANDOM},
			&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: set.Name, SetID: set.ID},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: natFamily(f), RegAddrMin: 1},
		)
		w.add("services", exprs...)
		if w.forward {
			w.add("services_fwd", exprs...)
		}
	}
	for _, a := range r.Reject {
		f := nft.FamilyOf(a)
		for _, chain := range []string{"untranslated", "untranslated_fwd"} {
			if chain == "untranslated_fwd" && !w.forward {
				continue
			}
			match := append(family(f), addrField(f, false), eq(a.AsSlice()))
			tcp := append(slices.Clone(match), l4(unix.IPPROTO_TCP)...)
			w.add(chain, append(tcp, &expr.Reject{Type: unix.NFT_REJECT_TCP_RST})...)
			w.add(chain, append(match, &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH})...)
		}
	}
	for _, name := range r.Shield {
		if !w.forward {
			break
		}
		set := w.set(name)
		_, f := nft.ParseName(name)
		exprs := append(family(f), ctState(expr.CtStateBitNEW)...)
		exprs = append(exprs, addrField(f, false), &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}, drop())
		w.add("untranslated_fwd", exprs...)
	}
	clamp := append(l4(unix.IPPROTO_TCP),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x06}, Xor: []byte{0}},
		eq([]byte{0x02}),
		&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
		&expr.Exthdr{SourceRegister: 1, Type: 2, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	)
	w.add("clamp", clamp...)
	if w.forward {
		w.add("clamp_fwd", clamp...)
	}
	return nil
}

func accept() expr.Any { return &expr.Verdict{Kind: expr.VerdictAccept} }
func drop() expr.Any   { return &expr.Verdict{Kind: expr.VerdictDrop} }

func eq(data []byte) expr.Any { return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data} }

func natFamily(f nft.Family) uint32 {
	if f == nft.IPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// family matches the packet's family in the inet table.
func family(f nft.Family) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, eq([]byte{byte(natFamily(f))})}
}

// addrField loads the source or destination address into register 1.
func addrField(f nft.Family, source bool) expr.Any {
	off, n := uint32(24), uint32(16)
	switch {
	case f == nft.IPv6 && source:
		off = 8
	case f == nft.IPv4 && source:
		off, n = 12, 4
	case f == nft.IPv4:
		off, n = 16, 4
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n}
}

// l4 matches the transport protocol.
func l4(proto byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, eq([]byte{proto})}
}

// protoMatch matches a policy rule's protocol and ports.
func protoMatch(proto model.Proto, ports model.PortRange) []expr.Any {
	if proto == model.AnyProto {
		return nil
	}
	p := byte(unix.IPPROTO_TCP)
	if proto == model.UDP {
		p = unix.IPPROTO_UDP
	}
	out := l4(p)
	if ports.All() {
		return out
	}
	out = append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
	if ports.Lo == ports.Hi {
		return append(out, eq(binaryutil.BigEndian.PutUint16(ports.Lo)))
	}
	return append(out, &expr.Range{Op: expr.CmpOpEq, Register: 1,
		FromData: binaryutil.BigEndian.PutUint16(ports.Lo), ToData: binaryutil.BigEndian.PutUint16(ports.Hi)})
}

func ifname(key expr.MetaKey, name string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, eq(padIfname(name))}
}

func padIfname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

// ctState matches a packet whose conntrack state has any of bits.
func ctState(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binary.NativeEndian.AppendUint32(nil, bits), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
	}
}
