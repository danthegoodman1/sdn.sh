//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// Egress: a workload granted the internet gets a veth pair, eg0 in its
// namespace and wne<index> on the host. The host's table wirenet_egress drops
// what the link must never reach — link-local and metadata addresses,
// private ranges, the host's own prefixes, every relay, and the host
// itself — then applies the link's own grant, reached through a verdict
// map keyed by the link's name, and masquerades what leaves.
const (
	egressTable  = "wirenet_egress"
	egressPrefix = "wne"
	egressNSLink = "eg0"
	egressAlias  = "wirenet-egress:"
)

func egressLink(idx uint16) string { return egressPrefix + strconv.Itoa(int(idx)) }

// egressAddrs derives a link's addresses from its index: a /31 in
// 100.64.0.0/10 and a /127 in fdff:e9e5::/64, the host side first. They
// never leave the host, since everything the link sends is masqueraded.
func egressAddrs(idx uint16) (host4, ns4, host6, ns6 netip.Addr) {
	v := uint32(100)<<24 | uint32(64)<<16 + uint32(idx)*2
	host4 = netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, v)))
	ns4 = netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, v+1)))
	b := [16]byte{0xfd, 0xff, 0xe9, 0xe5, 12: byte(idx >> 8), 13: byte(idx)}
	host6 = netip.AddrFrom16(b)
	b[15] = 1
	ns6 = netip.AddrFrom16(b)
	return
}

// DefaultEgressBlocked is what no egress link may reach whatever the
// host: loopback, link-local and metadata addresses (Azure's WireServer
// among them), private and shared ranges, multicast and reserved space, in
// both families.
func DefaultEgressBlocked() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "168.63.129.16/32", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/127", "::ffff:0:0/96", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// nat64 is the well-known NAT64 prefix (RFC 6052), which embeds an IPv4
// address in its last 32 bits: behind a NAT64 gateway 64:ff9b::a00:5
// reaches 10.0.0.5. The local-use prefix 64:ff9b:1::/48 embeds by the
// operator's choice of length, so it is blocked whole.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// withNAT64 adds, for each IPv4 prefix, the NAT64 prefix that embeds it.
func withNAT64(blocked []netip.Prefix) []netip.Prefix {
	out := slices.Clone(blocked)
	for _, p := range blocked {
		if !p.Addr().Is4() {
			continue
		}
		b := nat64.Addr().As16()
		a4 := p.Addr().As4()
		copy(b[12:], a4[:])
		out = append(out, netip.PrefixFrom(netip.AddrFrom16(b), 96+p.Bits()))
	}
	return out
}

// blockedSet is every prefix the filter drops: the defaults, blocked, and
// their NAT64 forms, each once. blocked may already hold the defaults, as
// the set read back from a running filter does.
func blockedSet(blocked []netip.Prefix) []netip.Prefix {
	all := withNAT64(append(DefaultEgressBlocked(), blocked...))
	for i, p := range all {
		all[i] = p.Masked()
	}
	return slices.Compact(kernel.SortPrefixes(all))
}

// IsEgressAddr reports whether an address belongs to an egress link, which
// the agent creates and the underlay never routes.
func IsEgressAddr(a netip.Addr) bool {
	host4, _, host6, _ := egressAddrs(0)
	return netip.PrefixFrom(host4, 15).Contains(a) || netip.PrefixFrom(host6, 64).Contains(a)
}

// blockedTag marks a rule that drops one blocked prefix; the prefix follows
// it in the rule's comment, so the filter records what it blocks.
const blockedTag = "blocked "

// comment is a rule's user data holding s as the comment nft shows.
func comment(s string) []byte { return userdata.AppendString(nil, userdata.TypeComment, s) }

// ruleComment reads the text a rule records: its comment, or the whole
// user data for a rule an earlier agent tagged with bare text.
func ruleComment(udata []byte) string {
	if len(udata) >= 2 && userdata.Type(udata[0]) == userdata.TypeComment && 2+int(udata[1]) <= len(udata) {
		return strings.TrimSuffix(string(udata[2:2+int(udata[1])]), "\x00")
	}
	return string(udata)
}

// EnsureEgress installs the host's egress table, or refreshes the
// prefixes it blocks, in one transaction that leaves every link's grant in
// place. blocked adds to DefaultEgressBlocked: the host's own prefixes and
// every relay address.
func (k *Kernel) EnsureEgress(blocked []netip.Prefix) error {
	k.egressMu.Lock()
	defer k.egressMu.Unlock()
	c, err := nftables.New(nftables.WithNetNSFd(int(k.root)))
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	t := c.AddTable(&nftables.Table{Name: egressTable, Family: nftables.TableFamilyINet})
	if err := c.AddSet(egressMap(t), nil); err != nil {
		return err
	}
	policy := nftables.ChainPolicyAccept
	fwd := c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &policy})
	in := c.AddChain(&nftables.Chain{Name: "input", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &policy})
	post := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &policy})
	c.FlushChain(fwd)
	c.FlushChain(in)
	c.FlushChain(post)
	add := func(ch *nftables.Chain, exprs ...expr.Any) {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs})
	}
	fromLink := ifnamePrefix(expr.MetaKeyIIFNAME, egressPrefix)
	toLink := ifnamePrefix(expr.MetaKeyOIFNAME, egressPrefix)
	for _, p := range blockedSet(blocked) {
		c.AddRule(&nftables.Rule{Table: t, Chain: fwd, Exprs: concat(fromLink, prefixMatch(p), []expr.Any{drop()}),
			UserData: comment(blockedTag + p.String())})
	}
	add(fwd, concat(fromLink, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: "links", IsDestRegSet: true, DestRegister: 0},
	})...)
	add(fwd, concat(fromLink, []expr.Any{drop()})...)
	add(fwd, concat(toLink, ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), []expr.Any{accept()})...)
	add(fwd, concat(toLink, []expr.Any{drop()})...)
	// The host itself is out of reach, but for the neighbour discovery an
	// IPv6 link needs.
	for _, typ := range []byte{135, 136} {
		add(in, concat(fromLink, l4(unix.IPPROTO_ICMPV6),
			[]expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, eq([]byte{typ}), accept()})...)
	}
	add(in, concat(fromLink, []expr.Any{drop()})...)
	add(post, concat(fromLink, []expr.Any{&expr.Masq{}})...)
	return c.Flush()
}

// EgressBlocked lists the prefixes the installed filter blocks, or none
// when there is no filter, so a restarted agent keeps blocking every relay
// it knew of until desired state names them again.
func (k *Kernel) EgressBlocked() ([]netip.Prefix, error) {
	k.egressMu.Lock()
	defer k.egressMu.Unlock()
	c, err := nftables.New(nftables.WithNetNSFd(int(k.root)))
	if err != nil {
		return nil, err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Name: egressTable, Family: nftables.TableFamilyINet}
	rules, err := c.GetRules(t, &nftables.Chain{Name: "forward", Table: t})
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("egress rules: %w", err)
	}
	var out []netip.Prefix
	for _, r := range rules {
		tag, ok := strings.CutPrefix(ruleComment(r.UserData), blockedTag)
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(tag)
		if err != nil {
			return nil, fmt.Errorf("egress rule %d: %w", r.Handle, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func egressMap(t *nftables.Table) *nftables.Set {
	return &nftables.Set{Table: t, Name: "links", IsMap: true, KeyType: nftables.TypeIFName, DataType: nftables.TypeVerdict}
}

func concat(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ifnamePrefix matches an interface name by its first bytes, as nft's
// "iifname wne*" does.
func ifnamePrefix(key expr.MetaKey, prefix string) []expr.Any {
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, eq([]byte(prefix))}
}

// prefixMatch matches a destination inside a prefix.
func prefixMatch(p netip.Prefix) []expr.Any {
	f, off, n := byte(unix.NFPROTO_IPV6), uint32(24), uint32(16)
	if p.Addr().Is4() {
		f, off, n = unix.NFPROTO_IPV4, 16, 4
	}
	mask := make([]byte, n)
	for i := range p.Bits() {
		mask[i/8] |= 0x80 >> (i % 8)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, eq([]byte{f}),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: n, Mask: mask, Xor: make([]byte, n)},
		eq(p.Addr().AsSlice()),
	}
}

// setEgress installs, changes or removes a namespace's egress link.
func (k *Kernel) setEgress(h *nsHandles, cfg *kernel.EgressConfig) error {
	k.egressMu.Lock()
	defer k.egressMu.Unlock()
	cur, err := k.observeEgress(h)
	if err != nil {
		return err
	}
	if cur != nil && (cfg == nil || cur.Index != cfg.Index) {
		if err := k.removeEgress(cur.Index); err != nil {
			return err
		}
	}
	if cfg == nil {
		// A link left behind with no host side is gone with it; the name
		// may still hold the namespace's end alone after a crash.
		if l, err := h.nl.LinkByName(egressNSLink); err == nil {
			return h.nl.LinkDel(l)
		}
		return nil
	}
	if cur == nil || cur.Index != cfg.Index {
		if err := k.createEgressLink(h, cfg.Index); err != nil {
			return err
		}
	}
	return k.grantEgress(cfg)
}

// createEgressLink makes the veth pair, addresses it and routes the
// namespace's default through it.
func (k *Kernel) createEgressLink(h *nsHandles, idx uint16) error {
	name := egressLink(idx)
	if l, err := k.rootNL.LinkByName(name); err == nil {
		// A stale host side, from a namespace a process still holds.
		if err := k.rootNL.LinkDel(l); err != nil {
			return fmt.Errorf("deleting stale %s: %w", name, err)
		}
	}
	if l, err := h.nl.LinkByName(egressNSLink); err == nil {
		if err := h.nl.LinkDel(l); err != nil {
			return err
		}
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: egressNSLink, PeerNamespace: netlink.NsFd(int(h.fd))}
	if err := k.rootNL.LinkAdd(veth); err != nil {
		return fmt.Errorf("veth %s: %w", name, err)
	}
	host4, ns4, host6, ns6 := egressAddrs(idx)
	hostLink, err := k.rootNL.LinkByName(name)
	if err != nil {
		return err
	}
	nsLink, err := h.nl.LinkByName(egressNSLink)
	if err != nil {
		return err
	}
	if err := h.nl.LinkSetAlias(nsLink, egressAlias+strconv.Itoa(int(idx))); err != nil {
		return err
	}
	for _, a := range []struct {
		nl   *netlink.Handle
		link netlink.Link
		addr netip.Prefix
	}{
		{k.rootNL, hostLink, netip.PrefixFrom(host4, 31)},
		{k.rootNL, hostLink, netip.PrefixFrom(host6, 127)},
		{h.nl, nsLink, netip.PrefixFrom(ns4, 31)},
		{h.nl, nsLink, netip.PrefixFrom(ns6, 127)},
	} {
		addr := &netlink.Addr{IPNet: ipNet(a.addr)}
		if a.addr.Addr().Is6() {
			addr.Flags = unix.IFA_F_NODAD
		}
		if err := a.nl.AddrReplace(a.link, addr); err != nil {
			return fmt.Errorf("address %v: %w", a.addr, err)
		}
	}
	if err := k.rootNL.LinkSetUp(hostLink); err != nil {
		return err
	}
	if err := h.nl.LinkSetUp(nsLink); err != nil {
		return err
	}
	routes := []*netlink.Route{{LinkIndex: nsLink.Attrs().Index, Dst: ipNet(netip.MustParsePrefix("0.0.0.0/0")), Gw: host4.AsSlice()}}
	if k.egress6 {
		routes = append(routes, &netlink.Route{LinkIndex: nsLink.Attrs().Index, Dst: ipNet(netip.MustParsePrefix("::/0")), Gw: host6.AsSlice()})
	}
	for _, r := range routes {
		if err := h.nl.RouteReplace(r); err != nil {
			return fmt.Errorf("egress route %v: %w", r.Dst, err)
		}
	}
	return nil
}

// grantTag marks a rule of a link's grant; the flow it admits follows in
// the rule's comment, so the chain records its own grant.
const grantTag = "grant "

// grantEgress writes the link's grant chain and its map entry.
func (k *Kernel) grantEgress(cfg *kernel.EgressConfig) error {
	c, err := nftables.New(nftables.WithNetNSFd(int(k.root)))
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Name: egressTable, Family: nftables.TableFamilyINet}
	ch := c.AddChain(&nftables.Chain{Name: egressLink(cfg.Index), Table: t})
	c.FlushChain(ch)
	for _, r := range cfg.Rules {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: append(protoMatch(r.Proto, r.Ports), accept()),
			UserData: comment(grantTag + formatRule(r))})
	}
	if err := c.SetAddElements(egressMap(t), []nftables.SetElement{{
		Key: padIfname(egressLink(cfg.Index)), VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: ch.Name},
	}}); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("egress grant %d: %w", cfg.Index, err)
	}
	return nil
}

// egressGrant reads a link's grant back from its chain. A chain that is
// missing holds no rules, so it reads as an empty grant. So does a chain
// holding a rule that records no flow, as an agent that kept the grant in
// the link's alias wrote: no desired grant is empty, so the agent rewrites
// the chain.
func (k *Kernel) egressGrant(idx uint16) ([]kernel.EgressRule, error) {
	c, err := nftables.New(nftables.WithNetNSFd(int(k.root)))
	if err != nil {
		return nil, err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Name: egressTable, Family: nftables.TableFamilyINet}
	rules, err := c.GetRules(t, &nftables.Chain{Name: egressLink(idx), Table: t})
	if err != nil {
		return nil, fmt.Errorf("egress grant %d: %w", idx, err)
	}
	var out []kernel.EgressRule
	for _, r := range rules {
		tag, ok := strings.CutPrefix(ruleComment(r.UserData), grantTag)
		g, err := parseRule(tag)
		if !ok || err != nil {
			return nil, nil
		}
		out = append(out, g)
	}
	return out, nil
}

// removeEgressIndex removes the host's filter and link for an index, when
// one is named.
func (k *Kernel) removeEgressIndex(idx uint16) error {
	if idx == 0 {
		return nil
	}
	k.egressMu.Lock()
	defer k.egressMu.Unlock()
	return k.removeEgress(idx)
}

// removeEgress deletes a link's grant and the link. Each step tolerates
// finding its object gone, so a removal a crash cut short completes.
func (k *Kernel) removeEgress(idx uint16) error {
	c, err := nftables.New(nftables.WithNetNSFd(int(k.root)))
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Name: egressTable, Family: nftables.TableFamilyINet}
	if err := c.SetDeleteElements(egressMap(t), []nftables.SetElement{{Key: padIfname(egressLink(idx))}}); err != nil {
		return err
	}
	if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("egress map entry %d: %w", idx, err)
	}
	ch := &nftables.Chain{Name: egressLink(idx), Table: t}
	c.FlushChain(ch)
	c.DelChain(ch)
	if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("egress chain %d: %w", idx, err)
	}
	l, err := k.rootNL.LinkByName(egressLink(idx))
	switch {
	case notFound(err):
		return nil
	case err != nil:
		return err
	}
	return k.rootNL.LinkDel(l)
}

func notFound(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf)
}

// observeEgress reads a namespace's egress link and its grant.
func (k *Kernel) observeEgress(h *nsHandles) (*kernel.EgressConfig, error) {
	l, err := h.nl.LinkByName(egressNSLink)
	switch {
	case notFound(err):
		return nil, nil
	case err != nil:
		return nil, err
	}
	idx, err := strconv.ParseUint(strings.TrimPrefix(l.Attrs().Alias, egressAlias), 10, 16)
	if err != nil || !strings.HasPrefix(l.Attrs().Alias, egressAlias) {
		return nil, nil
	}
	cfg := &kernel.EgressConfig{Index: uint16(idx)}
	_, err = k.rootNL.LinkByName(egressLink(cfg.Index))
	switch {
	case notFound(err):
		// The host side is gone, so the pair is: nothing to report.
		return nil, nil
	case err != nil:
		return nil, err
	}
	if cfg.Rules, err = k.egressGrant(cfg.Index); err != nil {
		return nil, err
	}
	return cfg, nil
}

// formatRule writes one flow of a grant as "tcp/443-443"; parseRule reads
// it back.
func formatRule(r kernel.EgressRule) string {
	return fmt.Sprintf("%s/%d-%d", r.Proto, r.Ports.Lo, r.Ports.Hi)
}

func parseRule(s string) (kernel.EgressRule, error) {
	proto, ports, ok := strings.Cut(s, "/")
	lo, hi, ok2 := strings.Cut(ports, "-")
	l, err1 := strconv.ParseUint(lo, 10, 16)
	h, err2 := strconv.ParseUint(hi, 10, 16)
	if !ok || !ok2 || err1 != nil || err2 != nil {
		return kernel.EgressRule{}, fmt.Errorf("grant %q", s)
	}
	return kernel.EgressRule{Proto: model.Proto(proto), Ports: model.PortRange{Lo: uint16(l), Hi: uint16(h)}}, nil
}

// EnableForwarding turns on IPv4 forwarding, which egress needs on every
// interface its return traffic arrives on, and reports whether IPv6 egress
// is available: only where the host already forwards IPv6, since turning
// that on would stop the host accepting router advertisements.
func EnableForwarding() (ipv6 bool, err error) {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return false, err
	}
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	return err == nil && strings.TrimSpace(string(b)) == "1", nil
}

// SetEgressIPv6 says whether egress links get an IPv6 default route.
func (k *Kernel) SetEgressIPv6(on bool) { k.egress6 = on }
