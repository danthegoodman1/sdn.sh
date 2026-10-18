//sdn:deterministic

// Package dns decides what the stub resolver answers. A workload's
// resolver answers the names of the services its interface may reach, in
// its network's domain, from pushed state: AAAA for every service, and A
// only where both the client's service and the target have IPv4, so no
// client receives an address it cannot reach. Names outside the domain go
// upstream when the interface may reach the internet, and are refused
// otherwise.
package dns

import (
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"sdn.sh/internal/api"
)

// TTL is how long a client may cache an answer, in seconds. Reachability
// changes with policy, so answers stay short-lived.
const TTL = 5

// ListenAddr is where every workload's resolver listens, inside its
// namespace.
func ListenAddr() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 53}), 53)
}

// Zone is what one namespace's resolver answers.
type Zone struct {
	// Domain is the network's domain, a lowercase FQDN with a trailing dot.
	Domain string
	// Names holds each reachable service's addresses, sorted by FQDN.
	Names []Name
	// Forward sends names outside the domain upstream.
	Forward bool
}

// Served is a zone and the addresses beyond 127.0.0.53 it answers on: a
// gateway's own, for its development machines.
type Served struct {
	Zone  Zone
	Addrs []netip.Addr
}

// ServedFor builds what one interface's namespace serves.
func ServedFor(n *api.NetworkState, x *api.Interface) Served {
	s := Served{Zone: ZoneFor(n, x)}
	if x.Kind == api.Gateway {
		s.Addrs = x.Addrs()
	}
	return s
}

// Name is one service's addresses. A is zero when the client must not
// receive one.
type Name struct {
	FQDN string
	AAAA netip.Addr
	A    netip.Addr
}

// ZoneFor builds the zone for one interface of a network.
func ZoneFor(n *api.NetworkState, x *api.Interface) Zone {
	// A gateway forwards for the development machines it serves, which
	// use it as their only resolver.
	z := Zone{Domain: strings.ToLower(n.Domain()) + ".", Forward: len(x.Egress) > 0 || x.Kind == api.Gateway}
	for _, r := range x.Reach {
		s, ok := n.Service(r.Service)
		if !ok {
			continue
		}
		name := Name{FQDN: strings.ToLower(s.Name) + "." + z.Domain, AAAA: s.Addr6}
		if x.Addr4.IsValid() && s.Addr4.IsValid() {
			name.A = s.Addr4
		}
		z.Names = append(z.Names, name)
	}
	slices.SortFunc(z.Names, func(a, b Name) int { return strings.Compare(a.FQDN, b.FQDN) })
	z.Names = slices.CompactFunc(z.Names, func(a, b Name) bool { return a.FQDN == b.FQDN })
	return z
}

// Verdict is what to do with a query.
type Verdict int

const (
	// Reply sends the response back.
	Reply Verdict = iota
	// Forward sends the query upstream and relays its answer.
	Forward
	// Ignore drops a datagram that is not a query.
	Ignore
)

// Answer decides one query. For Reply it returns the response to send.
func (z *Zone) Answer(query []byte) (Verdict, []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return Ignore, nil
	}
	q, err := p.Question()
	if err != nil {
		return Reply, respond(h, nil, dnsmessage.RCodeFormatError, nil)
	}
	if h.OpCode != 0 {
		return Reply, respond(h, &q, dnsmessage.RCodeNotImplemented, nil)
	}
	name := strings.ToLower(q.Name.String())
	if name != z.Domain && !strings.HasSuffix(name, "."+z.Domain) {
		if z.Forward {
			return Forward, nil
		}
		return Reply, respond(h, &q, dnsmessage.RCodeRefused, nil)
	}
	i, found := slices.BinarySearchFunc(z.Names, name, func(n Name, s string) int { return strings.Compare(n.FQDN, s) })
	if !found {
		return Reply, respond(h, &q, dnsmessage.RCodeNameError, nil)
	}
	n := z.Names[i]
	var answers []dnsmessage.Resource
	hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: TTL}
	switch q.Type {
	case dnsmessage.TypeAAAA:
		hdr.Type = dnsmessage.TypeAAAA
		answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: n.AAAA.As16()}})
	case dnsmessage.TypeA:
		if n.A.IsValid() {
			hdr.Type = dnsmessage.TypeA
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: n.A.As4()}})
		}
	case dnsmessage.TypeALL:
		hdr.Type = dnsmessage.TypeAAAA
		answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: n.AAAA.As16()}})
		if n.A.IsValid() {
			hdr.Type = dnsmessage.TypeA
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: n.A.As4()}})
		}
	}
	// A name with no record of the asked type answers with no records,
	// which tells the client the name exists.
	return Reply, respond(h, &q, dnsmessage.RCodeSuccess, answers)
}

func respond(h dnsmessage.Header, q *dnsmessage.Question, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: h.ID, Response: true, Authoritative: rcode == dnsmessage.RCodeSuccess || rcode == dnsmessage.RCodeNameError,
			RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode,
		},
		Answers: answers,
	}
	if q != nil {
		m.Questions = []dnsmessage.Question{*q}
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}
