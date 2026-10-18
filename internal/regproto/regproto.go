//sdn:deterministic

// Package regproto is the registration datagram an agent sends a relay to
// claim a direction's endpoint, the acknowledgment the relay sends back once
// it commits one, and the probe an agent uses to tell whether a relay
// answers.
//
// A registration is 32 bytes:
//
//	0:4   magic 0xff 'S' 'D' 'R'
//	4     version 1
//	5:8   zero
//	8:16  counter, big-endian
//	16:32 HMAC-SHA256 over a label, the relay's advertised address and
//	      port, and bytes 0:16, truncated to 16 bytes
//
// WireGuard's messages begin with a type from 1 to 4 followed by three zero
// bytes, so the first byte alone tells a registration from traffic. The MAC
// key is derived per relay from the direction's secret, so a relay holds
// keys that verify registrations for itself and compute none for another
// relay. Covering the advertised address and port stops a registration
// captured at one relay or port from working at another.
package regproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"net/netip"

	"sdn.sh/internal/model"
)

// Sizes of the datagrams.
const (
	Size      = 32
	AckSize   = 16
	ProbeSize = 16
	version   = 1
	macLen    = 16
)

// RelayKey derives one relay's registration key for a direction.
func RelayKey(secret model.Secret, relay model.RelayID) model.Secret {
	m := hmac.New(sha256.New, secret[:])
	m.Write([]byte("sdn relay key v1\x00"))
	m.Write([]byte(relay))
	var k model.Secret
	copy(k[:], m.Sum(nil))
	return k
}

// Encode builds a registration for the relay port advertised, under that
// relay's key for the direction.
func Encode(key model.Secret, advertised netip.AddrPort, counter uint64) [Size]byte {
	var b [Size]byte
	b[0], b[1], b[2], b[3] = 0xff, 'S', 'D', 'R'
	b[4] = version
	binary.BigEndian.PutUint64(b[8:16], counter)
	copy(b[16:], mac(key, advertised, b[:16]))
	return b
}

// IsRegistration reports whether a datagram claims to be a registration.
func IsRegistration(b []byte) bool {
	return len(b) == Size && b[0] == 0xff && b[1] == 'S' && b[2] == 'D' && b[3] == 'R'
}

// Verify checks a registration against a relay's key for the direction and
// the port it arrived on, and returns its counter.
func Verify(key model.Secret, advertised netip.AddrPort, b []byte) (uint64, bool) {
	if !IsRegistration(b) || b[4] != version || b[5]|b[6]|b[7] != 0 {
		return 0, false
	}
	if subtle.ConstantTimeCompare(mac(key, advertised, b[:16]), b[16:]) != 1 {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[8:16]), true
}

func mac(key model.Secret, advertised netip.AddrPort, header []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("sdn registration v1\x00"))
	a16 := advertised.Addr().As16()
	m.Write(a16[:])
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], advertised.Port())
	m.Write(port[:])
	m.Write(header)
	return m.Sum(nil)[:macLen]
}

// Probe builds a probe carrying nonce. A relay answers a probe on its probe
// port with the same 16 bytes, so an answer is never larger than what asked
// for it.
func Probe(nonce uint64) [ProbeSize]byte {
	var b [ProbeSize]byte
	b[0], b[1], b[2], b[3] = 0xff, 'S', 'D', 'P'
	b[4] = version
	binary.BigEndian.PutUint64(b[8:16], nonce)
	return b
}

// ProbeNonce returns a probe's nonce, if b is one.
func ProbeNonce(b []byte) (uint64, bool) {
	if len(b) != ProbeSize || b[0] != 0xff || b[1] != 'S' || b[2] != 'D' || b[3] != 'P' || b[4] != version {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[8:16]), true
}

// Ack builds the acknowledgment a relay sends from a direction's port to the
// endpoint a registration named, once the relay has committed it: magic
// 0xff 'S' 'D' 'A', version 1, three zero bytes and the registration's
// counter. It tells the agent the port is bound and holds its direction.
// It carries no MAC: one forged by an off-path sender can only make an
// agent stop waiting early, which costs a handshake retry and nothing else,
// and it is smaller than the registration that earns it.
func Ack(counter uint64) [AckSize]byte {
	var b [AckSize]byte
	b[0], b[1], b[2], b[3] = 0xff, 'S', 'D', 'A'
	b[4] = version
	binary.BigEndian.PutUint64(b[8:16], counter)
	return b
}

// AckCounter returns an acknowledgment's counter, if b is one.
func AckCounter(b []byte) (uint64, bool) {
	if len(b) != AckSize || b[0] != 0xff || b[1] != 'S' || b[2] != 'D' || b[3] != 'A' || b[4] != version || b[5]|b[6]|b[7] != 0 {
		return 0, false
	}
	return binary.BigEndian.Uint64(b[8:16]), true
}
