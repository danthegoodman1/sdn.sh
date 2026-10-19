package regproto

import (
	"net/netip"
	"testing"

	"github.com/danthegoodman1/wirenet/internal/model"
)

var (
	secret = model.Secret{1, 2, 3}
	here   = netip.MustParseAddrPort("203.0.113.7:7001")
)

func TestARegistrationVerifiesWhereItWasMeant(t *testing.T) {
	key := RelayKey(secret, "relay-a")
	b := Encode(key, here, 42)
	if !IsRegistration(b[:]) {
		t.Fatal("not recognized as a registration")
	}
	c, withdrawal, ok := Verify(key, here, b[:])
	if !ok || c != 42 || withdrawal {
		t.Fatalf("verify = %d, %v, %v", c, withdrawal, ok)
	}
}

// TestAWithdrawalVerifiesAsOne keeps a withdrawal apart from a claim: the
// kind byte is under the MAC, so neither becomes the other in flight, and
// a relay reads no kind it does not know.
func TestAWithdrawalVerifiesAsOne(t *testing.T) {
	key := RelayKey(secret, "relay-a")
	w := EncodeWithdrawal(key, here, 43)
	if c, withdrawal, ok := Verify(key, here, w[:]); !ok || c != 43 || !withdrawal {
		t.Fatalf("verify = %d, %v, %v", c, withdrawal, ok)
	}
	claim := Encode(key, here, 43)
	turned := claim
	turned[5] = 1
	if _, _, ok := Verify(key, here, turned[:]); ok {
		t.Error("a claim with its kind flipped verified")
	}
	unknown := encode(key, here, 43, 2)
	if _, _, ok := Verify(key, here, unknown[:]); ok {
		t.Error("an unknown kind verified")
	}
}

func TestARegistrationFailsAnywhereElse(t *testing.T) {
	key := RelayKey(secret, "relay-a")
	b := Encode(key, here, 42)
	if _, _, ok := Verify(RelayKey(secret, "relay-b"), here, b[:]); ok {
		t.Error("verified under another relay's key")
	}
	if _, _, ok := Verify(key, netip.MustParseAddrPort("203.0.113.7:7002"), b[:]); ok {
		t.Error("verified at another port")
	}
	if _, _, ok := Verify(key, netip.MustParseAddrPort("203.0.113.8:7001"), b[:]); ok {
		t.Error("verified at another address")
	}
	for i := range Size {
		tampered := b
		tampered[i] ^= 1
		if _, _, ok := Verify(key, here, tampered[:]); ok {
			t.Errorf("verified with byte %d flipped", i)
		}
	}
	if _, _, ok := Verify(key, here, b[:Size-1]); ok {
		t.Error("verified a short datagram")
	}
}

func TestWireGuardTrafficIsNeverARegistration(t *testing.T) {
	for typ := byte(1); typ <= 4; typ++ {
		b := make([]byte, Size)
		b[0] = typ
		if IsRegistration(b) {
			t.Errorf("WireGuard type %d read as a registration", typ)
		}
	}
}

func TestProbeRoundTrips(t *testing.T) {
	p := Probe(99)
	if n, ok := ProbeNonce(p[:]); !ok || n != 99 {
		t.Fatalf("nonce %d, %v", n, ok)
	}
	reg := Encode(model.Secret{}, here, 1)
	if _, ok := ProbeNonce(reg[:ProbeSize]); ok {
		t.Fatal("a registration's head read as a probe")
	}
}

func TestAnAckRoundTripsAndIsNothingElse(t *testing.T) {
	a := Ack(1792320666820)
	if n, ok := AckCounter(a[:]); !ok || n != 1792320666820 {
		t.Fatalf("counter %d, %v", n, ok)
	}
	if IsRegistration(a[:]) {
		t.Fatal("an ack read as a registration")
	}
	if _, ok := ProbeNonce(a[:]); ok {
		t.Fatal("an ack read as a probe")
	}
	p := Probe(7)
	reg := Encode(model.Secret{}, here, 7)
	for _, b := range [][]byte{p[:], reg[:AckSize], reg[:]} {
		if _, ok := AckCounter(b); ok {
			t.Fatalf("%x read as an ack", b)
		}
	}
	if AckSize > Size {
		t.Fatal("an ack outgrows the registration that earns it")
	}
}
