//wirenet:deterministic

package model

// RelayWeight ranks relay r for the edge between interfaces a and b. An edge
// sends through the relay of highest weight among those its agent finds up,
// which is rendezvous hashing: both ends compute the same weight whichever
// asks, so they choose the same relay, and a relay that comes or goes moves
// only the edges whose highest weight it holds.
func RelayWeight(a, b InterfaceID, r RelayID) uint64 {
	if b < a {
		a, b = b, a
	}
	// FNV-1a over the three names, each closed by a zero byte, then the
	// SplitMix64 finalizer, which spreads FNV's weak high bits.
	const offset, prime = 14695981039346656037, 1099511628211
	x := uint64(offset)
	for _, s := range [...]string{string(a), string(b), string(r)} {
		for i := 0; i < len(s); i++ {
			x = (x ^ uint64(s[i])) * prime
		}
		x *= prime
	}
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}
