//wirenet:deterministic

// Package prng is the seeded random source every deterministic package draws
// from. It lives in this module so a recorded seed replays the same run after
// any dependency or toolchain upgrade.
package prng

import (
	"math/bits"
	"time"
)

// Rand is xoshiro256**, seeded through SplitMix64.
type Rand struct {
	s [4]uint64
}

// New returns a generator seeded with seed.
func New(seed uint64) *Rand {
	mix := seed
	var r Rand
	for i := range r.s {
		r.s[i] = SplitMix64(&mix)
	}
	return &r
}

// Stream returns a generator for one purpose, independent of every other
// purpose's stream under the same seed, so drawing more numbers for one
// purpose leaves the others' draws unchanged.
func Stream(seed uint64, purpose string) *Rand {
	return New(seed ^ fnv1a(purpose))
}

// Fork returns a new stream for purpose, seeded from this generator's next
// draw.
func (r *Rand) Fork(purpose string) *Rand {
	return Stream(r.Uint64(), purpose)
}

// Uint64 returns the next value.
func (r *Rand) Uint64() uint64 {
	s := &r.s
	result := rotl(s[1]*5, 7) * 9
	t := s[1] << 17
	s[2] ^= s[0]
	s[3] ^= s[1]
	s[1] ^= s[2]
	s[0] ^= s[3]
	s[2] ^= t
	s[3] = rotl(s[3], 45)
	return result
}

// Below returns a uniform value in [0, n). It panics if n is zero.
func (r *Rand) Below(n uint64) uint64 {
	if n == 0 {
		panic("prng: Below(0)")
	}
	// Lemire's method: reject the few products that would bias the result.
	threshold := -n % n
	for {
		hi, lo := bits.Mul64(r.Uint64(), n)
		if lo >= threshold {
			return hi
		}
	}
}

// Range returns a uniform value in [lo, hi].
func (r *Rand) Range(lo, hi uint64) uint64 {
	return lo + r.Below(hi-lo+1)
}

// Index returns a uniform index into a slice of length n.
func (r *Rand) Index(n int) int {
	return int(r.Below(uint64(n)))
}

// Percent reports true p times in a hundred.
func (r *Rand) Percent(p uint64) bool {
	return r.Below(100) < p
}

// Permille reports true p times in a thousand.
func (r *Rand) Permille(p uint64) bool {
	return r.Below(1000) < p
}

// Duration returns a uniform duration in [lo, hi].
func (r *Rand) Duration(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(r.Below(uint64(hi-lo)+1))
}

// Read fills b, so a generator serves as the io.Reader a core mints keys
// and secrets from.
func (r *Rand) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i += 8 {
		v := r.Uint64()
		for j := 0; j < 8 && i+j < len(b); j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
	return len(b), nil
}

// SplitMix64 advances state and returns the next SplitMix64 output.
func SplitMix64(state *uint64) uint64 {
	*state += 0x9e3779b97f4a7c15
	z := *state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func rotl(x uint64, k uint) uint64 {
	return (x << k) | (x >> (64 - k))
}

func fnv1a(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
