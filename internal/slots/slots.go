//sdn:deterministic

// Package slots assigns a service's fixed slots to its backends.
//
// Each slot goes to the backend with the highest score for that slot, a hash
// of the slot and the backend's identifier: rendezvous hashing, per slot. Any
// two agents given the same backends build the same table, so nothing about
// the table is stored or pushed, and the table moves as little as a backend
// change allows: removing a backend reassigns only its own slots, and adding
// one takes only the slots it now wins.
package slots

import (
	"sdn.sh/internal/model"
)

// Count is every service's slot count, fixed for the service's life.
const Count = 1024

// Assign returns, for each slot, the index into backends of the backend that
// owns it, or nil when there are no backends.
func Assign(backends []model.InterfaceID) []int {
	if len(backends) == 0 {
		return nil
	}
	hashes := make([]uint64, len(backends))
	for i, b := range backends {
		hashes[i] = fnv1a(string(b))
	}
	table := make([]int, Count)
	for slot := range Count {
		best, bestScore := 0, uint64(0)
		for i, h := range hashes {
			score := mix(h ^ (uint64(slot) * 0x9e3779b97f4a7c15))
			if i == 0 || score > bestScore || score == bestScore && backends[i] < backends[best] {
				best, bestScore = i, score
			}
		}
		table[slot] = best
	}
	return table
}

func mix(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func fnv1a(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
