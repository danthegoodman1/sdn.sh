//sdn:deterministic

package sim

import (
	"time"

	"sdn.sh/internal/prng"
)

// Node names an endpoint of the simulated network: the control plane, a host
// or a relay.
type Node string

// Faults are the network's misbehaviors while faults are on.
type Faults struct {
	LossPercent       uint64
	SpikePercent      uint64
	SpikeMax          time.Duration
	PartitionPermille uint64
	PartitionMax      time.Duration
}

// Network delivers messages between nodes after a delay drawn from the seed,
// and loses them or holds them back during partitions while faults are on.
type Network struct {
	loop     *Loop
	rng      *prng.Rand
	DelayMin time.Duration
	DelayMax time.Duration
	Faults   Faults
	// FaultsOn turns the faults on and off; the liveness phase of a run
	// turns them off.
	FaultsOn bool
	// cut holds, per node, the time its partition heals.
	cut map[Node]time.Time
	// Sent, Lost and Cut count messages by outcome.
	Sent, Lost, Cut uint64
}

// NewNetwork returns a network over loop drawing from rng.
func NewNetwork(loop *Loop, rng *prng.Rand, delayMin, delayMax time.Duration) *Network {
	return &Network{loop: loop, rng: rng, DelayMin: delayMin, DelayMax: delayMax, cut: map[Node]time.Time{}}
}

// Partitioned reports whether n is cut off from everyone now.
func (n *Network) Partitioned(node Node) bool {
	until, ok := n.cut[node]
	return ok && n.loop.Now().Before(until)
}

// Partition cuts node off until d from now.
func (n *Network) Partition(node Node, d time.Duration) {
	until := n.loop.Now().Add(d)
	if cur, ok := n.cut[node]; !ok || cur.Before(until) {
		n.cut[node] = until
	}
}

// Heal ends every partition.
func (n *Network) Heal() {
	n.cut = map[Node]time.Time{}
}

// MaybePartition draws whether to cut node off now, while faults are on.
func (n *Network) MaybePartition(node Node) {
	if n.FaultsOn && n.Faults.PartitionPermille > 0 && n.rng.Permille(n.Faults.PartitionPermille) {
		n.Partition(node, n.rng.Duration(n.Faults.PartitionMax/10, n.Faults.PartitionMax))
	}
}

// Delay draws one message's delay.
func (n *Network) Delay() time.Duration {
	d := n.rng.Duration(n.DelayMin, n.DelayMax)
	if n.FaultsOn && n.Faults.SpikePercent > 0 && n.rng.Percent(n.Faults.SpikePercent) {
		d += n.rng.Duration(0, n.Faults.SpikeMax)
	}
	return d
}

// Send delivers a message from one node to another by calling deliver after
// the network's delay, unless the message is lost or either end is cut off
// at sending or at delivery. It reports whether the message left.
func (n *Network) Send(from, to Node, deliver func()) bool {
	n.Sent++
	if n.Partitioned(from) || n.Partitioned(to) {
		n.Cut++
		return false
	}
	if n.FaultsOn && n.Faults.LossPercent > 0 && n.rng.Percent(n.Faults.LossPercent) {
		n.Lost++
		return false
	}
	n.loop.After(n.Delay(), func() {
		if n.Partitioned(from) || n.Partitioned(to) {
			n.Cut++
			return
		}
		deliver()
	})
	return true
}
