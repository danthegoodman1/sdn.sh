//sdn:deterministic

package sim

import (
	"fmt"
	"time"

	"sdn.sh/internal/prng"
)

// Options configure one run. Swarm draws them from the seed, so one seed
// fixes the topology, the workload and the faults.
type Options struct {
	Hosts, Relays, Networks int
	// Services per network, the share that opt into IPv4, and the chance
	// any ordered pair of services gets a rule.
	Services, IPv4Percent, RulePercent int
	// CutoverPercent of services evict connections on removal.
	CutoverPercent int

	// FaultTime is how long the orchestrator changes things while faults
	// happen; Quiesce is how long the system then runs fault-free before
	// the liveness checks.
	FaultTime, Quiesce time.Duration
	// ChangeEvery is the mean time between orchestrator changes.
	ChangeEvery time.Duration
	// MaxAttached bounds live interfaces at once.
	MaxAttached int

	// CPDelay and UnderlayDelay bound one-way message delays.
	CPDelayMin, CPDelayMax             time.Duration
	UnderlayDelayMin, UnderlayDelayMax time.Duration
	// OpDelayMax bounds one kernel operation's duration.
	OpDelayMax time.Duration

	// Faults, while on.
	LossPercent        uint64
	PartitionPermille  uint64
	PartitionMax       time.Duration
	AgentCrashPermille uint64 // per kernel operation
	OpFailPermille     uint64 // per kernel operation
	RelayCrashPermille uint64 // per second per relay
	CPCrashPermille    uint64 // per second
	RebootPermille     uint64 // per second per host
	NATRebindPermille  uint64 // per second per host
	StrayPermille      uint64 // per detach: a stray process keeps the namespace
	ForeignPorts       int    // listen ports other software holds per host
	// Attacker sends to relay ports and replays registrations it saw.
	Attacker bool
}

// Swarm draws a run's options from its seed.
func Swarm(seed uint64) Options {
	r := prng.Stream(seed, "options")
	o := Options{
		Hosts:            int(r.Range(2, 4)),
		Relays:           int(r.Range(1, 3)),
		Networks:         int(r.Range(1, 2)),
		Services:         int(r.Range(2, 4)),
		IPv4Percent:      int(r.Below(101)),
		RulePercent:      int(r.Range(20, 80)),
		CutoverPercent:   int(r.Below(40)),
		FaultTime:        time.Duration(r.Range(20, 40)) * time.Second,
		Quiesce:          40 * time.Second,
		ChangeEvery:      time.Duration(r.Range(100, 800)) * time.Millisecond,
		MaxAttached:      int(r.Range(4, 16)),
		CPDelayMin:       time.Millisecond,
		CPDelayMax:       time.Duration(r.Range(2, 30)) * time.Millisecond,
		UnderlayDelayMin: 100 * time.Microsecond,
		UnderlayDelayMax: time.Duration(r.Range(1, 20)) * time.Millisecond,
		OpDelayMax:       time.Duration(r.Range(1, 5)) * time.Millisecond,
	}
	if r.Percent(80) {
		o.LossPercent = r.Below(10)
		o.PartitionPermille = r.Below(10)
		o.PartitionMax = time.Duration(r.Range(1, 8)) * time.Second
		o.AgentCrashPermille = r.Below(20)
		o.OpFailPermille = r.Below(30)
		o.RelayCrashPermille = r.Below(30)
		o.CPCrashPermille = r.Below(20)
		o.RebootPermille = r.Below(5)
		o.NATRebindPermille = r.Below(30)
		o.StrayPermille = r.Below(300)
		o.ForeignPorts = int(r.Below(4))
		o.Attacker = r.Percent(50)
	}
	return o
}

func (o Options) String() string {
	return fmt.Sprintf("hosts=%d relays=%d networks=%d services=%d ipv4=%d%% rules=%d%% faults=%v+%v loss=%d%% partition=%d‰ crash=%d‰/op opfail=%d‰ relaycrash=%d‰ cpcrash=%d‰ reboot=%d‰ rebind=%d‰ stray=%d‰ foreign=%d attacker=%v",
		o.Hosts, o.Relays, o.Networks, o.Services, o.IPv4Percent, o.RulePercent, o.FaultTime, o.Quiesce,
		o.LossPercent, o.PartitionPermille, o.AgentCrashPermille, o.OpFailPermille, o.RelayCrashPermille,
		o.CPCrashPermille, o.RebootPermille, o.NATRebindPermille, o.StrayPermille, o.ForeignPorts, o.Attacker)
}
