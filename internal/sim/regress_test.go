package sim

import "testing"

func runSeed(t *testing.T, seed uint64) {
	t.Helper()
	if _, err := New(seed).Run(); err != nil {
		t.Fatal(err)
	}
}

// Seed 70: an attach answer delivered a network at revision 31, then a poll
// answer computed before the attach arrived without it, and the agent
// dropped the network and every peer in it.
func TestAPollOlderThanAnAttachKeepsItsNetwork(t *testing.T) { runSeed(t, 70) }

// Seed 6: a revoked interface's records were purged, so its host held no
// state for the network, and its namespace never counted as settled.
func TestARevokedAndForgottenInterfaceSettles(t *testing.T) { runSeed(t, 6) }

// Seed 113: an agent restarted mid-detach and finished it alone; the
// orchestrator's retry then waited on a reply already sent.
func TestADetachRetriedAfterItFinishedIsAnswered(t *testing.T) { runSeed(t, 113) }

// Seed 3: an agent crashed between building an interface and answering, and
// a retried attach built a second one; attaches now name their workload.
func TestARetriedAttachReturnsTheSameInterface(t *testing.T) { runSeed(t, 3) }

// Seed 2: a release the control plane missed was never sent again, so the
// interface stayed half torn down.
func TestAFailedReleaseIsRetried(t *testing.T) { runSeed(t, 2) }

// Seed 8: the kernel reports allowed IPs IPv4 first and desired state lists
// IPv6 first, so every resync rewrote every peer.
func TestAResyncFindsNoDriftInPrefixOrder(t *testing.T) { runSeed(t, 8) }

// Seed 6135: a pair lost and regained policy while one host lagged; its
// packets through the old edge's ports roamed the other side onto a port
// the relay then dropped, stranding the peer. A disconnected pair now keeps
// its edge, dormant, for the port quarantine.
func TestAPairThatReconnectsKeepsItsEdge(t *testing.T) { runSeed(t, 6135) }
