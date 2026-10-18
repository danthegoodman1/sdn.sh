package kmodel

import (
	"errors"
	"testing"

	"sdn.sh/internal/kernel"
	"sdn.sh/internal/model"
	"sdn.sh/internal/prng"
)

func run(t *testing.T, k *Kernel, op kernel.Op) {
	t.Helper()
	if _, err := k.Run(op); err != nil {
		t.Fatalf("%s %s: %v", op.Kind, op.Namespace, err)
	}
}

// device creates a namespace holding a device on port.
func device(t *testing.T, k *Kernel, name string, port uint16) {
	t.Helper()
	priv, err := model.NewPrivateKey(prng.New(uint64(port)))
	if err != nil {
		t.Fatal(err)
	}
	run(t, k, kernel.Op{Kind: kernel.CreateNamespace, Namespace: name})
	run(t, k, kernel.Op{Kind: kernel.CreateDevice, Namespace: name, Device: "sdn0",
		Create: &kernel.DeviceConfig{PrivateKey: priv, ListenPort: port, Alias: "sdn:test:" + name}})
}

// TestTheAgentsSocketsHoldANamespaceItsNameNoLongerReaches deletes a
// namespace's name behind the agent and checks that the device keeps its
// port while the workload or the agent's sockets hold it, until the agent
// deletes the namespace or exits.
func TestTheAgentsSocketsHoldANamespaceItsNameNoLongerReaches(t *testing.T) {
	for _, end := range []string{"delete", "exit"} {
		t.Run(end, func(t *testing.T) {
			k := New()
			device(t, k, "a", 7000)
			if !k.Hold("a") {
				t.Fatal("no namespace to hold")
			}
			held, _ := k.Named("a")
			k.Unname("a")
			if _, err := k.Namespace("a", "sdn:test:"); !errors.Is(err, kernel.ErrNoNamespace) {
				t.Fatalf("observing a deleted name: %v", err)
			}
			k.Unhold(held)
			if _, ok := k.PortOwner(7000); !ok {
				t.Fatal("the device went while the agent's sockets held its namespace")
			}
			switch end {
			case "delete":
				run(t, k, kernel.Op{Kind: kernel.DeleteNamespace, Namespace: "a"})
			case "exit":
				k.AgentExit()
			}
			if _, ok := k.PortOwner(7000); ok {
				t.Fatalf("after the agent's %s, the device still holds its port", end)
			}
		})
	}
}

// TestANameOpenedAgainReleasesTheNamespaceItUsedToReach checks that once the
// agent creates a namespace under a name an operator deleted, the old one
// dies with nothing holding it.
func TestANameOpenedAgainReleasesTheNamespaceItUsedToReach(t *testing.T) {
	k := New()
	device(t, k, "a", 7000)
	k.Unname("a")
	device(t, k, "a", 7001)
	if _, ok := k.PortOwner(7000); ok {
		t.Fatal("the namespace the name used to reach outlived the agent opening the new one")
	}
	if _, ok := k.PortOwner(7001); !ok {
		t.Fatal("the new namespace has no device")
	}
}
