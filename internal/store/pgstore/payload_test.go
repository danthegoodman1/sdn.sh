package pgstore

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

func TestPayloadsFitAndCoverTheChange(t *testing.T) {
	big := store.Change{Revision: 1<<63 + 5}
	for i := range 300 {
		big.Networks = append(big.Networks, model.NetworkID(fmt.Sprintf("net-%016d", i)))
		big.Hosts = append(big.Hosts, model.HostID(fmt.Sprintf("host-%016d", i)))
	}
	for i := range 3 {
		big.Relays = append(big.Relays, model.RelayID(fmt.Sprintf("relay-%016d", i)))
	}
	for _, c := range []store.Change{
		{},
		{Revision: 7, Hosts: []model.HostID{"host-a"}},
		big,
	} {
		ps, err := payloads(c)
		if err != nil {
			t.Fatal(err)
		}
		var got store.Change
		for _, p := range ps {
			if len(p) > maxPayload {
				t.Fatalf("payload of %d bytes", len(p))
			}
			var part store.Change
			if err := json.Unmarshal([]byte(p), &part); err != nil {
				t.Fatal(err)
			}
			if part.Revision != c.Revision {
				t.Fatalf("part revision %d, want %d", part.Revision, c.Revision)
			}
			got.Merge(part)
		}
		if got.Revision != c.Revision || !slices.Equal(got.Networks, c.Networks) ||
			!slices.Equal(got.Hosts, c.Hosts) || !slices.Equal(got.Relays, c.Relays) {
			t.Fatalf("%d payloads cover %+v, want %+v", len(ps), got, c)
		}
		if c.Revision == big.Revision && len(ps) < 2 {
			t.Fatalf("a %d-entry change fit one payload", len(c.Networks)+len(c.Hosts)+len(c.Relays))
		}
	}
}
