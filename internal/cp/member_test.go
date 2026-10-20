package cp

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/mem"
)

// memberAttach is an attach naming a member, with the key the agent keeps.
type memberAttach struct {
	req  api.AttachRequest
	host model.HostID
}

func (f *fixture) memberRequest(host, net, svc, member string, replace bool) memberAttach {
	priv, _ := model.NewPrivateKey(f.rng)
	id, _ := model.NewID(model.InterfacePrefix, f.rng)
	return memberAttach{host: f.host(host), req: api.AttachRequest{
		Interface: model.InterfaceID(id), Network: net, Service: svc, Member: member, Replace: replace,
		PublicKey: priv.Public(), ListenPort: uint16(40000 + f.rng.Below(1000)),
	}}
}

// tryAttach runs an attach and returns what it issued and replaced.
func (f *fixture) tryAttach(a memberAttach) (store.Interface, model.InterfaceID, error) {
	var i store.Interface
	var replaced model.InterfaceID
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		i, replaced, err = f.p.Attach(tx, f.now, a.host, a.req)
		return err
	})
	return i, replaced, err
}

func (f *fixture) member(host, net, svc, member string, replace bool) (store.Interface, model.InterfaceID) {
	f.t.Helper()
	i, replaced, err := f.tryAttach(f.memberRequest(host, net, svc, member, replace))
	if err != nil {
		f.t.Fatalf("attach %s as %s: %v", svc, member, err)
	}
	return i, replaced
}

func (f *fixture) iface(id model.InterfaceID) store.Interface {
	f.t.Helper()
	var i store.Interface
	f.view(func(tx store.ReadTx) error {
		var err error
		i, err = tx.Interface(id)
		return err
	})
	return i
}

func (f *fixture) holder(svc model.ServiceID, member string) (store.Interface, error) {
	var i store.Interface
	err := f.s.View(f.t.Context(), func(tx store.ReadTx) error {
		var err error
		i, err = tx.Holder(svc, member)
		return err
	})
	return i, err
}

func (f *fixture) view(fn func(store.ReadTx) error) {
	f.t.Helper()
	if err := f.s.View(f.t.Context(), fn); err != nil {
		f.t.Fatal(err)
	}
}

func apiCode(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func TestAMemberNameHasOneLiveHolder(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop"})
		etcd := f.service("shop", "etcd", false)
		first, _ := f.member("h1", "shop", "etcd", "etcd-1", false)
		if first.Member != "etcd-1" {
			t.Fatalf("the interface holds %q", first.Member)
		}

		_, _, err := f.tryAttach(f.memberRequest("h2", "shop", "etcd", "etcd-1", false))
		if apiCode(err) != api.CodeConflict || !strings.Contains(err.Error(), string(first.ID)) {
			t.Fatalf("a second attach of a held name: %v, want a conflict naming %s", err, first.ID)
		}
		if h, err := f.holder(etcd.ID, "etcd-1"); err != nil || h.ID != first.ID {
			t.Fatalf("after the conflict the holder is %s, %v", h.ID, err)
		}
		// Another service's member of the same name is its own.
		f.service("shop", "zk", false)
		f.member("h2", "shop", "zk", "etcd-1", false)

		second, replaced := f.member("h2", "shop", "etcd", "etcd-1", true)
		if replaced != first.ID {
			t.Fatalf("replacing returned %q, want %s", replaced, first.ID)
		}
		if old := f.iface(first.ID); old.State != api.Revoked || !old.Drained {
			t.Fatalf("the replaced holder is %s, drained %v; want revoked at once", old.State, old.Drained)
		}
		if h, err := f.holder(etcd.ID, "etcd-1"); err != nil || h.ID != second.ID {
			t.Fatalf("after the replacement the holder is %s, %v", h.ID, err)
		}

		// A replacement with no holder is a plain attach.
		if _, replaced := f.member("h1", "shop", "etcd", "etcd-2", true); replaced != "" {
			t.Fatalf("replacing an unheld name replaced %s", replaced)
		}

		// A release frees the name at once, though the holder drains.
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h2"), []model.InterfaceID{second.ID}) })
		third, replaced := f.member("h1", "shop", "etcd", "etcd-1", false)
		if replaced != "" || f.iface(second.ID).State != api.Released {
			t.Fatalf("attaching after a release replaced %q and left the holder %s", replaced, f.iface(second.ID).State)
		}

		// So does an expired lease.
		f.now = f.now.Add(f.p.Config.LeaseTTL + time.Second)
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now); return err })
		if f.iface(third.ID).State != api.Revoked {
			t.Fatalf("the expired holder is %s", f.iface(third.ID).State)
		}
		f.member("h2", "shop", "etcd", "etcd-1", false)
	})
}

func TestAMemberNameIsALabelAWorkloadHolds(t *testing.T) {
	f := newFixture(t, mem.New())
	f.network(api.CreateNetwork{Name: "shop"})
	f.service("shop", "etcd", false)
	for _, name := range []string{"Etcd-1", "etcd_1", "-etcd", "etcd-", "etcd.1", strings.Repeat("e", 64)} {
		if _, _, err := f.tryAttach(f.memberRequest("h1", "shop", "etcd", name, false)); apiCode(err) != api.CodeInvalid {
			t.Errorf("member %q: %v, want invalid", name, err)
		}
	}
	a := f.memberRequest("h1", "shop", "etcd", "gw", false)
	a.req.Kind = api.Gateway
	if _, _, err := f.tryAttach(a); apiCode(err) != api.CodeInvalid {
		t.Errorf("a gateway member: %v, want invalid", err)
	}
	if _, _, err := f.tryAttach(f.memberRequest("h1", "shop", "etcd", "", true)); apiCode(err) != api.CodeInvalid {
		t.Errorf("a replacement naming no member: %v, want invalid", err)
	}
	f.member("h1", "shop", "etcd", strings.Repeat("e", 63), false)
}

func TestAnAttachRetriedWithReplaceReturnsItsInterface(t *testing.T) {
	f := newFixture(t, mem.New())
	f.network(api.CreateNetwork{Name: "shop"})
	f.service("shop", "etcd", false)
	old, _ := f.member("h1", "shop", "etcd", "etcd-1", false)
	a := f.memberRequest("h2", "shop", "etcd", "etcd-1", true)
	first, replaced, err := f.tryAttach(a)
	if err != nil || replaced != old.ID {
		t.Fatalf("the replacement: %v, replaced %q", err, replaced)
	}
	again, replaced, err := f.tryAttach(a)
	if err != nil || again.ID != first.ID || replaced != "" {
		t.Fatalf("the retry: %s, replaced %q, %v; want %s and nothing replaced", again.ID, replaced, err, first.ID)
	}
	if got := f.iface(first.ID); got.State != api.Live {
		t.Fatalf("the retried replacement left its interface %s", got.State)
	}
	// A retry naming another member is another request.
	a.req.Member, a.req.Replace = "etcd-2", false
	if _, _, err := f.tryAttach(a); apiCode(err) != api.CodeConflict {
		t.Fatalf("a retry naming another member: %v, want a conflict", err)
	}
	a.req.Member = ""
	if _, _, err := f.tryAttach(a); apiCode(err) != api.CodeConflict {
		t.Fatalf("a retry naming no member: %v, want a conflict", err)
	}
}

func TestMembersReachTheStateTheirPeersHold(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.9.0.0/16")})
		etcd := f.service("shop", "etcd", true)
		f.service("shop", "app", false)
		f.rule("shop", "app", "etcd", model.TCP, 2379)
		one, _ := f.member("h1", "shop", "etcd", "etcd-1", false)
		plain, _ := f.attach("h1", "shop", "etcd")
		app, _ := f.attach("h2", "shop", "app")

		var svc *api.Service
		for _, n := range f.state("h2").Networks {
			svc, _ = n.Service(etcd.ID)
		}
		if svc == nil {
			t.Fatal("app's host holds no state for etcd")
		}
		names := map[model.InterfaceID]string{}
		for _, b := range svc.Backends {
			names[b.Interface] = b.Name
		}
		if names[one.ID] != "etcd-1.etcd" || names[plain.ID] != "" || len(names) != 2 {
			t.Fatalf("etcd's backends carry names %v", names)
		}
		for _, n := range f.state("h1").Networks {
			for _, x := range n.Interfaces {
				want := ""
				if x.ID == one.ID {
					want = "etcd-1.etcd"
				}
				if x.Name != want {
					t.Errorf("%s's own name is %q, want %q", x.ID, x.Name, want)
				}
			}
		}
		for _, n := range f.state("h2").Networks {
			if x, ok := n.Interface(app.ID); !ok || x.Name != "" {
				t.Errorf("app's own name: %+v", x)
			}
		}

		// The replaced holder's name leaves with it, for its replacement.
		next, _ := f.member("h2", "shop", "etcd", "etcd-1", true)
		for _, n := range f.state("h1").Networks {
			if x, ok := n.Interface(one.ID); ok && x.Name != "" {
				t.Errorf("the revoked holder still names itself %q", x.Name)
			}
		}
		svc = nil
		for _, n := range f.state("h2").Networks {
			svc, _ = n.Service(etcd.ID)
		}
		if svc == nil {
			t.Fatal("after the replacement, app's host holds no state for etcd")
		}
		names = map[model.InterfaceID]string{}
		for _, b := range svc.Backends {
			names[b.Interface] = b.Name
		}
		if names[next.ID] != "etcd-1.etcd" || names[plain.ID] != "" || len(names) != 2 {
			t.Errorf("after the replacement, etcd's backends carry names %v; want etcd-1.etcd on %s", names, next.ID)
		}
	})
}
