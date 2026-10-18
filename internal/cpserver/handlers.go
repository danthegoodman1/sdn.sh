package cpserver

import (
	"net/http"
	"strconv"
	"time"

	"sdn.sh/internal/api"
	"sdn.sh/internal/cp"
	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

// The operator's API.

func (s *Server) createNetwork(r *http.Request, _ principal) (any, error) {
	req, err := decode[api.CreateNetwork](r)
	if err != nil {
		return nil, err
	}
	var n store.Network
	if _, err := s.update(r.Context(), "create_network", func(tx store.Tx) error {
		n, err = s.plane.CreateNetwork(tx, s.now(), req)
		return err
	}); err != nil {
		return nil, err
	}
	s.log.Info().Str("network", string(n.ID)).Str("name", n.Name).Stringer("prefix6", n.Prefix6).Msg("network created")
	return networkInfo(n), nil
}

func (s *Server) listNetworks(r *http.Request, _ principal) (any, error) {
	var out []api.Network
	err := s.view(r.Context(), "list_networks", func(tx store.ReadTx) error {
		nets, err := tx.Networks()
		out = make([]api.Network, 0, len(nets))
		for _, n := range nets {
			out = append(out, networkInfo(n))
		}
		return err
	})
	return out, err
}

func (s *Server) getNetwork(r *http.Request, _ principal) (any, error) {
	var out api.Network
	err := s.view(r.Context(), "get_network", func(tx store.ReadTx) error {
		n, err := cp.ResolveNetwork(tx, r.PathValue("net"))
		out = networkInfo(n)
		return err
	})
	return out, err
}

func (s *Server) deleteNetwork(r *http.Request, _ principal) (any, error) {
	_, err := s.update(r.Context(), "delete_network", func(tx store.Tx) error {
		return s.plane.DeleteNetwork(tx, r.PathValue("net"))
	})
	if err == nil {
		s.log.Info().Str("network", r.PathValue("net")).Msg("network deleted")
	}
	return nil, err
}

func (s *Server) createService(r *http.Request, _ principal) (any, error) {
	req, err := decode[api.CreateService](r)
	if err != nil {
		return nil, err
	}
	var svc store.Service
	if _, err := s.update(r.Context(), "create_service", func(tx store.Tx) error {
		svc, err = s.plane.CreateService(tx, s.now(), r.PathValue("net"), req)
		return err
	}); err != nil {
		return nil, err
	}
	s.log.Info().Str("network", string(svc.Network)).Str("service", string(svc.ID)).Str("name", svc.Name).
		Stringer("addr6", svc.Addr6).Msg("service created")
	return serviceInfo(svc), nil
}

func (s *Server) listServices(r *http.Request, _ principal) (any, error) {
	var out []api.ServiceInfo
	err := s.view(r.Context(), "list_services", func(tx store.ReadTx) error {
		n, err := cp.ResolveNetwork(tx, r.PathValue("net"))
		if err != nil {
			return err
		}
		svcs, err := tx.Services(n.ID)
		out = make([]api.ServiceInfo, 0, len(svcs))
		for _, svc := range svcs {
			out = append(out, serviceInfo(svc))
		}
		return err
	})
	return out, err
}

func (s *Server) deleteService(r *http.Request, _ principal) (any, error) {
	_, err := s.update(r.Context(), "delete_service", func(tx store.Tx) error {
		return s.plane.DeleteService(tx, s.now(), r.PathValue("net"), r.PathValue("svc"))
	})
	if err == nil {
		s.log.Info().Str("network", r.PathValue("net")).Str("service", r.PathValue("svc")).Msg("service deleted")
	}
	return nil, err
}

func (s *Server) createRule(r *http.Request, _ principal) (any, error) {
	req, err := decode[api.CreateRule](r)
	if err != nil {
		return nil, err
	}
	var rule store.Rule
	if _, err := s.update(r.Context(), "create_rule", func(tx store.Tx) error {
		rule, err = s.plane.CreateRule(tx, s.now(), r.PathValue("net"), req)
		return err
	}); err != nil {
		return nil, err
	}
	s.log.Info().Str("network", string(rule.Network)).Str("rule", string(rule.ID)).Str("from", req.From).Str("to", req.To).Msg("rule created")
	return ruleInfo(rule), nil
}

func (s *Server) listRules(r *http.Request, _ principal) (any, error) {
	var out []api.Rule
	err := s.view(r.Context(), "list_rules", func(tx store.ReadTx) error {
		n, err := cp.ResolveNetwork(tx, r.PathValue("net"))
		if err != nil {
			return err
		}
		rules, err := tx.Rules(n.ID)
		out = make([]api.Rule, 0, len(rules))
		for _, rule := range rules {
			out = append(out, ruleInfo(rule))
		}
		return err
	})
	return out, err
}

func (s *Server) deleteRule(r *http.Request, _ principal) (any, error) {
	_, err := s.update(r.Context(), "delete_rule", func(tx store.Tx) error {
		return s.plane.DeleteRule(tx, s.now(), r.PathValue("net"), model.RuleID(r.PathValue("rule")))
	})
	if err == nil {
		s.log.Info().Str("network", r.PathValue("net")).Str("rule", r.PathValue("rule")).Msg("rule deleted")
	}
	return nil, err
}

func (s *Server) listInterfaces(r *http.Request, _ principal) (any, error) {
	var out []api.InterfaceInfo
	err := s.view(r.Context(), "list_interfaces", func(tx store.ReadTx) error {
		n, err := cp.ResolveNetwork(tx, r.PathValue("net"))
		if err != nil {
			return err
		}
		ifaces, err := tx.Interfaces(n.ID)
		out = make([]api.InterfaceInfo, 0, len(ifaces))
		for _, i := range ifaces {
			out = append(out, interfaceInfo(i))
		}
		return err
	})
	return out, err
}

func (s *Server) revoke(r *http.Request, _ principal) (any, error) {
	id := model.InterfaceID(r.PathValue("id"))
	_, err := s.update(r.Context(), "revoke", func(tx store.Tx) error { return s.plane.Revoke(tx, s.now(), id) })
	if err == nil {
		s.m.leaseEvents.WithLabelValues("revoked").Inc()
		s.log.Info().Str("interface", string(id)).Msg("interface revoked")
	}
	return nil, err
}

func (s *Server) createHost(r *http.Request, _ principal) (any, error) {
	req, err := decode[api.CreateHost](r)
	if err != nil {
		return nil, err
	}
	var h store.Host
	var token string
	if _, err := s.update(r.Context(), "create_host", func(tx store.Tx) error {
		h, token, err = s.plane.CreateHost(tx, s.now(), req)
		return err
	}); err != nil {
		return nil, err
	}
	s.log.Info().Str("host", string(h.ID)).Str("name", h.Name).Msg("host registered")
	return api.Credentials{ID: string(h.ID), Token: token}, nil
}

func (s *Server) createRelay(r *http.Request, _ principal) (any, error) {
	req, err := decode[api.CreateRelay](r)
	if err != nil {
		return nil, err
	}
	var rl store.Relay
	var token string
	if _, err := s.update(r.Context(), "create_relay", func(tx store.Tx) error {
		rl, token, err = s.plane.CreateRelay(tx, s.now(), req)
		return err
	}); err != nil {
		return nil, err
	}
	s.log.Info().Str("relay", string(rl.ID)).Str("name", rl.Name).Msg("relay registered")
	return api.Credentials{ID: string(rl.ID), Token: token}, nil
}

func (s *Server) listRelays(r *http.Request, _ principal) (any, error) {
	var out []api.RelayInfo
	err := s.view(r.Context(), "list_relays", func(tx store.ReadTx) error {
		relays, err := tx.Relays()
		out = make([]api.RelayInfo, 0, len(relays))
		for _, rl := range relays {
			out = append(out, api.RelayInfo{
				ID: rl.ID, Name: rl.Name, Addresses: rl.Addresses,
				PortLo: rl.PortLo, PortHi: rl.PortHi, ProbePort: rl.ProbePort, Revision: rl.Revision,
			})
		}
		return err
	})
	return out, err
}

// The agents' API.

func (s *Server) attach(r *http.Request, p principal) (any, error) {
	req, err := decode[api.AttachRequest](r)
	if err != nil {
		return nil, err
	}
	var resp api.AttachResponse
	if _, err := s.update(r.Context(), "attach", func(tx store.Tx) error {
		iface, err := s.plane.Attach(tx, s.now(), p.host, req)
		if err != nil {
			return err
		}
		resp.Interface = iface.ID
		return nil
	}); err != nil {
		return nil, err
	}
	// The answer is read after the commit, so it carries the revision the
	// attach made.
	if err := s.view(r.Context(), "attach_state", func(tx store.ReadTx) error {
		iface, err := tx.Interface(resp.Interface)
		if err != nil {
			return err
		}
		resp.State, err = cp.NetworkStateFor(tx, s.cache, iface.Network, p.host)
		return err
	}); err != nil {
		return nil, err
	}
	s.m.leaseEvents.WithLabelValues("attached").Inc()
	s.log.Info().Str("host", string(p.host)).Str("interface", string(resp.Interface)).Str("network", string(resp.State.Network)).
		Str("service", req.Service).Uint64("revision", resp.State.Revision).Msg("interface attached")
	return resp, nil
}

func (s *Server) release(r *http.Request, p principal) (any, error) {
	req, err := decode[api.ReleaseRequest](r)
	if err != nil {
		return nil, err
	}
	if _, err := s.update(r.Context(), "release", func(tx store.Tx) error {
		return s.plane.Release(tx, s.now(), p.host, req.Interfaces)
	}); err != nil {
		return nil, err
	}
	s.m.leaseEvents.WithLabelValues("released").Add(float64(len(req.Interfaces)))
	s.log.Info().Str("host", string(p.host)).Strs("interfaces", ids(req.Interfaces)).Msg("interfaces released")
	return nil, nil
}

func (s *Server) renew(r *http.Request, p principal) (any, error) {
	req, err := decode[api.RenewRequest](r)
	if err != nil {
		return nil, err
	}
	var resp api.RenewResponse
	if _, err := s.update(r.Context(), "renew", func(tx store.Tx) error {
		resp.Expires, err = s.plane.Renew(tx, s.now(), p.host, req.Interfaces)
		return err
	}); err != nil {
		return nil, err
	}
	s.m.leaseEvents.WithLabelValues("renewed").Add(float64(len(resp.Expires)))
	return resp, nil
}

// hostPoll answers as soon as the host's generation passes since, or with
// what is current once the poll timeout passes.
func (s *Server) hostPoll(r *http.Request, p principal) (any, error) {
	since, err := sinceParam(r)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(s.cfg.PollTimeout)
	defer deadline.Stop()
	var nets []model.NetworkID
	for {
		w := s.hub.watchHost(p.host, nets)
		var u api.StateUpdate
		var gen uint64
		err := s.view(r.Context(), "host_state", func(tx store.ReadTx) error {
			var held []store.Network
			var err error
			gen, held, err = cp.HostGeneration(tx, p.host)
			if err != nil {
				return err
			}
			nets = nets[:0]
			for _, n := range held {
				nets = append(nets, n.ID)
			}
			if gen > since {
				u, err = cp.HostState(tx, s.cache, p.host, since)
			}
			return err
		})
		if err != nil || gen > since {
			s.hub.cancel(w)
			if err == nil {
				s.m.pushed.Inc()
			}
			return u, err
		}
		if !sameNets(w.nets, nets) {
			// The host joined or left a network since the waiter was
			// registered; watch the networks it holds now.
			s.hub.cancel(w)
			continue
		}
		select {
		case <-w.ch:
			s.m.wakeDelay.Observe(time.Since(w.at).Seconds())
		case <-deadline.C:
			s.hub.cancel(w)
			var u api.StateUpdate
			err := s.view(r.Context(), "host_state", func(tx store.ReadTx) error {
				var err error
				u, err = cp.HostState(tx, s.cache, p.host, since)
				return err
			})
			return u, err
		case <-r.Context().Done():
			s.hub.cancel(w)
			return nil, r.Context().Err()
		}
	}
}

func (s *Server) relayPoll(r *http.Request, p principal) (any, error) {
	since, err := sinceParam(r)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(s.cfg.PollTimeout)
	defer deadline.Stop()
	for {
		w := s.hub.watchRelay(p.relay)
		var st api.RelayState
		var fresh bool
		err := s.view(r.Context(), "relay_state", func(tx store.ReadTx) error {
			rl, err := tx.Relay(p.relay)
			if err != nil {
				return err
			}
			fresh = rl.Revision > since || since == 0
			st, err = cp.RelayState(tx, p.relay)
			return err
		})
		if err != nil || fresh {
			s.hub.cancel(w)
			return st, err
		}
		select {
		case <-w.ch:
		case <-deadline.C:
			s.hub.cancel(w)
			return st, nil
		case <-r.Context().Done():
			s.hub.cancel(w)
			return nil, r.Context().Err()
		}
	}
}

func sinceParam(r *http.Request) (uint64, error) {
	v := r.URL.Query().Get("since")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, &api.Error{Code: api.CodeInvalid, Message: "since must be a generation"}
	}
	return n, nil
}

func sameNets(a, b []model.NetworkID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ids(in []model.InterfaceID) []string {
	out := make([]string, len(in))
	for i, id := range in {
		out[i] = string(id)
	}
	return out
}

func networkInfo(n store.Network) api.Network {
	return api.Network{ID: n.ID, Name: n.Name, Prefix6: n.Prefix6, Prefix4: n.Prefix4, MTU: n.MTU, Relays: n.Relays, Revision: n.Revision}
}

func serviceInfo(s store.Service) api.ServiceInfo {
	return api.ServiceInfo{ID: s.ID, Network: s.Network, Name: s.Name, Addr6: s.Addr6, Addr4: s.Addr4, Mode: s.Mode}
}

func ruleInfo(r store.Rule) api.Rule {
	return api.Rule{ID: r.ID, Network: r.Network, From: r.From, To: r.To, Proto: r.Proto, Ports: r.Ports}
}

func interfaceInfo(i store.Interface) api.InterfaceInfo {
	return api.InterfaceInfo{
		ID: i.ID, Network: i.Network, Service: i.Service, Host: i.Host, Kind: i.Kind, PublicKey: i.PublicKey,
		Addr6: i.Addr6, Addr4: i.Addr4, ListenPort: i.ListenPort, State: i.State, Expires: i.Expires,
	}
}
