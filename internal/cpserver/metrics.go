package cpserver

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cp"
)

type metrics struct {
	requests    *prometheus.CounterVec
	latency     *prometheus.HistogramVec
	txs         *prometheus.CounterVec
	txLatency   *prometheus.HistogramVec
	swept       prometheus.Counter
	leaseEvents *prometheus.CounterVec
	pushed      prometheus.Counter
	wakeDelay   prometheus.Histogram

	// The census's gauges, and the relays the last census named.
	interfaces  *prometheus.GaugeVec
	quarantine4 prometheus.Gauge
	relayPorts  *prometheus.GaugeVec
	relays      map[string]bool
}

func newMetrics(reg prometheus.Registerer, h *hub) *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wirenet_cp_requests_total", Help: "API requests by route and status.",
		}, []string{"route", "code"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "wirenet_cp_request_seconds", Help: "API request latency by route, long polls included.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 18),
		}, []string{"route"}),
		txs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wirenet_cp_store_transactions_total", Help: "Store transactions by operation and result.",
		}, []string{"op", "result"}),
		txLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "wirenet_cp_store_seconds", Help: "Store transaction latency by operation, retries included.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 18),
		}, []string{"op"}),
		swept: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_cp_swept_interfaces_total", Help: "Interfaces a sweep expired, drained or deleted.",
		}),
		leaseEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wirenet_cp_lease_events_total", Help: "Lease transitions by kind.",
		}, []string{"event"}),
		pushed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_cp_pushes_total", Help: "Long polls answered with a newer generation.",
		}),
		wakeDelay: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "wirenet_cp_push_seconds", Help: "Time from a commit waking a long poll to its answer being read.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		}),
		interfaces: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "wirenet_cp_interfaces", Help: "Interfaces on record by lease state, at the last census.",
		}, []string{"state"}),
		quarantine4: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wirenet_cp_ipv4_quarantined", Help: "Released IPv4 addresses still in quarantine, at the last census.",
		}),
		relayPorts: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "wirenet_cp_relay_ports", Help: "Relay ports by pool: every port a relay offers, those edges hold, and those in quarantine, at the last census.",
		}, []string{"relay", "pool"}),
	}
	reg.MustRegister(m.requests, m.latency, m.txs, m.txLatency, m.swept, m.leaseEvents, m.pushed, m.wakeDelay,
		m.interfaces, m.quarantine4, m.relayPorts,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "wirenet_cp_polls_open", Help: "Long polls parked, by kind.", ConstLabels: prometheus.Labels{"kind": "host"},
		}, func() float64 { hosts, _ := h.open(); return float64(hosts) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "wirenet_cp_polls_open", Help: "Long polls parked, by kind.", ConstLabels: prometheus.Labels{"kind": "relay"},
		}, func() float64 { _, relays := h.open(); return float64(relays) }),
	)
	return m
}

// observeCensus sets the census's gauges, and drops the series of relays it
// no longer names.
func (m *metrics) observeCensus(c cp.Census) {
	for _, st := range []api.LeaseState{api.Live, api.Released, api.Revoked} {
		m.interfaces.WithLabelValues(string(st)).Set(float64(c.Interfaces[st]))
	}
	m.quarantine4.Set(float64(c.IPv4Quarantined))
	named := map[string]bool{}
	for _, r := range c.Relays {
		m.relayPorts.WithLabelValues(r.Name, "capacity").Set(float64(r.Capacity))
		m.relayPorts.WithLabelValues(r.Name, "live").Set(float64(r.Live))
		m.relayPorts.WithLabelValues(r.Name, "quarantined").Set(float64(r.Quarantined))
		named[r.Name] = true
	}
	for name := range m.relays {
		if !named[name] {
			m.relayPorts.DeletePartialMatch(prometheus.Labels{"relay": name})
		}
	}
	m.relays = named
}

func (m *metrics) observeTx(op string, err error, d time.Duration) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.txs.WithLabelValues(op, result).Inc()
	m.txLatency.WithLabelValues(op).Observe(d.Seconds())
}
