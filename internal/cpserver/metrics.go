package cpserver

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
}

func newMetrics(reg prometheus.Registerer, h *hub) *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_cp_requests_total", Help: "API requests by route and status.",
		}, []string{"route", "code"}),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sdn_cp_request_seconds", Help: "API request latency by route, long polls included.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 18),
		}, []string{"route"}),
		txs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_cp_store_transactions_total", Help: "Store transactions by operation and result.",
		}, []string{"op", "result"}),
		txLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sdn_cp_store_seconds", Help: "Store transaction latency by operation, retries included.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 18),
		}, []string{"op"}),
		swept: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sdn_cp_swept_interfaces_total", Help: "Interfaces a sweep expired, drained or deleted.",
		}),
		leaseEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_cp_lease_events_total", Help: "Lease transitions by kind.",
		}, []string{"event"}),
		pushed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "sdn_cp_pushes_total", Help: "Long polls answered with a newer generation.",
		}),
		wakeDelay: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "sdn_cp_push_seconds", Help: "Time from a commit waking a long poll to its answer being read.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		}),
	}
	reg.MustRegister(m.requests, m.latency, m.txs, m.txLatency, m.swept, m.leaseEvents, m.pushed, m.wakeDelay,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sdn_cp_polls_open", Help: "Long polls parked, by kind.", ConstLabels: prometheus.Labels{"kind": "host"},
		}, func() float64 { hosts, _ := h.open(); return float64(hosts) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "sdn_cp_polls_open", Help: "Long polls parked, by kind.", ConstLabels: prometheus.Labels{"kind": "relay"},
		}, func() float64 { _, relays := h.open(); return float64(relays) }),
	)
	return m
}

func (m *metrics) observeTx(op string, err error, d time.Duration) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.txs.WithLabelValues(op, result).Inc()
	m.txLatency.WithLabelValues(op).Observe(d.Seconds())
}
