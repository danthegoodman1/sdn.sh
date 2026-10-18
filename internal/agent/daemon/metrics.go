package daemon

import (
	"github.com/prometheus/client_golang/prometheus"

	agentcore "sdn.sh/internal/agent/core"
)

// Metrics are the agent's Prometheus metrics.
type Metrics struct {
	kernelOps     *prometheus.CounterVec
	kernelSeconds *prometheus.HistogramVec
	batches       *prometheus.CounterVec
	batchSeconds  prometheus.Histogram
	nftSize       prometheus.Histogram
	flushed       *prometheus.CounterVec
	cpCalls       *prometheus.CounterVec
	polls         *prometheus.CounterVec
	generation    prometheus.Gauge
	registrations *prometheus.CounterVec
	probes        *prometheus.CounterVec
	probeRTT      *prometheus.HistogramVec
	localCalls    *prometheus.CounterVec
	localSeconds  *prometheus.HistogramVec
	core          *prometheus.CounterVec
	convergence   prometheus.Histogram
	interfaces    *prometheus.GaugeVec
	namespaces    *prometheus.GaugeVec
	peers         prometheus.Gauge
}

// NewMetrics registers the agent's metrics.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		kernelOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_kernel_ops_total", Help: "Kernel operations by kind and result.",
		}, []string{"kind", "result"}),
		kernelSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sdn_agent_kernel_op_seconds", Help: "Kernel operation latency by kind.",
			Buckets: prometheus.ExponentialBuckets(0.00001, 2, 20),
		}, []string{"kind"}),
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_batches_total", Help: "Per-namespace batches by result.",
		}, []string{"result"}),
		batchSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "sdn_agent_batch_seconds", Help: "Batch latency, queueing for a worker included.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 18),
		}),
		nftSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "sdn_agent_nft_transaction_size", Help: "Objects and elements one nftables transaction writes.",
			Buckets: prometheus.ExponentialBuckets(1, 4, 9),
		}),
		flushed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_flushed_total", Help: "Conntrack entries and sockets removed for departed peers.",
		}, []string{"what"}),
		cpCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_cp_calls_total", Help: "Control-plane calls by kind and result.",
		}, []string{"call", "result"}),
		polls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_polls_total", Help: "Desired-state long polls by result.",
		}, []string{"result"}),
		generation: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sdn_agent_generation", Help: "The desired-state generation the agent holds.",
		}),
		registrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_registrations_total", Help: "Registration datagrams by result.",
		}, []string{"result"}),
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_relay_probes_total", Help: "Relay probes sent and answered, by relay.",
		}, []string{"relay", "result"}),
		probeRTT: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sdn_agent_relay_probe_seconds", Help: "Relay probe round-trip time.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
		}, []string{"relay"}),
		localCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_local_calls_total", Help: "Local attach and detach calls by result.",
		}, []string{"call", "result"}),
		localSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sdn_agent_local_call_seconds", Help: "Local attach and detach latency, to a namespace ready to hand over.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}, []string{"call"}),
		convergence: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "sdn_agent_convergence_seconds", Help: "Time from the control plane committing a network revision to a namespace's kernel state settling on it.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 16),
		}),
		core: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sdn_agent_core_events_total", Help: "Core decisions: conflicts deferred, batches preempted, relay failovers, failed batches.",
		}, []string{"event"}),
		interfaces: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sdn_agent_interfaces", Help: "Interfaces the agent manages, by phase.",
		}, []string{"phase"}),
		namespaces: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sdn_agent_namespaces", Help: "Namespaces the agent tracks: named, or held by something else and awaiting a reap.",
		}, []string{"kind"}),
		peers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sdn_agent_peers", Help: "Peers the agent's devices hold, as it believes them.",
		}),
	}
	reg.MustRegister(m.kernelOps, m.kernelSeconds, m.batches, m.batchSeconds, m.nftSize, m.flushed, m.cpCalls,
		m.polls, m.generation, m.registrations, m.probes, m.probeRTT, m.localCalls, m.localSeconds, m.core, m.convergence,
		m.interfaces, m.namespaces, m.peers)
	return m
}

// census sets the gauges from a core census.
func (m *Metrics) census(c agentcore.Census) {
	for phase, n := range c.Interfaces {
		m.interfaces.WithLabelValues(phase).Set(float64(n))
	}
	m.namespaces.WithLabelValues("named").Set(float64(c.Namespaces))
	m.namespaces.WithLabelValues("held").Set(float64(c.Held))
	m.peers.Set(float64(c.Peers))
}

func (m *Metrics) coreStat(event string, delta uint64) {
	if delta > 0 {
		m.core.WithLabelValues(event).Add(float64(delta))
	}
}
