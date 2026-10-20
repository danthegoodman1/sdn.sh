package server

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	relaycore "github.com/danthegoodman1/wirenet/internal/relay/core"
)

// Metrics are the relay's Prometheus metrics.
type Metrics struct {
	forwarded      prometheus.Counter
	forwardedBytes prometheus.Counter
	writeFailed    prometheus.Counter
	dropped        *prometheus.CounterVec
	registrations  *prometheus.CounterVec
	waits          *prometheus.CounterVec
	probes         prometheus.Counter
	probesLimited  prometheus.Counter
	readBatch      prometheus.Histogram
	fsync          prometheus.Histogram
	ports          prometheus.Gauge
	unbound        prometheus.Gauge
	bindFailed     prometheus.Counter
	generation     prometheus.Gauge
	perPort        *portCollector
}

// NewMetrics registers the relay's metrics. perPortCap bounds how many
// ports carry per-port series, the busiest first.
func NewMetrics(reg prometheus.Registerer, perPortCap int) *Metrics {
	m := &Metrics{
		forwarded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_relay_forwarded_packets_total", Help: "Packets forwarded.",
		}),
		forwardedBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_relay_forwarded_bytes_total", Help: "Bytes forwarded.",
		}),
		writeFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_relay_write_failed_packets_total", Help: "Packets the relay decided to forward and failed to send.",
		}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wirenet_relay_dropped_packets_total", Help: "Packets dropped, by reason.",
		}, []string{"reason"}),
		registrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wirenet_relay_registrations_total", Help: "Registrations by outcome.",
		}, []string{"result"}),
		waits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wirenet_relay_waiting_packets_total", Help: "Data packets that waited for a registration, by outcome.",
		}, []string{"outcome"}),
		probes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_relay_probes_answered_total", Help: "Probes answered.",
		}),
		probesLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_relay_probes_limited_total", Help: "Probes left unanswered by the relay-wide cap.",
		}),
		readBatch: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "wirenet_relay_read_batch_size", Help: "Datagrams per receive batch.",
			Buckets: []float64{1, 2, 4, 8, 16, 32, 64, 128},
		}),
		fsync: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "wirenet_relay_registration_fsync_seconds", Help: "Time to make a group of registrations durable.",
			Buckets: prometheus.ExponentialBuckets(0.00005, 2, 16),
		}),
		ports: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wirenet_relay_ports", Help: "Directions' ports bound.",
		}),
		unbound: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wirenet_relay_unbound_ports", Help: "Directions' ports the relay failed to bind and is retrying.",
		}),
		bindFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wirenet_relay_bind_failures_total", Help: "Attempts to bind a direction's port that failed.",
		}),
		generation: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wirenet_relay_generation", Help: "The port table's control-plane generation.",
		}),
		perPort: &portCollector{cap: perPortCap},
	}
	reg.MustRegister(m.forwarded, m.forwardedBytes, m.writeFailed, m.dropped, m.registrations, m.waits, m.probes,
		m.probesLimited, m.readBatch, m.fsync, m.ports, m.unbound, m.bindFailed, m.generation, m.perPort, rcvbufErrors{})
	return m
}

func (m *Metrics) attach(s *Server) { m.perPort.s = s }

var (
	portPackets = prometheus.NewDesc("wirenet_relay_port_forwarded_packets_total", "Packets forwarded from a port, for the busiest ports.", []string{"port"}, nil)
	portBytes   = prometheus.NewDesc("wirenet_relay_port_forwarded_bytes_total", "Bytes forwarded from a port, for the busiest ports.", []string{"port"}, nil)
	portDropped = prometheus.NewDesc("wirenet_relay_port_dropped_packets_total", "Packets dropped on a port by reason, for the busiest ports.", []string{"port", "reason"}, nil)
)

// portCollector reports per-port counters for at most cap ports, the ones
// with the most bytes, so a relay with a million ports exports a bounded
// number of series.
type portCollector struct {
	cap int
	s   *Server
}

func (c *portCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- portPackets
	ch <- portBytes
	ch <- portDropped
}

func (c *portCollector) Collect(ch chan<- prometheus.Metric) {
	if c.s == nil || c.cap <= 0 {
		return
	}
	dirs := c.s.Dirs()
	slices.SortFunc(dirs, func(a, b relaycore.Dir) int { return int64Cmp(b.Stats.Bytes, a.Stats.Bytes) })
	if len(dirs) > c.cap {
		dirs = dirs[:c.cap]
	}
	for _, d := range dirs {
		port := d.Local.String()
		ch <- prometheus.MustNewConstMetric(portPackets, prometheus.CounterValue, float64(d.Stats.Forwarded), port)
		ch <- prometheus.MustNewConstMetric(portBytes, prometheus.CounterValue, float64(d.Stats.Bytes), port)
		for reason, n := range map[string]uint64{
			"unregistered_sender": d.Stats.Unregistered, "peer_unregistered": d.Stats.PeerAbsent,
			"rate_limited": d.Stats.Limited, "bad_mac": d.Stats.BadMAC, "replay": d.Stats.Replayed, "crossed_initiation": d.Stats.Crossed,
		} {
			ch <- prometheus.MustNewConstMetric(portDropped, prometheus.CounterValue, float64(n), port, reason)
		}
	}
}

func int64Cmp(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

var rcvbufDesc = prometheus.NewDesc("wirenet_relay_udp_rcvbuf_errors_total",
	"The host's UdpRcvbufErrors and Udp6RcvbufErrors: datagrams dropped because a socket's receive queue was full.", []string{"family"}, nil)

// rcvbufErrors reads the host's UDP receive-queue drops, the sign of a
// relay that cannot keep up.
type rcvbufErrors struct{}

func (rcvbufErrors) Describe(ch chan<- *prometheus.Desc) { ch <- rcvbufDesc }

func (rcvbufErrors) Collect(ch chan<- prometheus.Metric) {
	if v, ok := snmpField("/proc/net/snmp", "Udp:", "RcvbufErrors"); ok {
		ch <- prometheus.MustNewConstMetric(rcvbufDesc, prometheus.CounterValue, v, "ipv4")
	}
	if v, ok := snmp6Field("/proc/net/snmp6", "Udp6RcvbufErrors"); ok {
		ch <- prometheus.MustNewConstMetric(rcvbufDesc, prometheus.CounterValue, v, "ipv6")
	}
}

// snmpField reads one counter from /proc/net/snmp, whose sections are a
// header line of names followed by a line of values.
func snmpField(path, section, field string) (float64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var names []string
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] != section {
			continue
		}
		if names == nil {
			names = fields
			continue
		}
		for i, n := range names {
			if n == field && i < len(fields) {
				v, err := strconv.ParseFloat(fields[i], 64)
				return v, err == nil
			}
		}
		return 0, false
	}
	return 0, false
}

func snmp6Field(path, field string) (float64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == field {
			v, err := strconv.ParseFloat(fields[1], 64)
			return v, err == nil
		}
	}
	return 0, false
}
