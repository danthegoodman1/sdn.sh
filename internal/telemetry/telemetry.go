// Package telemetry gives every daemon the same logger setup and the same
// listener for metrics, health and profiling.
package telemetry

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// LogConfig chooses where logs go and how they look.
type LogConfig struct {
	// Level is a zerolog level name: debug, info, warn or error.
	Level string
	// Format is "json", "console", or "" to pick console on a terminal.
	Format string
	// Out defaults to stderr.
	Out io.Writer
}

// NewLogger returns the logger for one component. Every line carries the
// component's name, so one host's interleaved daemons stay readable.
func NewLogger(component string, cfg LogConfig) (zerolog.Logger, error) {
	out := cfg.Out
	if out == nil {
		out = os.Stderr
	}
	level := zerolog.InfoLevel
	if cfg.Level != "" {
		l, err := zerolog.ParseLevel(cfg.Level)
		if err != nil {
			return zerolog.Logger{}, err
		}
		level = l
	}
	format := cfg.Format
	if format == "" {
		format = "json"
		if f, ok := out.(*os.File); ok && isTerminal(f) {
			format = "console"
		}
	}
	switch format {
	case "json":
	case "console":
		out = zerolog.ConsoleWriter{Out: out, TimeFormat: "15:04:05.000"}
	default:
		return zerolog.Logger{}, errors.New("log format must be json or console")
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano
	return zerolog.New(out).Level(level).With().Timestamp().Str("component", component).Logger(), nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// NewRegistry returns a Prometheus registry carrying the Go runtime and
// process collectors.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// Server serves /metrics, /healthz, /readyz and /debug/pprof.
type Server struct {
	Addr     string
	Registry *prometheus.Registry
	// Ready reports whether the daemon can serve; nil means always.
	Ready func() error
	Log   zerolog.Logger

	ln net.Listener
}

// Listen binds the server's address and returns the bound address, so a
// test can ask for port 0.
func (s *Server) Listen() (net.Addr, error) {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	return ln.Addr(), nil
}

// Serve serves until ctx ends. It calls Listen if the caller has not.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		if _, err := s.Listen(); err != nil {
			return err
		}
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.Ready != nil {
			if err := s.Ready(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	s.Log.Info().Str("addr", s.ln.Addr().String()).Msg("telemetry listening")
	if err := srv.Serve(s.ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
