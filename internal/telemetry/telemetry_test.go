package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoggerTagsItsComponent(t *testing.T) {
	var buf bytes.Buffer
	log, err := NewLogger("agent", LogConfig{Out: &buf, Format: "json", Level: "debug"})
	if err != nil {
		t.Fatal(err)
	}
	log.Info().Str("interface", "if-1").Msg("attached")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("%v in %q", err, buf.String())
	}
	if line["component"] != "agent" || line["interface"] != "if-1" || line["message"] != "attached" {
		t.Fatalf("line %v", line)
	}
	if _, err := NewLogger("agent", LogConfig{Format: "xml"}); err == nil {
		t.Fatal("accepted an unknown format")
	}
}

func TestServerServesMetricsAndReadiness(t *testing.T) {
	reg := NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "sdn_test_total", Help: "test"})
	reg.MustRegister(c)
	c.Add(3)
	var ready atomic.Bool
	s := &Server{Addr: "127.0.0.1:0", Registry: reg, Ready: func() error {
		if !ready.Load() {
			return errors.New("still loading")
		}
		return nil
	}}
	addr, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)
	get := func(path string) (int, string) {
		resp, err := http.Get("http://" + addr.String() + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/metrics"); code != 200 || !strings.Contains(body, "sdn_test_total 3") {
		t.Fatalf("metrics %d: %s", code, body)
	}
	if code, _ := get("/readyz"); code != 503 {
		t.Fatalf("readyz %d before ready", code)
	}
	ready.Store(true)
	if code, _ := get("/readyz"); code != 200 {
		t.Fatalf("readyz %d once ready", code)
	}
}
