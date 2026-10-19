package cpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestAConnectThatGetsNoAnswerDialsAgain hangs a call's first TCP connect,
// as a lost SYN would, and checks the call dials again and succeeds within
// its timeout; with every connect hanging, the error says no connection
// was made.
func TestAConnectThatGetsNoAnswerDialsAgain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("[]")) }))
	defer srv.Close()
	var dials, hang atomic.Int32
	hang.Store(1)
	var d net.Dialer
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if dials.Add(1) <= hang.Load() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return d.DialContext(ctx, network, addr)
	}
	c, err := New(srv.URL, "token", Options{Timeout: time.Second, DialTimeout: 100 * time.Millisecond, Dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Networks(context.Background()); err != nil || dials.Load() != 2 {
		t.Fatalf("after a connect that hung: %v, %d dials", err, dials.Load())
	}

	dials.Store(0)
	hang.Store(100)
	c, _ = New(srv.URL, "token", Options{Timeout: 350 * time.Millisecond, DialTimeout: 100 * time.Millisecond, Dial: dial})
	_, err = c.Networks(context.Background())
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "no connection") || dials.Load() < 3 {
		t.Fatalf("with every connect hanging: %v after %d dials", err, dials.Load())
	}
}
