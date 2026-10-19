//go:build linux

package main

import (
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpreadPicksEvenlyWithBothEnds(t *testing.T) {
	for _, c := range []struct {
		n, k int
		want []int
	}{
		{100, 10, []int{0, 11, 22, 33, 44, 55, 66, 77, 88, 99}},
		{5, 10, []int{0, 1, 2, 3, 4}},
		{1, 10, []int{0}},
		{10, 1, []int{9}},
		{10, 0, []int{}},
		{3, 2, []int{0, 2}},
	} {
		if got := spread(c.n, c.k); !slices.Equal(got, c.want) {
			t.Errorf("spread(%d, %d) = %v, want %v", c.n, c.k, got, c.want)
		}
	}
}

// serveNames answers name requests with whatever name holds.
func serveNames(t *testing.T, name *atomic.Value) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c, name.Load().(string))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestDialLoopPlacesASwitchWithinAnInterval(t *testing.T) {
	var name atomic.Value
	name.Store("old")
	addr := serveNames(t, &name)
	var switched atomic.Int64
	go func() {
		time.Sleep(200 * time.Millisecond)
		switched.Store(time.Now().UnixNano())
		name.Store("new")
	}()
	const interval = 5 * time.Millisecond
	d := dialLoop("", addr, "new", false, 10, 5*time.Second, interval, time.Second)
	if !d.Reached {
		t.Fatalf("never settled: %+v", d)
	}
	at := switched.Load()
	if d.Other >= at || d.Converged < d.Other {
		t.Fatalf("old answered at %d and the run began at %d, but the switch was at %d", d.Other, d.Converged, at)
	}
	if late := time.Duration(d.Converged - at); late > 2*interval {
		t.Errorf("settled %v after the switch, more than two intervals", late)
	}
	if d.Answers["old"] == 0 || d.Answers["new"] < 10 || d.Failures != 0 {
		t.Errorf("answers %v, failures %d", d.Answers, d.Failures)
	}
}

// TestARefusedDialLoopSettlesOnceConnectionsFail stops a server mid-loop:
// the loop settles at the first of a run of failures, after the server's
// last answer.
func TestARefusedDialLoopSettlesOnceConnectionsFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c, "db")
			}()
		}
	}()
	var stopped atomic.Int64
	go func() {
		time.Sleep(200 * time.Millisecond)
		stopped.Store(time.Now().UnixNano())
		ln.Close()
	}()
	const interval = 5 * time.Millisecond
	d := dialLoop("", ln.Addr().String(), "", true, 10, 5*time.Second, interval, time.Second)
	if !d.Reached || !d.Refused {
		t.Fatalf("never settled: %+v", d)
	}
	at := stopped.Load()
	if d.Answers["db"] == 0 || d.Other >= at || d.Converged < d.Other || d.Failures < 10 {
		t.Fatalf("answers %v, last at %d, run from %d, failures %d; the server stopped at %d", d.Answers, d.Other, d.Converged, d.Failures, at)
	}
	if late := time.Duration(d.Converged - at); late > 2*interval {
		t.Errorf("settled %v after the server stopped, more than two intervals", late)
	}
}

func TestDialLoopGivesUpAndSaysWhy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	d := dialLoop("", addr, "", false, 1, 100*time.Millisecond, 10*time.Millisecond, 50*time.Millisecond)
	if d.Reached || d.Failures == 0 || d.Failures != d.Attempts || d.Error == "" || d.Converged != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestStreamSinkCountsWhatArrived(t *testing.T) {
	var name atomic.Value
	name.Store("srv")
	addr := serveNames(t, &name)
	c, err := dialTCP("", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{modeSink}); err != nil {
		t.Fatal(err)
	}
	got, err := send(c, time.Now().Add(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if got.Bytes < streamBuffer {
		t.Fatalf("the server counted %d bytes", got.Bytes)
	}
}
