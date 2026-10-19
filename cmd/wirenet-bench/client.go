//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/danthegoodman1/wirenet/internal/bench"
)

func dialTCP(ns, target string, timeout time.Duration) (*net.TCPConn, error) {
	var c net.Conn
	err := inNetns(ns, func() error {
		var err error
		c, err = net.DialTimeout("tcp", target, timeout)
		return err
	})
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func stream(args []string) error {
	fs := flag.NewFlagSet("stream", flag.ContinueOnError)
	target := fs.String("target", "", "server address:port")
	ns := fs.String("netns", "", "namespace to connect from")
	duration := fs.Duration("duration", 10*time.Second, "how long to send")
	parallel := fs.Int("parallel", 1, "connections")
	reverse := fs.Bool("reverse", false, "the server sends and the client receives")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *target == "" || *parallel < 1 {
		return errors.New("stream: --target and a positive --parallel are required")
	}
	conns := make([]*net.TCPConn, 0, *parallel)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	mode := []byte{modeSink}
	if *reverse {
		mode[0] = modeSource
	}
	for range *parallel {
		c, err := dialTCP(*ns, *target, 5*time.Second)
		if err != nil {
			return err
		}
		conns = append(conns, c)
		if _, err := c.Write(mode); err != nil {
			return err
		}
	}
	res := bench.Stream{Target: *target, Reverse: *reverse, Parallel: *parallel, Conns: make([]bench.StreamConn, *parallel)}
	errs := make([]error, *parallel)
	start := time.Now()
	deadline := start.Add(*duration)
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Go(func() {
			if *reverse {
				res.Conns[i].Bytes, errs[i] = receive(c, deadline)
			} else {
				res.Conns[i], errs[i] = send(c, deadline)
			}
		})
	}
	wg.Wait()
	res.Seconds = time.Since(start).Seconds()
	if *reverse {
		res.Seconds = duration.Seconds()
	}
	// Every connection must finish, or the figure covers less work than it
	// claims.
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for _, c := range res.Conns {
		res.Bytes += c.Bytes
		res.Retransmits += uint64(c.Retransmits)
	}
	res.BitsPerSecond = float64(res.Bytes) * 8 / res.Seconds
	return emit(res)
}

// send writes until the deadline, closes its write side, and reads back
// the byte count the server received.
func send(c *net.TCPConn, deadline time.Time) (bench.StreamConn, error) {
	buf := make([]byte, streamBuffer)
	c.SetWriteDeadline(deadline)
	for {
		if _, err := c.Write(buf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			return bench.StreamConn{}, err
		}
	}
	if err := c.CloseWrite(); err != nil {
		return bench.StreamConn{}, err
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	var n uint64
	if err := binary.Read(c, binary.BigEndian, &n); err != nil {
		return bench.StreamConn{}, fmt.Errorf("reading the server's count: %w", err)
	}
	out := bench.StreamConn{Bytes: int64(n)}
	retrans, rtt, err := tcpInfo(c)
	if err != nil {
		return out, err
	}
	out.Retransmits, out.RTT = retrans, float64(rtt)/1000
	return out, nil
}

func receive(c *net.TCPConn, deadline time.Time) (int64, error) {
	buf := make([]byte, streamBuffer)
	c.SetReadDeadline(deadline)
	var n int64
	for {
		k, err := c.Read(buf)
		n += int64(k)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// tcpInfo reads the connection's total retransmits and smoothed RTT in
// microseconds from TCP_INFO (struct tcp_info in linux/tcp.h).
func tcpInfo(c *net.TCPConn) (retrans, rttUS uint32, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var info [232]byte
	var serr error
	err = raw.Control(func(fd uintptr) {
		n := uint32(len(info))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&n)), 0)
		if e != 0 {
			serr = e
		} else if n < 104 {
			serr = fmt.Errorf("tcp_info is %d bytes", n)
		}
	})
	if err = errors.Join(err, serr); err != nil {
		return 0, 0, fmt.Errorf("TCP_INFO: %w", err)
	}
	// tcpi_rtt is at offset 68 and tcpi_total_retrans at 100.
	return binary.NativeEndian.Uint32(info[100:]), binary.NativeEndian.Uint32(info[68:]), nil
}

func rr(args []string) error {
	fs := flag.NewFlagSet("rr", flag.ContinueOnError)
	target := fs.String("target", "", "server address:port")
	ns := fs.String("netns", "", "namespace to connect from")
	size := fs.Int("size", 1, "bytes per request and per response")
	duration := fs.Duration("duration", 5*time.Second, "how long to run, when --count is 0")
	count := fs.Int("count", 0, "round trips to run")
	interval := fs.Duration("interval", 0, "pause between round trips")
	timeout := fs.Duration("timeout", 30*time.Second, "how long one round trip may take")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *target == "" || *size < 1 || *size > maxEchoSize {
		return errors.New("rr: --target and a --size from 1 to 1MiB are required")
	}
	res := bench.RR{Target: *target, Size: *size}
	start := time.Now()
	c, err := dialTCP(*ns, *target, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	res.Connect = ms(time.Since(start))
	hello := make([]byte, 5)
	hello[0] = modeEcho
	binary.BigEndian.PutUint32(hello[1:], uint32(*size))
	if _, err := c.Write(hello); err != nil {
		return err
	}
	req, resp := make([]byte, *size), make([]byte, *size)
	var samples []time.Duration
	var worst time.Duration
	res.Start = time.Now().UnixNano()
	end := time.Now().Add(*duration)
	for (*count > 0 && len(samples) < *count) || (*count == 0 && time.Now().Before(end)) {
		t0 := time.Now()
		c.SetDeadline(t0.Add(*timeout))
		if _, err := c.Write(req); err != nil {
			res.Error = err.Error()
			break
		}
		if _, err := io.ReadFull(c, resp); err != nil {
			res.Error = err.Error()
			break
		}
		took := time.Since(t0)
		samples = append(samples, took)
		if took > worst {
			worst, res.WorstAt = took, t0.UnixNano()
		}
		if *interval > 0 {
			time.Sleep(*interval)
		}
	}
	res.End = time.Now().UnixNano()
	res.Latency = bench.Summarize(samples)
	return emit(res)
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func dial(args []string) error {
	fs := flag.NewFlagSet("dial", flag.ContinueOnError)
	target := fs.String("target", "", "server address:port")
	nss := fs.String("netns", "", "comma-separated namespaces to dial from, one loop each")
	want := fs.String("want", "", "the server name that counts as reached; any answer counts when empty")
	refused := fs.Bool("refused", false, "count a connection that fails as reached, and any answer as another server's")
	streak := fs.Int("streak", 1, "consecutive wanted answers that end a loop")
	until := fs.Duration("until", 10*time.Second, "how long a loop tries")
	interval := fs.Duration("interval", 20*time.Millisecond, "pause between attempts")
	timeout := fs.Duration("timeout", 500*time.Millisecond, "how long one attempt may take")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *target == "" || *streak < 1 {
		return errors.New("dial: --target and a positive --streak are required")
	}
	names := strings.Split(*nss, ",")
	out := bench.Dials{Results: make([]bench.Dial, len(names))}
	var wg sync.WaitGroup
	for i, ns := range names {
		wg.Go(func() {
			out.Results[i] = dialLoop(ns, *target, *want, *refused, *streak, *until, *interval, *timeout)
		})
	}
	wg.Wait()
	return emit(out)
}

// dialLoop launches an attempt every interval, each connecting and asking
// the server's name, until the latest streak attempts, in launch order,
// all got the wanted answer and every attempt before them has finished;
// or until passes. Attempts overlap, so one that times out delays no
// other, and the loop places a switch of servers within one interval.
func dialLoop(ns, target, want string, refused bool, streak int, until, interval, timeout time.Duration) bench.Dial {
	d := bench.Dial{Namespace: ns, Target: target, Want: want, Refused: refused, Answers: map[string]int{}}
	var mu sync.Mutex
	var attempts []*dialAttempt // by launch order; nil until finished
	finished := make(chan struct{}, 1)
	launch := func() {
		mu.Lock()
		i := len(attempts)
		attempts = append(attempts, nil)
		mu.Unlock()
		t0 := time.Now()
		go func() {
			name, at, err := askName(ns, target, timeout)
			if at.IsZero() {
				at = t0
			}
			mu.Lock()
			attempts[i] = &dialAttempt{launched: at, done: time.Now(), name: name, err: err}
			mu.Unlock()
			select {
			case finished <- struct{}{}:
			default:
			}
		}()
	}
	wanted := func(a *dialAttempt) bool { return a.wanted(want, refused) }
	start := time.Now()
	d.Start = start.UnixNano()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.NewTimer(until)
	defer deadline.Stop()
	launch()
	for {
		select {
		case <-ticker.C:
			launch()
			continue
		case <-finished:
		case <-deadline.C:
		}
		mu.Lock()
		// The finished prefix, and the run of wanted answers ending it.
		k := 0
		for k < len(attempts) && attempts[k] != nil {
			k++
		}
		j := k
		for j > 0 && wanted(attempts[j-1]) {
			j--
		}
		if k-j >= streak {
			d.Reached = true
			d.Converged = attempts[j].launched.UnixNano()
		}
		if d.Reached || time.Since(start) >= until {
			tally(&d, attempts)
			mu.Unlock()
			return d
		}
		mu.Unlock()
	}
}

type dialAttempt struct {
	launched, done time.Time
	name           string
	err            error
}

// wanted reports whether an attempt got the outcome its loop waits for: the
// wanted server's answer, or with refused a failure.
func (a *dialAttempt) wanted(want string, refused bool) bool {
	if refused {
		return a.err != nil
	}
	return a.err == nil && (want == "" || a.name == want)
}

// tally counts a dial loop's finished attempts into d.
func tally(d *bench.Dial, attempts []*dialAttempt) {
	for _, a := range attempts {
		if a == nil {
			continue
		}
		launched, done := a.launched.UnixNano(), a.done.UnixNano()
		d.Attempts++
		if a.err != nil {
			d.Failures++
			if !d.Refused {
				d.Error = a.err.Error()
			}
		} else {
			d.Answers[a.name]++
		}
		switch {
		case a.wanted(d.Want, d.Refused):
			if d.First == 0 || launched < d.First {
				d.First = launched
			}
			if d.FirstDone == 0 || done < d.FirstDone {
				d.FirstDone = done
			}
		case a.err == nil:
			if !d.Reached || launched < d.Converged {
				d.Other = max(d.Other, launched)
			}
		}
	}
	if d.Reached {
		d.Error = ""
	}
}

// askName asks target for its name from namespace ns, and returns when
// the connection began: once the thread is in the namespace, which can
// trail the attempt's launch by milliseconds when many dial at once.
func askName(ns, target string, timeout time.Duration) (string, time.Time, error) {
	var c net.Conn
	var at time.Time
	err := inNetns(ns, func() error {
		var err error
		at = time.Now()
		c, err = net.DialTimeout("tcp", target, timeout)
		return err
	})
	if err != nil {
		return "", at, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{modeName}); err != nil {
		return "", at, err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", at, err
	}
	return strings.TrimSuffix(line, "\n"), at, nil
}
