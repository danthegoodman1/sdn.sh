//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"sdn.sh/internal/bench"
)

// A client opens each connection with one mode byte.
const (
	// modeSink: the client sends until it closes its write side, and the
	// server answers with the bytes it read as a big-endian uint64.
	modeSink = 's'
	// modeSource: the server sends until the client closes.
	modeSource = 'r'
	// modeEcho: a big-endian uint32 size follows, and the server echoes
	// every request of that many bytes.
	modeEcho = 'e'
	// modeName: the server answers with its name and a newline, then
	// closes.
	modeName = 'n'
)

const (
	streamBuffer = 256 << 10
	maxEchoSize  = 1 << 20
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":"+strconv.Itoa(bench.Port), "comma-separated TCP addresses to listen on")
	ns := fs.String("netns", "", "namespace to listen in")
	host, _ := os.Hostname()
	name := fs.String("name", host, "the answer to a name request")
	if err := parse(fs, args); err != nil {
		return err
	}
	var lns []net.Listener
	for _, addr := range strings.Split(*listen, ",") {
		var ln net.Listener
		if err := inNetns(*ns, func() error {
			var err error
			ln, err = net.Listen("tcp", addr)
			return err
		}); err != nil {
			return err
		}
		lns = append(lns, ln)
	}
	addrs := make([]string, len(lns))
	errs := make(chan error, len(lns))
	for i, ln := range lns {
		addrs[i] = ln.Addr().String()
		go func() { errs <- accept(ln, *name) }()
	}
	if err := emit(map[string]any{"listening": addrs, "name": *name}); err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		return nil
	case err := <-errs:
		return err
	}
}

func accept(ln net.Listener, name string) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if err := handle(c, name); err != nil && !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "sdn-bench: %v: %v\n", c.RemoteAddr(), err)
			}
		}()
	}
}

func handle(c net.Conn, name string) error {
	var mode [1]byte
	if _, err := io.ReadFull(c, mode[:]); err != nil {
		return err
	}
	switch mode[0] {
	case modeSink:
		buf := make([]byte, streamBuffer)
		var n uint64
		for {
			k, err := c.Read(buf)
			n += uint64(k)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
		}
		return binary.Write(c, binary.BigEndian, n)
	case modeSource:
		buf := make([]byte, streamBuffer)
		for {
			if _, err := c.Write(buf); err != nil {
				return nil // the client closing ends the run
			}
		}
	case modeEcho:
		var size uint32
		if err := binary.Read(c, binary.BigEndian, &size); err != nil {
			return err
		}
		if size == 0 || size > maxEchoSize {
			return fmt.Errorf("echo size %d out of range", size)
		}
		buf := make([]byte, size)
		for {
			if _, err := io.ReadFull(c, buf); err != nil {
				return err
			}
			if _, err := c.Write(buf); err != nil {
				return err
			}
		}
	case modeName:
		_, err := io.WriteString(c, name+"\n")
		return err
	}
	return fmt.Errorf("unknown mode %q", mode[0])
}
