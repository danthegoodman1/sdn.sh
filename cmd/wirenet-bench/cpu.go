//go:build linux

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/bench"
)

// userHZ is the unit of /proc/stat's counters, fixed at 100 on Linux.
const userHZ = 100

func cpu(args []string) error {
	fs := flag.NewFlagSet("cpu", flag.ContinueOnError)
	duration := fs.Duration("duration", 10*time.Second, "how long to sample")
	if err := parse(fs, args); err != nil {
		return err
	}
	before, cpus, err := readStat()
	if err != nil {
		return err
	}
	start := time.Now()
	time.Sleep(*duration)
	after, _, err := readStat()
	if err != nil {
		return err
	}
	d := func(i int) float64 { return float64(after[i]-before[i]) / userHZ }
	res := bench.CPU{
		Seconds: time.Since(start).Seconds(), CPUs: cpus,
		User: d(statUser) + d(statNice), System: d(statSystem), IRQ: d(statIRQ), SoftIRQ: d(statSoftIRQ),
		Steal: d(statSteal), Idle: d(statIdle) + d(statIOWait),
	}
	res.Busy = res.User + res.System + res.IRQ + res.SoftIRQ
	return emit(res)
}

// Columns of /proc/stat's cpu line. Guest time is already counted in user.
const (
	statUser = iota
	statNice
	statSystem
	statIdle
	statIOWait
	statIRQ
	statSoftIRQ
	statSteal
	statColumns
)

// readStat returns the aggregate cpu line's counters and the number of
// CPUs.
func readStat() ([statColumns]uint64, int, error) {
	var out [statColumns]uint64
	f, err := os.Open("/proc/stat")
	if err != nil {
		return out, 0, err
	}
	defer f.Close()
	found, cpus := false, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		switch {
		case len(fields) > statColumns && fields[0] == "cpu":
			for i := range out {
				v, err := strconv.ParseUint(fields[i+1], 10, 64)
				if err != nil {
					return out, 0, fmt.Errorf("/proc/stat: %w", err)
				}
				out[i] = v
			}
			found = true
		case len(fields) > 0 && strings.HasPrefix(fields[0], "cpu"):
			cpus++
		}
	}
	if err := sc.Err(); err != nil {
		return out, 0, err
	}
	if !found {
		return out, 0, errors.New("/proc/stat has no cpu line")
	}
	return out, cpus, nil
}
