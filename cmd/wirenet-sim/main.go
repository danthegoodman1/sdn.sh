// Command wirenet-sim runs simulations. With no seed it picks one; pass a seed,
// or a git commit hash, to replay a run. --seeds N runs N consecutive seeds
// on every core.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/danthegoodman1/wirenet/internal/sim"
)

func main() {
	seeds := flag.Uint64("seeds", 0, "run this many consecutive seeds from SEED")
	trace := flag.Bool("trace", false, "print the last events of a failing run")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wirenet-sim [--seeds N] [--trace] [SEED]")
		flag.PrintDefaults()
	}
	flag.Parse()
	var seed uint64
	switch flag.NArg() {
	case 0:
		var b [8]byte
		rand.Read(b[:])
		seed = binary.LittleEndian.Uint64(b[:])
	case 1:
		s, err := sim.ParseSeed(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		seed = s
	default:
		flag.Usage()
		os.Exit(2)
	}
	if *seeds == 0 {
		os.Exit(runOne(seed, *trace))
	}
	os.Exit(sweep(seed, *seeds))
}

func runOne(seed uint64, trace bool) int {
	w := sim.New(seed)
	if trace {
		w = w.Trace()
	}
	fmt.Printf("seed %d: %v\n", seed, w.Options())
	summary, err := w.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintf(os.Stderr, "replay: go run ./cmd/wirenet-sim --trace %d\n", seed)
		return 1
	}
	fmt.Println(summary)
	return 0
}

// sweep runs seeds start..start+count in parallel. Each run is
// deterministic on its own, so the goroutines change only the order results
// print in.
func sweep(start, count uint64) int {
	var next atomic.Uint64
	var mu sync.Mutex
	var failed []uint64
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Go(func() {
			for {
				i := next.Add(1) - 1
				if i >= count {
					return
				}
				seed := start + i
				err := run(seed)
				if err != nil {
					mu.Lock()
					failed = append(failed, seed)
					fmt.Fprintln(os.Stderr, err)
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	slices.Sort(failed)
	fmt.Printf("%d of %d seeds from %d failed\n", len(failed), count, start)
	for _, s := range failed {
		fmt.Printf("replay: go run ./cmd/wirenet-sim --trace %s\n", strconv.FormatUint(s, 10))
	}
	if len(failed) > 0 {
		return 1
	}
	return 0
}

func run(seed uint64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("seed %d panicked: %v", seed, r)
		}
	}()
	_, err = sim.New(seed).Run()
	return err
}
