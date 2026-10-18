package bench

import (
	"math/rand/v2"
	"testing"
	"time"
)

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestSummarizeUsesNearestRank(t *testing.T) {
	// 1..100ms in shuffled order: the p-th percentile is p milliseconds.
	var samples []time.Duration
	for i := 1; i <= 100; i++ {
		samples = append(samples, ms(i))
	}
	rand.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
	got := Summarize(samples)
	want := Latency{Count: 100, Mean: 50.5, P50: 50, P90: 90, P99: 99, Max: 100}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestPercentileOfSmallSets(t *testing.T) {
	for _, c := range []struct {
		samples []int
		p       float64
		want    int
	}{
		{[]int{7}, 50, 7},
		{[]int{7}, 99, 7},
		{[]int{1, 2}, 50, 1},
		{[]int{1, 2}, 51, 2},
		{[]int{1, 2, 3, 4}, 75, 3},
		{[]int{1, 2, 3, 4}, 99, 4},
		{[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 90, 9},
		{[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 99, 10},
		{[]int{1, 2, 3}, 0, 1},
		{[]int{1, 2, 3}, 100, 3},
	} {
		var sorted []time.Duration
		for _, s := range c.samples {
			sorted = append(sorted, ms(s))
		}
		if got := Percentile(sorted, c.p); got != ms(c.want) {
			t.Errorf("p%v of %v = %v, want %v", c.p, c.samples, got, ms(c.want))
		}
	}
}

func TestSummarizeEmptyAndOne(t *testing.T) {
	if got := Summarize(nil); got != (Latency{}) {
		t.Errorf("empty: %+v", got)
	}
	got := Summarize([]time.Duration{1500 * time.Microsecond})
	want := Latency{Count: 1, Mean: 1.5, P50: 1.5, P90: 1.5, P99: 1.5, Max: 1.5}
	if got != want {
		t.Errorf("one: got %+v, want %+v", got, want)
	}
}

func TestATailOutlierMovesOnlyTheTop(t *testing.T) {
	// 99 fast samples and one stall: p99 stays fast and max shows the stall.
	samples := make([]time.Duration, 0, 100)
	for range 99 {
		samples = append(samples, ms(1))
	}
	samples = append(samples, ms(900))
	got := Summarize(samples)
	if got.P50 != 1 || got.P99 != 1 || got.Max != 900 {
		t.Fatalf("got %+v", got)
	}
}
