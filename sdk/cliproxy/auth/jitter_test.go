package auth

import (
	"testing"
	"time"
)

func TestJitteredNow_WithinJitterWindow(t *testing.T) {
	now := time.Now()
	for i := 0; i < 1000; i++ {
		got := jitteredNow(now)
		delta := got.Sub(now)
		if delta < 0 {
			t.Fatalf("jitteredNow returned %v, before now", got)
		}
		if delta >= startupBurstJitter {
			t.Fatalf("jitteredNow returned delta=%v, must be < %v", delta, startupBurstJitter)
		}
	}
}

func TestJitteredNow_SpreadsAcrossWindow(t *testing.T) {
	now := time.Now()
	const buckets = 6
	bucketSize := startupBurstJitter / buckets
	hits := make([]int, buckets)
	for i := 0; i < 600; i++ {
		got := jitteredNow(now)
		idx := int(got.Sub(now) / bucketSize)
		if idx >= buckets {
			idx = buckets - 1
		}
		hits[idx]++
	}
	for i, h := range hits {
		if h == 0 {
			t.Fatalf("bucket %d (offset %v..%v) was never hit in 600 trials — jitter not uniform", i, time.Duration(i)*bucketSize, time.Duration(i+1)*bucketSize)
		}
	}
}
