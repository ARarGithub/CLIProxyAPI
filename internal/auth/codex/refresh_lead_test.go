package codex

import (
	"testing"
	"time"
)

func TestNextRefreshLead_WithinBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := NextRefreshLead()
		if d < RefreshLeadMin {
			t.Fatalf("NextRefreshLead returned %v < min %v", d, RefreshLeadMin)
		}
		if d >= RefreshLeadMax {
			t.Fatalf("NextRefreshLead returned %v >= max %v (must be open upper bound)", d, RefreshLeadMax)
		}
	}
}

func TestNextRefreshLead_ProducesVariety(t *testing.T) {
	seen := map[time.Duration]struct{}{}
	for i := 0; i < 100; i++ {
		seen[NextRefreshLead()] = struct{}{}
	}
	if len(seen) < 50 {
		t.Fatalf("NextRefreshLead produced only %d distinct values out of 100 — randomness broken", len(seen))
	}
}
