package auth

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
)

func TestCodexAuthenticator_RefreshLead_RandomInBounds(t *testing.T) {
	a := NewCodexAuthenticator()
	for i := 0; i < 200; i++ {
		lead := a.RefreshLead()
		if lead == nil {
			t.Fatal("RefreshLead returned nil")
		}
		if *lead < codex.RefreshLeadMin || *lead >= codex.RefreshLeadMax {
			t.Fatalf("RefreshLead returned %v, want in [%v, %v)", *lead, codex.RefreshLeadMin, codex.RefreshLeadMax)
		}
	}
}

func TestCodexAuthenticator_RefreshLead_ReRollsOnEachCall(t *testing.T) {
	a := NewCodexAuthenticator()
	seen := map[time.Duration]struct{}{}
	for i := 0; i < 100; i++ {
		seen[*a.RefreshLead()] = struct{}{}
	}
	if len(seen) < 50 {
		t.Fatalf("RefreshLead produced only %d distinct values out of 100 — caller must always see a fresh roll", len(seen))
	}
}
