package executor

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Helpers for the installation_id (F) and window_id (G) features. Each test
// pins a guarantee that the implementation must keep across future refactors;
// see CODEX_CLI_REFERENCE.md §6.F / §6.G and LEAK_RISKS.md F / G.

// ---------------------------------------------------------------------------
// installation_id
// ---------------------------------------------------------------------------

func TestCodexInstallationID_NilOrEmpty_ReturnsEmpty(t *testing.T) {
	if got := codexInstallationIDForAuth(nil); got != "" {
		t.Fatalf("nil auth: got %q, want empty", got)
	}
	if got := codexInstallationIDForAuth(&cliproxyauth.Auth{}); got != "" {
		t.Fatalf("auth with nil Metadata: got %q, want empty", got)
	}
	if got := codexInstallationIDForAuth(&cliproxyauth.Auth{Metadata: map[string]any{}}); got != "" {
		t.Fatalf("auth with empty Metadata: got %q, want empty", got)
	}
}

func TestCodexInstallationID_ReadsExistingValue(t *testing.T) {
	want := "11111111-2222-4333-8444-555555555555"
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"installation_id": want}}
	if got := codexInstallationIDForAuth(auth); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestEnsureCodexInstallationID_GeneratesV4OnFirstCall(t *testing.T) {
	auth := &cliproxyauth.Auth{}
	got := ensureCodexInstallationID(auth)
	if got == "" {
		t.Fatal("ensure returned empty")
	}
	parsed, err := uuid.Parse(got)
	if err != nil {
		t.Fatalf("ensure produced non-UUID %q: %v", got, err)
	}
	if v := byte(parsed.Version()); v != 4 {
		t.Fatalf("ensure produced UUID version %d, want 4 (real Codex CLI installation_id is v4)", v)
	}
	if persisted, _ := auth.Metadata["installation_id"].(string); persisted != got {
		t.Fatalf("metadata persisted %q, ensure returned %q", persisted, got)
	}
}

func TestEnsureCodexInstallationID_PreservesExistingValue(t *testing.T) {
	// Real Codex CLI never overwrites the installation_id once written; the
	// fork analogue must do the same so a stable per-auth UUID survives every
	// subsequent refresh / login revisit. Cross-account distinctness comes
	// from each auth getting its own value at FIRST seed, not from rotating.
	want := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"installation_id": want}}
	got := ensureCodexInstallationID(auth)
	if got != want {
		t.Fatalf("ensure overwrote existing value: got %q, want %q", got, want)
	}
}

func TestEnsureCodexInstallationID_PerAuthDistinct(t *testing.T) {
	a := &cliproxyauth.Auth{}
	b := &cliproxyauth.Auth{}
	idA := ensureCodexInstallationID(a)
	idB := ensureCodexInstallationID(b)
	if idA == idB {
		t.Fatalf("two fresh auths got the same installation_id (%q) — must be independently random", idA)
	}
}

// ---------------------------------------------------------------------------
// x-codex-window-id
// ---------------------------------------------------------------------------

func TestCodexWindowID_FormatIsThreadColonGeneration(t *testing.T) {
	thread := "019eabcd-1234-7567-89ab-cdef01234567"
	got := codexWindowID(thread, 0)
	if got != thread+":0" {
		t.Fatalf("generation 0: got %q, want %q", got, thread+":0")
	}
	got = codexWindowID(thread, 7)
	if got != thread+":7" {
		t.Fatalf("generation 7: got %q, want %q", got, thread+":7")
	}
}

func TestCodexWindowID_EmptyThread_ReturnsEmpty(t *testing.T) {
	if got := codexWindowID("", 0); got != "" {
		t.Fatalf("empty thread: got %q, want empty", got)
	}
	if got := codexWindowID("   ", 5); got != "" {
		t.Fatalf("whitespace thread: got %q, want empty", got)
	}
}

func TestParseInboundWindowGeneration(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want uint64
	}{
		{"empty", "", 0},
		{"plain uuid no colon", "019eabcd-1234-7567-89ab-cdef01234567", 0},
		{"colon at end (no number)", "019eabcd-1234-7567-89ab-cdef01234567:", 0},
		{"valid generation 0", "019eabcd-1234-7567-89ab-cdef01234567:0", 0},
		{"valid generation 1", "019eabcd-1234-7567-89ab-cdef01234567:1", 1},
		{"valid generation 42", "019eabcd-1234-7567-89ab-cdef01234567:42", 42},
		{"non-numeric suffix", "019eabcd-1234-7567-89ab-cdef01234567:abc", 0},
		{"large generation", "x:18446744073709551615", 18446744073709551615},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseInboundWindowGeneration(tc.in); got != tc.want {
				t.Fatalf("parseInboundWindowGeneration(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// Roundtrip: given a real Codex-CLI-shaped inbound, the proxy's parsed
// generation feeding back into codexWindowID must produce the same suffix
// (only the thread prefix changes).
func TestCodexWindowID_RoundTripGenerationFromInbound(t *testing.T) {
	inbound := "019eabcd-1234-7567-89ab-cdef01234567:9"
	gen := parseInboundWindowGeneration(inbound)
	derivedThread := "019deadbe-1234-7567-89ab-cdef01234567"
	got := codexWindowID(derivedThread, gen)
	want := derivedThread + ":9"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// The thread prefix must be replaced — never leak the inbound thread id.
	if strings.HasPrefix(got, "019eabcd") {
		t.Fatalf("output %q still carries the inbound thread prefix — must be replaced by derived", got)
	}
}
