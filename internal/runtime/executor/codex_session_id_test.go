package executor

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// This file is the focused unit-test suite for derivePerAuthSessionID. Tests
// are grouped by guarantee:
//
//   §1 Determinism
//   §2 Auth-switching round-trip (returning to a previous auth gives back the
//      same upstream id)
//   §3 Timestamp correctness (mirrored from inbound v7 / pinned for non-v7)
//   §4 Cross-input distinctness
//   §5 Edge cases (nil/empty, whitespace, non-v7 inbound)
//   §6 Structural validity (every output is a valid v7-looking UUID)
//   §7 Concurrency safety
//
// Real Codex CLI uses Uuid::now_v7() (codex-rs/protocol/src/session_id.rs).
// All outputs of derivePerAuthSessionID must be indistinguishable from a real
// Codex CLI session id by trivial structural inspection from the upstream.
//
// See LEAK_RISKS.md L1, SESSION_ID_BEHAVIOR.md, MERGE_GUIDE.md "Session ID
// test suite" section.

// makeAuth is a tiny helper to construct a minimal auth with just an ID, which
// is all derivePerAuthSessionID consumes.
func makeAuth(id string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{ID: id}
}

// freshNonCodexInput returns an originalID guaranteed to NOT parse as a v7
// UUID (it intentionally is not even a UUID), so derivePerAuthSessionID falls
// onto its non-codex-direct timestamp path. Includes the test name in the
// string to keep cache keys disjoint across tests so one test's cache state
// can't leak into another's.
func freshNonCodexInput(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("non-uuid-input::%s::%d", t.Name(), time.Now().UnixNano())
}

// freshCodexV7Input returns a fresh real UUIDv7 string, simulating what the
// Codex CLI would send in its Session_id header.
func freshCodexV7Input(t *testing.T) string {
	t.Helper()
	return uuid.Must(uuid.NewV7()).String()
}

// ---------------------------------------------------------------------------
// §1 Determinism: same (originalID, auth.ID) input → same output, always.
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_Deterministic_CodexDirect(t *testing.T) {
	in := freshCodexV7Input(t)
	a := makeAuth("auth-A")

	first := derivePerAuthSessionID(in, a)
	for i := 0; i < 50; i++ {
		got := derivePerAuthSessionID(in, a)
		if got != first {
			t.Fatalf("call %d: got %q, want %q (codex direct must be deterministic)", i, got, first)
		}
	}
}

func TestDerivePerAuthSessionID_Deterministic_NonCodex(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")

	first := derivePerAuthSessionID(in, a)
	for i := 0; i < 50; i++ {
		got := derivePerAuthSessionID(in, a)
		if got != first {
			t.Fatalf("call %d: got %q, want %q (non-codex must be deterministic within process via cache)", i, got, first)
		}
	}
}

// ---------------------------------------------------------------------------
// §2 Auth-switching round-trip:
//      (X, A) -> s0
//      (X, B) -> s1
//      (X, A) -> s2
//      (X, B) -> s3
//    Must hold: s0 == s2, s1 == s3, s0 != s1.
//    This proves that switching back to a previous auth restores the previous
//    upstream session id (so prompt cache continuity works) AND that within
//    one auth period the value is stable.
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_AuthSwitching_RoundTrip_CodexDirect(t *testing.T) {
	in := freshCodexV7Input(t)
	a := makeAuth("auth-A")
	b := makeAuth("auth-B")

	s0 := derivePerAuthSessionID(in, a)
	s1 := derivePerAuthSessionID(in, b)
	s2 := derivePerAuthSessionID(in, a)
	s3 := derivePerAuthSessionID(in, b)

	if s0 != s2 {
		t.Fatalf("returning to auth A must give same id: s0=%q s2=%q", s0, s2)
	}
	if s1 != s3 {
		t.Fatalf("returning to auth B must give same id: s1=%q s3=%q", s1, s3)
	}
	if s0 == s1 {
		t.Fatalf("cross-auth must differ at all times: s0=s1=%q", s0)
	}
}

func TestDerivePerAuthSessionID_AuthSwitching_RoundTrip_NonCodex(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")
	b := makeAuth("auth-B")

	s0 := derivePerAuthSessionID(in, a)
	s1 := derivePerAuthSessionID(in, b)
	s2 := derivePerAuthSessionID(in, a)
	s3 := derivePerAuthSessionID(in, b)

	if s0 != s2 {
		t.Fatalf("returning to auth A must give same id: s0=%q s2=%q", s0, s2)
	}
	if s1 != s3 {
		t.Fatalf("returning to auth B must give same id: s1=%q s3=%q", s1, s3)
	}
	if s0 == s1 {
		t.Fatalf("cross-auth must differ at all times: s0=s1=%q", s0)
	}
}

// ---------------------------------------------------------------------------
// §3 Timestamp correctness
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_Timestamp_BorrowedFromInboundV7(t *testing.T) {
	inStr := freshCodexV7Input(t)
	inU := uuid.MustParse(inStr)
	wantTS := extractV7TimestampMs(inU)

	for _, authID := range []string{"auth-A", "auth-B", "auth-some-long-id-xyz"} {
		got := derivePerAuthSessionID(inStr, makeAuth(authID))
		gotTS := extractV7TimestampMs(uuid.MustParse(got))
		if gotTS != wantTS {
			t.Errorf("auth %q: derived timestamp %d, want inbound %d", authID, gotTS, wantTS)
		}
	}
}

func TestDerivePerAuthSessionID_Timestamp_PinnedAtFirstCall_NonCodex(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")

	before := time.Now().UnixMilli()
	first := derivePerAuthSessionID(in, a)
	after := time.Now().UnixMilli()

	tsFirst := extractV7TimestampMs(uuid.MustParse(first))
	if tsFirst < before-100 || tsFirst > after+100 {
		t.Fatalf("first-call timestamp %d should be within [%d, %d]", tsFirst, before, after)
	}

	// Sleep just enough for time.Now() to advance, then call again. The
	// cached timestamp should be reused, so the new derive output must have
	// the SAME timestamp (not advance with the clock).
	time.Sleep(20 * time.Millisecond)
	second := derivePerAuthSessionID(in, a)
	tsSecond := extractV7TimestampMs(uuid.MustParse(second))
	if tsSecond != tsFirst {
		t.Fatalf("subsequent call must reuse cached timestamp: first=%d second=%d (clock advanced unexpectedly)", tsFirst, tsSecond)
	}
}

func TestDerivePerAuthSessionID_Timestamp_DifferentAuthsHaveIndependentCacheEntries(t *testing.T) {
	in := freshNonCodexInput(t)

	tsA1 := extractV7TimestampMs(uuid.MustParse(derivePerAuthSessionID(in, makeAuth("auth-A"))))
	time.Sleep(20 * time.Millisecond)
	tsB1 := extractV7TimestampMs(uuid.MustParse(derivePerAuthSessionID(in, makeAuth("auth-B"))))
	tsA2 := extractV7TimestampMs(uuid.MustParse(derivePerAuthSessionID(in, makeAuth("auth-A"))))
	tsB2 := extractV7TimestampMs(uuid.MustParse(derivePerAuthSessionID(in, makeAuth("auth-B"))))

	if tsA1 != tsA2 {
		t.Errorf("auth-A timestamp not pinned across calls: %d vs %d", tsA1, tsA2)
	}
	if tsB1 != tsB2 {
		t.Errorf("auth-B timestamp not pinned across calls: %d vs %d", tsB1, tsB2)
	}
	if tsA1 == tsB1 {
		t.Errorf("auth-A and auth-B share the same cache slot: both %d (independent cache entries expected)", tsA1)
	}
}

// ---------------------------------------------------------------------------
// §4 Cross-input distinctness
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_DifferentInputs_DifferentOutputs(t *testing.T) {
	a := makeAuth("auth-A")

	x := freshCodexV7Input(t)
	y := freshCodexV7Input(t)
	if x == y {
		t.Fatalf("setup error: expected two different v7 inputs, got %q twice", x)
	}

	sx := derivePerAuthSessionID(x, a)
	sy := derivePerAuthSessionID(y, a)
	if sx == sy {
		t.Fatalf("different inputs must produce different outputs: %q == %q", sx, sy)
	}
}

func TestDerivePerAuthSessionID_DifferentAuths_DifferentOutputs(t *testing.T) {
	in := freshCodexV7Input(t)

	sA := derivePerAuthSessionID(in, makeAuth("auth-A"))
	sB := derivePerAuthSessionID(in, makeAuth("auth-B"))
	if sA == sB {
		t.Fatalf("different auths must produce different outputs: A=B=%q", sA)
	}
}

// ---------------------------------------------------------------------------
// §5 Edge cases — function must be safe to call with degenerate inputs.
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_EmptyOriginalID_ReturnsEmpty(t *testing.T) {
	if got := derivePerAuthSessionID("", makeAuth("auth-A")); got != "" {
		t.Fatalf("empty originalID should yield empty output, got %q", got)
	}
	if got := derivePerAuthSessionID("   ", makeAuth("auth-A")); got != "" {
		t.Fatalf("whitespace-only originalID should yield empty output, got %q", got)
	}
}

func TestDerivePerAuthSessionID_NilAuth_ReturnsOriginal(t *testing.T) {
	in := freshCodexV7Input(t)
	if got := derivePerAuthSessionID(in, nil); got != in {
		t.Fatalf("nil auth must pass-through originalID, got %q want %q", got, in)
	}
}

func TestDerivePerAuthSessionID_EmptyAuthID_ReturnsOriginal(t *testing.T) {
	in := freshCodexV7Input(t)
	if got := derivePerAuthSessionID(in, makeAuth("")); got != in {
		t.Fatalf("empty auth.ID must pass-through originalID, got %q want %q", got, in)
	}
	if got := derivePerAuthSessionID(in, makeAuth("   ")); got != in {
		t.Fatalf("whitespace-only auth.ID must pass-through originalID, got %q want %q", got, in)
	}
}

func TestDerivePerAuthSessionID_NonV7Inbound_OutputsV7(t *testing.T) {
	// uuid.NewSHA1 produces v5; uuid.New produces v4. The proxy must NOT
	// mirror these versions to upstream — real Codex CLI only ever emits v7.
	v4 := uuid.New().String()
	v5 := uuid.NewSHA1(uuid.NameSpaceOID, []byte("test")).String()

	for _, in := range []string{v4, v5, "not-a-uuid-at-all", freshNonCodexInput(t)} {
		got := derivePerAuthSessionID(in, makeAuth("auth-A"))
		assertLooksLikeRealCodexSessionID(t, got)
	}
}

// ---------------------------------------------------------------------------
// §6 Structural validity — every output is a valid v7-looking UUID.
//    (The detail check is in assertLooksLikeRealCodexSessionID, defined in
//    codex_executor_cache_test.go in the same package.)
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_StructurallyValidV7(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"v7 inbound", freshCodexV7Input(t)},
		{"v4 inbound", uuid.New().String()},
		{"v5 inbound", uuid.NewSHA1(uuid.NameSpaceOID, []byte("seed")).String()},
		{"non-uuid string", "arbitrary-key-123"},
		{"long opaque", freshNonCodexInput(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := derivePerAuthSessionID(tc.in, makeAuth("auth-A"))
			assertLooksLikeRealCodexSessionID(t, got)
		})
	}
}

// ---------------------------------------------------------------------------
// §7 Concurrency safety — many goroutines hitting the same input must all
//    agree on the output (cache mutex correctness).
// ---------------------------------------------------------------------------

func TestDerivePerAuthSessionID_ConcurrentSameInput_AllAgree(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")

	const goroutines = 64
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results = make(map[string]int, goroutines)
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			got := derivePerAuthSessionID(in, a)
			mu.Lock()
			results[got]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) != 1 {
		t.Fatalf("concurrent calls disagreed: %d distinct outputs %v", len(results), results)
	}
}
