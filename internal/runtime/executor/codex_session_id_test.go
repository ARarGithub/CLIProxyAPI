package executor

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Focused unit-test suite for the two derive streams (derivedSessionID +
// derivedThreadID). Tests are grouped by guarantee:
//
//   §1 Determinism — same inputs always return the same output.
//   §2 Auth-switching round-trip — returning to a previous auth restores the
//      previous derived value (so per-account upstream prompt cache hits).
//   §3 Timestamp correctness — borrowed from inbound v7 / pinned via cache.
//   §4 Cross-input distinctness.
//   §5 Cross-stream distinctness — derivedSessionID ≠ derivedThreadID even
//      with identical (originalID, auth.ID), so that prompt_cache_key (= thread
//      stream) never equals Session_id (= session stream) — which would itself
//      be a fingerprint, since real Codex CLI never makes them equal.
//   §6 Edge cases (nil/empty, whitespace, non-v7 inbound).
//   §7 Structural validity — every output is a valid v7-looking UUID.
//   §8 Concurrency safety.
//
// See LEAK_RISKS.md L1, SESSION_ID_BEHAVIOR.md, MERGE_GUIDE.md "Session ID
// test suite", CODEX_CLI_REFERENCE.md.

func makeAuth(id string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{ID: id}
}

func freshNonCodexInput(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("non-uuid-input::%s::%d", t.Name(), time.Now().UnixNano())
}

func freshCodexV7Input(t *testing.T) string {
	t.Helper()
	return uuid.Must(uuid.NewV7()).String()
}

// derives is a small helper that returns both streams in one call so that
// tests asserting joint properties (e.g. cross-stream distinctness) read more
// naturally.
func derives(originalID string, auth *cliproxyauth.Auth) (sessionDerived, threadDerived string) {
	return derivedSessionID(originalID, auth), derivedThreadID(originalID, auth)
}

// ---------------------------------------------------------------------------
// §1 Determinism
// ---------------------------------------------------------------------------

func TestDerive_Deterministic_CodexDirect(t *testing.T) {
	in := freshCodexV7Input(t)
	a := makeAuth("auth-A")

	sFirst, tFirst := derives(in, a)
	for i := 0; i < 50; i++ {
		s, th := derives(in, a)
		if s != sFirst || th != tFirst {
			t.Fatalf("call %d: derived values changed across calls (session %q→%q, thread %q→%q)",
				i, sFirst, s, tFirst, th)
		}
	}
}

func TestDerive_Deterministic_NonCodex(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")

	sFirst, tFirst := derives(in, a)
	for i := 0; i < 50; i++ {
		s, th := derives(in, a)
		if s != sFirst || th != tFirst {
			t.Fatalf("call %d: derived values changed across calls (session %q→%q, thread %q→%q)",
				i, sFirst, s, tFirst, th)
		}
	}
}

// ---------------------------------------------------------------------------
// §2 Auth-switching round-trip — must hold for BOTH streams independently.
// ---------------------------------------------------------------------------

func TestDerive_AuthSwitching_RoundTrip_CodexDirect(t *testing.T) {
	in := freshCodexV7Input(t)
	a := makeAuth("auth-A")
	b := makeAuth("auth-B")

	sA0, tA0 := derives(in, a)
	sB0, tB0 := derives(in, b)
	sA1, tA1 := derives(in, a)
	sB1, tB1 := derives(in, b)

	if sA0 != sA1 || tA0 != tA1 {
		t.Fatalf("auth A round-trip not stable: session %q→%q, thread %q→%q", sA0, sA1, tA0, tA1)
	}
	if sB0 != sB1 || tB0 != tB1 {
		t.Fatalf("auth B round-trip not stable: session %q→%q, thread %q→%q", sB0, sB1, tB0, tB1)
	}
	if sA0 == sB0 {
		t.Fatalf("session stream leaked across auths: A=B=%q", sA0)
	}
	if tA0 == tB0 {
		t.Fatalf("thread stream leaked across auths: A=B=%q", tA0)
	}
}

func TestDerive_AuthSwitching_RoundTrip_NonCodex(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")
	b := makeAuth("auth-B")

	sA0, tA0 := derives(in, a)
	sB0, tB0 := derives(in, b)
	sA1, tA1 := derives(in, a)
	sB1, tB1 := derives(in, b)

	if sA0 != sA1 || tA0 != tA1 || sB0 != sB1 || tB0 != tB1 {
		t.Fatalf("round-trip not stable across auth-A/B: %q %q %q %q %q %q %q %q",
			sA0, sA1, tA0, tA1, sB0, sB1, tB0, tB1)
	}
	if sA0 == sB0 || tA0 == tB0 {
		t.Fatalf("cross-auth leak: session A=B=%q? thread A=B=%q?", sA0, tA0)
	}
}

// ---------------------------------------------------------------------------
// §3 Timestamp correctness
// ---------------------------------------------------------------------------

func TestDerive_Timestamp_BorrowedFromInboundV7(t *testing.T) {
	inStr := freshCodexV7Input(t)
	wantTS := extractV7TimestampMs(uuid.MustParse(inStr))

	for _, authID := range []string{"auth-A", "auth-B", "auth-some-long-id-xyz"} {
		auth := makeAuth(authID)
		s, th := derives(inStr, auth)
		for _, sid := range []string{s, th} {
			gotTS := extractV7TimestampMs(uuid.MustParse(sid))
			if gotTS != wantTS {
				t.Errorf("auth %q: derived %q timestamp %d, want inbound %d", authID, sid, gotTS, wantTS)
			}
		}
	}
}

func TestDerive_Timestamp_PinnedAtFirstCall_NonCodex(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")

	before := time.Now().UnixMilli()
	s1, t1 := derives(in, a)
	after := time.Now().UnixMilli()

	for _, sid := range []string{s1, t1} {
		ts := extractV7TimestampMs(uuid.MustParse(sid))
		if ts < before-100 || ts > after+100 {
			t.Fatalf("first-call timestamp %d should be in [%d, %d] (sid=%s)", ts, before, after, sid)
		}
	}

	time.Sleep(20 * time.Millisecond)
	s2, t2 := derives(in, a)
	if s1 != s2 {
		t.Fatalf("session stream timestamp changed across calls (cache should pin): %q vs %q", s1, s2)
	}
	if t1 != t2 {
		t.Fatalf("thread stream timestamp changed across calls (cache should pin): %q vs %q", t1, t2)
	}
}

// ---------------------------------------------------------------------------
// §4 Cross-input distinctness
// ---------------------------------------------------------------------------

func TestDerive_DifferentInputs_DifferentOutputs(t *testing.T) {
	a := makeAuth("auth-A")
	x := freshCodexV7Input(t)
	y := freshCodexV7Input(t)
	if x == y {
		t.Fatalf("setup: expected two different v7 inputs")
	}

	sX, tX := derives(x, a)
	sY, tY := derives(y, a)
	if sX == sY {
		t.Fatalf("session stream collapsed inputs: %q == %q", sX, sY)
	}
	if tX == tY {
		t.Fatalf("thread stream collapsed inputs: %q == %q", tX, tY)
	}
}

// ---------------------------------------------------------------------------
// §5 Cross-stream distinctness — THE central guarantee of the two-stream
//    redesign. Real Codex CLI sends session_id ≠ thread_id (= prompt_cache_key)
//    and our derive must mirror that, so that body.prompt_cache_key !=
//    header.Session_id at every layer.
// ---------------------------------------------------------------------------

func TestDerive_CrossStream_AlwaysDistinct_CodexDirect(t *testing.T) {
	for i := 0; i < 50; i++ {
		in := freshCodexV7Input(t)
		auth := makeAuth(fmt.Sprintf("auth-%d", i))
		s, th := derives(in, auth)
		if s == th {
			t.Fatalf("trial %d: session derived == thread derived for input %q auth %q (both %q) — would leak Session_id == prompt_cache_key",
				i, in, auth.ID, s)
		}
	}
}

func TestDerive_CrossStream_AlwaysDistinct_NonCodex(t *testing.T) {
	for i := 0; i < 50; i++ {
		in := fmt.Sprintf("non-uuid-input-%d-%d", i, time.Now().UnixNano())
		auth := makeAuth(fmt.Sprintf("auth-%d", i))
		s, th := derives(in, auth)
		if s == th {
			t.Fatalf("trial %d: session derived == thread derived for input %q auth %q (both %q)",
				i, in, auth.ID, s)
		}
	}
}

// ---------------------------------------------------------------------------
// §6 Edge cases
// ---------------------------------------------------------------------------

func TestDerive_EmptyOriginalID_ReturnsEmpty(t *testing.T) {
	for _, fn := range []struct {
		name string
		f    func(string, *cliproxyauth.Auth) string
	}{
		{"derivedSessionID", derivedSessionID},
		{"derivedThreadID", derivedThreadID},
	} {
		if got := fn.f("", makeAuth("auth-A")); got != "" {
			t.Errorf("%s(\"\", ...) = %q, want \"\"", fn.name, got)
		}
		if got := fn.f("   ", makeAuth("auth-A")); got != "" {
			t.Errorf("%s(\"   \", ...) = %q, want \"\"", fn.name, got)
		}
	}
}

func TestDerive_NilAuth_ReturnsOriginal(t *testing.T) {
	in := freshCodexV7Input(t)
	if got := derivedSessionID(in, nil); got != in {
		t.Errorf("derivedSessionID(in, nil) = %q, want %q", got, in)
	}
	if got := derivedThreadID(in, nil); got != in {
		t.Errorf("derivedThreadID(in, nil) = %q, want %q", got, in)
	}
}

func TestDerive_EmptyAuthID_ReturnsOriginal(t *testing.T) {
	in := freshCodexV7Input(t)
	for _, authID := range []string{"", "   "} {
		auth := makeAuth(authID)
		if got := derivedSessionID(in, auth); got != in {
			t.Errorf("derivedSessionID(in, auth.ID=%q) = %q, want %q", authID, got, in)
		}
		if got := derivedThreadID(in, auth); got != in {
			t.Errorf("derivedThreadID(in, auth.ID=%q) = %q, want %q", authID, got, in)
		}
	}
}

func TestDerive_NonV7Inbound_OutputsV7(t *testing.T) {
	v4 := uuid.New().String()
	v5 := uuid.NewSHA1(uuid.NameSpaceOID, []byte("test")).String()

	for _, in := range []string{v4, v5, "not-a-uuid", freshNonCodexInput(t)} {
		auth := makeAuth("auth-A")
		s, th := derives(in, auth)
		assertLooksLikeRealCodexSessionID(t, s)
		assertLooksLikeRealCodexSessionID(t, th)
	}
}

// ---------------------------------------------------------------------------
// §7 Structural validity
// ---------------------------------------------------------------------------

func TestDerive_StructurallyValidV7(t *testing.T) {
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
			auth := makeAuth("auth-A")
			s, th := derives(tc.in, auth)
			assertLooksLikeRealCodexSessionID(t, s)
			assertLooksLikeRealCodexSessionID(t, th)
		})
	}
}

// ---------------------------------------------------------------------------
// §8 Concurrency safety — both streams' caches must be mutex-correct.
// ---------------------------------------------------------------------------

func TestDerive_ConcurrentSameInput_AllAgree(t *testing.T) {
	in := freshNonCodexInput(t)
	a := makeAuth("auth-A")

	const goroutines = 64
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		sessions = make(map[string]int)
		threads  = make(map[string]int)
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			s, th := derives(in, a)
			mu.Lock()
			sessions[s]++
			threads[th]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(sessions) != 1 {
		t.Fatalf("session stream: concurrent calls disagreed: %v", sessions)
	}
	if len(threads) != 1 {
		t.Fatalf("thread stream: concurrent calls disagreed: %v", threads)
	}
}
