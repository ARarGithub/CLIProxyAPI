package executor

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// assertLooksLikeRealCodexSessionID verifies the derived value passes the
// trivial structural checks that the upstream Codex API could perform: parses
// as a UUID, has the expected version (7), variant bits are RFC4122, and (for
// v7) carries a timestamp within a plausible recent window.
//
// Used by the L1 / D / F / G test suites to pin the v7-mimic property.
// See LEAK_RISKS.md L1, CODEX_CLI_REFERENCE.md §3.5 / §6.
func assertLooksLikeRealCodexSessionID(t *testing.T, sid string) {
	t.Helper()
	u, err := uuid.Parse(sid)
	if err != nil {
		t.Fatalf("derived session_id %q is not a valid UUID: %v", sid, err)
	}
	if v := byte(u.Version()); v != 7 {
		t.Fatalf("derived session_id %q has version %d, want 7 (real Codex CLI uses Uuid::now_v7)", sid, v)
	}
	if u[8]&0xc0 != 0x80 {
		t.Fatalf("derived session_id %q has non-RFC4122 variant bits 0x%02x", sid, u[8])
	}
	tsMs := extractV7TimestampMs(u)
	now := time.Now().UnixMilli()
	const window = int64(30 * 24 * time.Hour / time.Millisecond)
	if tsMs > now+60_000 {
		t.Fatalf("derived v7 timestamp %d is in the future (now=%d)", tsMs, now)
	}
	if tsMs < now-window {
		t.Fatalf("derived v7 timestamp %d is older than %d days (now=%d) — looks fake", tsMs, window/(24*60*60*1000), now)
	}
}
