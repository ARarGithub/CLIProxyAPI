package executor

import (
	"crypto/sha1"
	"strings"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"

	"github.com/google/uuid"
)

// Session id derive constants.
//
// Real Codex CLI generates session_id as Uuid::now_v7() (see codex-rs/protocol/
// src/session_id.rs). UUIDv7 carries a 48-bit unix-millisecond timestamp in
// its leading bits, so a v7 produced by SHA1 alone would decode to a random
// year and stand out under a trivial check. The derive function below mimics
// v7 by setting the version + variant bits AND injecting a plausible recent
// timestamp.
//
// See LEAK_RISKS.md L1, SESSION_ID_BEHAVIOR.md.
const (
	derivedSessionTimestampCacheTTL     = time.Hour
	derivedSessionTimestampCacheCleanup = 15 * time.Minute
)

// derivedSessionTimestampCache stores the timestamp first chosen for a given
// (originalID, auth.ID) pair so that subsequent derive calls within the same
// session see a stable upstream UUID. Only used when the inbound originalID
// is NOT a parseable v7 UUID (i.e., non-codex-direct paths where there is no
// real client-supplied timestamp to mirror).
type derivedSessionTimestampCacheEntry struct {
	timestampMs int64
	expire      time.Time
}

var (
	derivedSessionTimestampCache       = make(map[string]derivedSessionTimestampCacheEntry)
	derivedSessionTimestampCacheMu     sync.Mutex
	derivedSessionTimestampCacheOnce   sync.Once
)

func startDerivedSessionTimestampCacheCleanup() {
	go func() {
		ticker := time.NewTicker(derivedSessionTimestampCacheCleanup)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			derivedSessionTimestampCacheMu.Lock()
			for k, entry := range derivedSessionTimestampCache {
				if !entry.expire.After(now) {
					delete(derivedSessionTimestampCache, k)
				}
			}
			derivedSessionTimestampCacheMu.Unlock()
		}
	}()
}

func cachedDerivedTimestampMs(cacheKey string) int64 {
	derivedSessionTimestampCacheOnce.Do(startDerivedSessionTimestampCacheCleanup)
	now := time.Now()
	derivedSessionTimestampCacheMu.Lock()
	defer derivedSessionTimestampCacheMu.Unlock()
	if entry, ok := derivedSessionTimestampCache[cacheKey]; ok && entry.expire.After(now) {
		entry.expire = now.Add(derivedSessionTimestampCacheTTL)
		derivedSessionTimestampCache[cacheKey] = entry
		return entry.timestampMs
	}
	ts := now.UnixMilli()
	derivedSessionTimestampCache[cacheKey] = derivedSessionTimestampCacheEntry{
		timestampMs: ts,
		expire:      now.Add(derivedSessionTimestampCacheTTL),
	}
	return ts
}

// derivePerAuthSessionID returns a session_id for upstream that is:
//  1. Cross-account distinct: same originalID with a different auth.ID always
//     produces a different output, so the upstream cannot correlate two OAuth
//     accounts onto the same session.
//  2. Within-account stable: same (originalID, auth.ID) returns the same
//     output, so per-account upstream prompt cache still hits.
//  3. Indistinguishable from a real Codex CLI session id by trivial structural
//     inspection: matches the inbound UUID version (defaulting to v7), and
//     for v7 carries a plausible recent timestamp in the leading 48 bits.
//
// Returns originalID unchanged when auth or auth.ID is empty (test-friendly
// no-op for unit tests that don't set up an auth).
//
// See LEAK_RISKS.md L1.
func derivePerAuthSessionID(originalID string, auth *cliproxyauth.Auth) string {
	originalID = strings.TrimSpace(originalID)
	if originalID == "" {
		return ""
	}
	if auth == nil {
		return originalID
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return originalID
	}

	// Real Codex CLI always emits UUIDv7. We always emit v7 too, regardless of
	// whatever shape the inbound originalID happens to be (a Codex client v7,
	// a SHA1-derived v5 we synthesized in cacheHelper for the openai chat
	// path, or arbitrary caller-supplied prompt_cache_key for openai-response).
	const version byte = 7
	var timestampMs int64
	if inU, err := uuid.Parse(originalID); err == nil && byte(inU.Version()) == 7 {
		// Codex direct path: borrow the client's real timestamp so upstream
		// sees a coherent "session started at this wall-clock time" value.
		timestampMs = extractV7TimestampMs(inU)
	}
	if timestampMs == 0 {
		// No real client timestamp available. Pin one at first sight per
		// (originalID, auth.ID) and reuse for the rest of the session.
		timestampMs = cachedDerivedTimestampMs(authID + "|" + originalID)
	}

	// Entropy: SHA1 over the (originalID, authID) pair. The first 6 bytes are
	// later overwritten by the timestamp, so the entropy effectively fills
	// bytes 6..15 (rand_a + variant + rand_b).
	sum := sha1.Sum([]byte("cli-proxy-api:codex:per-auth:v7:" + originalID + ":" + authID))
	var u uuid.UUID
	copy(u[:], sum[:16])

	// Inject 48-bit unix-ms timestamp into the leading bytes (v7 layout).
	u[0] = byte(timestampMs >> 40)
	u[1] = byte(timestampMs >> 32)
	u[2] = byte(timestampMs >> 24)
	u[3] = byte(timestampMs >> 16)
	u[4] = byte(timestampMs >> 8)
	u[5] = byte(timestampMs)

	// Set version (high 4 bits of byte 6) and RFC4122 variant (high 2 bits of byte 8).
	u[6] = (u[6] & 0x0f) | (version << 4)
	u[8] = (u[8] & 0x3f) | 0x80

	return u.String()
}

// extractV7TimestampMs reads the 48-bit unix-millisecond timestamp from the
// leading bytes of a UUIDv7. Caller is responsible for confirming the UUID
// is actually v7 (this function does no validation).
func extractV7TimestampMs(u uuid.UUID) int64 {
	return int64(u[0])<<40 |
		int64(u[1])<<32 |
		int64(u[2])<<24 |
		int64(u[3])<<16 |
		int64(u[4])<<8 |
		int64(u[5])
}
