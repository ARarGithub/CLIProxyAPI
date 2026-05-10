package executor

import (
	"crypto/sha1"
	"strings"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"

	"github.com/google/uuid"
)

// Codex CLI emits TWO independent UUIDv7 conversation identifiers per request:
//
//   session_id  — `state.session_id`, sent in the `session_id` / `session-id`
//                 headers.
//   thread_id   — `state.thread_id`, sent in the `thread_id` / `thread-id` and
//                 `x-client-request-id` headers AND as the body's
//                 `prompt_cache_key`.
//
// These are produced by separate `Uuid::now_v7()` calls in
// codex-rs/protocol/src/{session_id,thread_id}.rs so they share neither
// random bits nor (necessarily) timestamp. Setting Session_id ==
// prompt_cache_key — as the original CLIProxyAPI did — is itself a
// fingerprint, since real Codex CLI never makes them equal.
//
// derivedSessionID() and derivedThreadID() each produce a v7-mimicking UUID
// keyed by (originalID, auth.ID). They use distinct namespaces internally so
// the two outputs are guaranteed different even when they receive the same
// originalID — which is the common case for non-codex-direct paths where the
// proxy synthesises a single cache.ID from the inbound apiKey or user id.
//
// See LEAK_RISKS.md L1, SESSION_ID_BEHAVIOR.md, CODEX_CLI_REFERENCE.md §1/§3.
const (
	derivedSessionTimestampCacheTTL     = time.Hour
	derivedSessionTimestampCacheCleanup = 15 * time.Minute

	derivedSessionNamespace = "cli-proxy-api:codex:per-auth:session_id:v7"
	derivedThreadNamespace  = "cli-proxy-api:codex:per-auth:thread_id:v7"
)

// derivedSessionTimestampCache stores the timestamp first chosen for a given
// (namespace, originalID, auth.ID) tuple so that subsequent derive calls
// within the same session see a stable upstream UUID. Only consulted when the
// inbound originalID is NOT a parseable v7 UUID (i.e., non-codex-direct
// paths where there is no real client-supplied timestamp to mirror).
type derivedSessionTimestampCacheEntry struct {
	timestampMs int64
	expire      time.Time
}

var (
	derivedSessionTimestampCache     = make(map[string]derivedSessionTimestampCacheEntry)
	derivedSessionTimestampCacheMu   sync.Mutex
	derivedSessionTimestampCacheOnce sync.Once
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

// derivedSessionID returns the value to put in the upstream `session_id` /
// `session-id` headers. Mirrors the inbound v7 timestamp when the inbound is
// itself a v7 (codex direct path); otherwise pins via the timestamp cache.
//
// Cross-account distinct, within-account stable, always v7-looking.
func derivedSessionID(originalID string, auth *cliproxyauth.Auth) string {
	return deriveV7Mimic(derivedSessionNamespace, originalID, auth)
}

// derivedThreadID returns the value to put in the upstream `thread_id` /
// `thread-id` / `x-client-request-id` headers AND in the body's
// `prompt_cache_key` (real Codex CLI uses thread_id as prompt_cache_key).
//
// Same v7-mimic semantics as derivedSessionID but a different namespace, so
// derivedThreadID(x, a) ≠ derivedSessionID(x, a) for any (x, a) — the
// guarantee that real Codex CLI's session_id and thread_id are independent.
func derivedThreadID(originalID string, auth *cliproxyauth.Auth) string {
	return deriveV7Mimic(derivedThreadNamespace, originalID, auth)
}

// deriveV7Mimic is the shared core. Returns "" for empty input, returns the
// originalID unchanged when auth is nil or auth.ID is empty (test-friendly
// no-op).
func deriveV7Mimic(namespace, originalID string, auth *cliproxyauth.Auth) string {
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

	// v7 timestamp: borrow from inbound v7 if possible (codex direct), else
	// pin via the namespaced cache (non-codex paths).
	const version byte = 7
	var timestampMs int64
	if inU, err := uuid.Parse(originalID); err == nil && byte(inU.Version()) == 7 {
		timestampMs = extractV7TimestampMs(inU)
	}
	if timestampMs == 0 {
		// Cache key includes the namespace: derivedSessionID and
		// derivedThreadID with the same originalID still get independent
		// timestamps (and may pin them at slightly different wall-clock
		// times — within one ms in practice).
		timestampMs = cachedDerivedTimestampMs(namespace + "|" + authID + "|" + originalID)
	}

	// Entropy: SHA1 over (namespace, originalID, authID). The leading 6 bytes
	// are overwritten by the timestamp, so the entropy effectively fills
	// bytes 6..15 (rand_a + variant + rand_b).
	sum := sha1.Sum([]byte(namespace + ":" + originalID + ":" + authID))
	var u uuid.UUID
	copy(u[:], sum[:16])

	u[0] = byte(timestampMs >> 40)
	u[1] = byte(timestampMs >> 32)
	u[2] = byte(timestampMs >> 24)
	u[3] = byte(timestampMs >> 16)
	u[4] = byte(timestampMs >> 8)
	u[5] = byte(timestampMs)

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
