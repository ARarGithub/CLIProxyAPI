package executor

import (
	"strconv"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"

	"github.com/google/uuid"
)

// installation_id and x-codex-window-id helpers.
//
// Real Codex CLI sends:
//
//   - body `client_metadata.x-codex-installation-id` = a UUIDv4 generated once
//     at first run and persisted to <codex_home>/installation_id (see
//     codex-rs/core/src/installation_id.rs). Stable per install.
//   - header `x-codex-window-id` = "{thread_id}:{window_generation}" where
//     thread_id is the same v7 in the thread headers and window_generation is
//     an AtomicU64 starting at 0, incremented on websocket session reset
//     (see codex-rs/core/src/client.rs:381-385).
//
// Fork-local mapping:
//
//   - installation_id is generated per OAuth account (NOT per install) and
//     persisted to auth.Metadata["installation_id"]. Different accounts get
//     different UUIDs (avoiding "single machine running many accounts" as a
//     pool fingerprint). See LEAK_RISKS.md F, CODEX_CLI_REFERENCE.md §6.F.
//   - window_id is built from the per-auth derived thread id (already
//     produced by derivedThreadID) plus a generation counter parsed from the
//     inbound x-codex-window-id header (codex direct path) or 0 otherwise.
//     See CODEX_CLI_REFERENCE.md §6.G.

// codexInstallationIDMetadataKey is the auth.Metadata key the fork uses to
// persist the per-auth installation_id. SDK does not look at this key, so we
// own its lifecycle entirely.
const codexInstallationIDMetadataKey = "installation_id"

// codexInstallationIDForAuth returns the persisted UUIDv4 for this auth, or
// an empty string if none is persisted yet. Callers that *must* emit a value
// (cacheHelper, applyCodexPromptCacheHeaders) treat empty as "skip injection";
// callers that mutate auth (Refresh, buildAuthRecord) set a fresh value via
// ensureCodexInstallationID below.
func codexInstallationIDForAuth(auth *cliproxyauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if v, ok := auth.Metadata[codexInstallationIDMetadataKey].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// ensureCodexInstallationID returns the existing per-auth installation_id if
// one is already persisted, or generates and persists a fresh UUIDv4 if not.
// installation_id is supposed to be stable per-install; we never overwrite an
// existing one (mirroring real Codex CLI's behaviour of reusing the value
// from <codex_home>/installation_id across runs).
//
// Caller must own auth.Metadata for writes; this is intended to be called
// during auth-creating / auth-mutating paths (buildAuthRecord, Refresh) where
// the manager treats the auth as exclusive.
func ensureCodexInstallationID(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if existing := codexInstallationIDForAuth(auth); existing != "" {
		return existing
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	id := uuid.New().String() // v4 by default in google/uuid
	auth.Metadata[codexInstallationIDMetadataKey] = id
	return id
}

// codexWindowID composes the value of the upstream x-codex-window-id header.
//
// Format: "{threadDerived}:{generation}". threadDerived MUST be the per-auth
// derived thread_id (same string as the Thread_id header / prompt_cache_key).
// generation is 0 by default; for the codex direct path the caller should
// parse the inbound header and pass the parsed generation here so that any
// websocket-session-reset increments propagate.
//
// Returns "" when threadDerived is empty.
func codexWindowID(threadDerived string, generation uint64) string {
	threadDerived = strings.TrimSpace(threadDerived)
	if threadDerived == "" {
		return ""
	}
	return threadDerived + ":" + strconv.FormatUint(generation, 10)
}

// parseInboundWindowGeneration extracts the generation suffix from a real
// Codex CLI x-codex-window-id ("{thread_uuid}:{integer}"). Returns 0 on any
// parse failure (which is the same as real client's startup state).
func parseInboundWindowGeneration(inbound string) uint64 {
	inbound = strings.TrimSpace(inbound)
	if inbound == "" {
		return 0
	}
	idx := strings.LastIndex(inbound, ":")
	if idx < 0 || idx == len(inbound)-1 {
		return 0
	}
	gen, err := strconv.ParseUint(inbound[idx+1:], 10, 64)
	if err != nil {
		return 0
	}
	return gen
}
