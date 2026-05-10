package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// applyCodexFingerprintHardeningHTTP is the single hook point through which
// every Codex-bound HTTP request passes after upstream's cacheHelper +
// applyCodexHeaders have built it. It overwrites the session-correlating
// headers / body fields with per-auth derived values that look like real
// Codex CLI output (UUIDv7 with mirrored or pinned timestamps; UUIDv4 for
// installation_id; "{uuid}:{int}" composite for window_id).
//
// Single-hook design rationale: confining all fingerprint logic to ONE
// function called from each Execute variant minimises the surface area we
// touch in upstream-controlled files. Upstream is free to change cacheHelper
// or applyCodexHeaders; we read the wire-shaped output (httpReq.Body +
// httpReq.Header), recompute, and write back. See LEAK_RISKS.md L1 + F + G,
// SESSION_ID_BEHAVIOR.md, MERGE_GUIDE.md "L1 不變式" table.
//
// Idempotent: calling twice yields the same outcome (deterministic compute
// from the same inputs).
func applyCodexFingerprintHardeningHTTP(ctx context.Context, httpReq *http.Request, auth *cliproxyauth.Auth, url string) error {
	if httpReq == nil {
		return nil
	}

	bodyBytes, err := drainRequestBody(httpReq)
	if err != nil {
		return fmt.Errorf("codex hardening: read request body: %w", err)
	}

	values := computeCodexFingerprintValues(ctx, bodyBytes, httpReq.Header, auth)

	bodyBytes = applyCodexFingerprintBody(bodyBytes, values, false /*includeWindowID*/)
	resetRequestBody(httpReq, bodyBytes)

	applyCodexFingerprintHeaders(httpReq.Header, values, isCompactCodexURL(url), false /*lowercaseKeys*/)

	return nil
}

// applyCodexFingerprintHardeningWS mirrors the HTTP variant for the websocket
// upgrade path. WS keeps body and headers as separate values rather than an
// http.Request, and emits a richer client_metadata (window_id sits in the
// body too, not just the header). Headers are written with case-preserved
// lowercase keys to match real Codex CLI's hyper output.
//
// Also strips the legacy `Conversation_id` header. Upstream's
// applyCodexPromptCacheHeaders sets that header from the synthesized
// cache.ID, but real Codex CLI never sends it (verified against
// codex-rs/core/src/client.rs:build_websocket_headers — see
// CODEX_CLI_REFERENCE.md §A). Removing it post-facto keeps the upstream
// function intact and concentrates our divergence here.
func applyCodexFingerprintHardeningWS(ctx context.Context, body []byte, headers http.Header, auth *cliproxyauth.Auth) ([]byte, http.Header) {
	if headers == nil {
		headers = http.Header{}
	}

	values := computeCodexFingerprintValues(ctx, body, headers, auth)

	body = applyCodexFingerprintBody(body, values, true /*includeWindowID*/)
	applyCodexFingerprintHeaders(headers, values, false /*compact never on WS*/, true /*lowercaseKeys*/)

	// Strip the upstream-fabricated Conversation_id header (real Codex CLI
	// never sends it). Cover any case variant the upstream may use.
	for _, key := range []string{"Conversation_id", "Conversation-Id", "conversation_id", "conversation-id"} {
		headers.Del(key)
	}

	return body, headers
}

// codexFingerprintValues holds the derived fields that get written to the
// outgoing request. All four must be either all empty or all set; in
// practice they're produced together from one auth + one inbound snapshot.
type codexFingerprintValues struct {
	sessionDerived string
	threadDerived  string
	windowID       string
	installationID string
}

// computeCodexFingerprintValues extracts inbound session_id / thread_id /
// window_id from the gin context (codex direct path) plus already-set values
// in the request body / headers (non-codex paths where cacheHelper synthesises
// a single cache.ID), then runs each through the per-auth derive pipeline.
func computeCodexFingerprintValues(ctx context.Context, body []byte, headers http.Header, auth *cliproxyauth.Auth) codexFingerprintValues {
	var inboundSession, inboundThread, inboundWindow string
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		inboundSession = strings.TrimSpace(ginCtx.GetHeader("Session_id"))
		inboundThread = strings.TrimSpace(ginCtx.GetHeader("Thread_id"))
		inboundWindow = strings.TrimSpace(ginCtx.GetHeader("X-Codex-Window-Id"))
	}
	// Non-codex paths: cacheHelper / applyCodexPromptCacheHeaders puts the
	// synthesised cache.ID into the Session_id header and the body's
	// prompt_cache_key. Use those as the inbound source for derive when the
	// gin context didn't supply one directly.
	if inboundSession == "" {
		inboundSession = strings.TrimSpace(headerValueCaseInsensitive(headers, "session_id"))
	}
	if inboundThread == "" {
		if pck := gjson.GetBytes(body, "prompt_cache_key"); pck.Exists() {
			inboundThread = strings.TrimSpace(pck.String())
		}
	}
	if inboundSession == "" {
		inboundSession = inboundThread
	}
	if inboundThread == "" {
		inboundThread = inboundSession
	}

	threadDerived := derivedThreadID(inboundThread, auth)
	return codexFingerprintValues{
		sessionDerived: derivedSessionID(inboundSession, auth),
		threadDerived:  threadDerived,
		windowID:       codexWindowID(threadDerived, parseInboundWindowGeneration(inboundWindow)),
		installationID: codexInstallationIDForAuth(auth),
	}
}

// applyCodexFingerprintBody writes the derived prompt_cache_key (= thread)
// and client_metadata.x-codex-installation-id into a request body. WS path
// also writes client_metadata.x-codex-window-id (real Codex CLI's WS body
// carries it; HTTP body does not).
func applyCodexFingerprintBody(body []byte, v codexFingerprintValues, includeWindowID bool) []byte {
	if v.threadDerived != "" {
		body, _ = sjson.SetBytes(body, "prompt_cache_key", v.threadDerived)
	}
	if v.installationID != "" {
		body, _ = sjson.SetBytes(body, "client_metadata.x-codex-installation-id", v.installationID)
	}
	if includeWindowID && v.windowID != "" {
		body, _ = sjson.SetBytes(body, "client_metadata.x-codex-window-id", v.windowID)
	}
	return body
}

// applyCodexFingerprintHeaders overrides the four header families that real
// Codex CLI sends. compactPath additionally emits X-Codex-Installation-Id as
// a header (real Codex CLI's compact route is the only HTTP path that does
// this). lowercaseKeys=true uses the case-preserved lowercase header names
// real Codex CLI emits over the websocket upgrade.
func applyCodexFingerprintHeaders(headers http.Header, v codexFingerprintValues, compactPath, lowercaseKeys bool) {
	setHeader := func(name, value string) {
		if value == "" {
			return
		}
		if lowercaseKeys {
			setHeaderCasePreserved(headers, name, value)
		} else {
			headers.Set(name, value)
		}
	}
	if lowercaseKeys {
		setHeader("session_id", v.sessionDerived)
		setHeader("thread_id", v.threadDerived)
		setHeader("x-client-request-id", v.threadDerived)
		setHeader("x-codex-window-id", v.windowID)
	} else {
		setHeader("Session_id", v.sessionDerived)
		setHeader("Thread_id", v.threadDerived)
		setHeader("X-Client-Request-Id", v.threadDerived)
		setHeader("X-Codex-Window-Id", v.windowID)
	}
	if compactPath && v.installationID != "" {
		// Compact path is HTTP-only; lowercase variant never used here.
		headers.Set("X-Codex-Installation-Id", v.installationID)
	}
}

// drainRequestBody fully reads + closes httpReq.Body so the caller can mutate
// the bytes and reset via resetRequestBody.
func drainRequestBody(httpReq *http.Request) ([]byte, error) {
	if httpReq.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(httpReq.Body)
	if cerr := httpReq.Body.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return b, err
}

// resetRequestBody installs a fresh ReadCloser over body, updates
// ContentLength, and provides a GetBody for retry safety. The Go transport
// uses GetBody to retry idempotent requests after early connection close.
func resetRequestBody(httpReq *http.Request, body []byte) {
	httpReq.Body = io.NopCloser(bytes.NewReader(body))
	httpReq.ContentLength = int64(len(body))
	bodySnapshot := body
	httpReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
	}
}

// isCompactCodexURL detects upstream's compact-route URLs so the hardening
// emits the path-specific X-Codex-Installation-Id header. Real Codex CLI's
// compact route is the only HTTP path that emits installation_id as a header.
func isCompactCodexURL(url string) bool {
	return strings.Contains(url, "/responses/compact")
}
