package executor

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// All assertions in this file deliberately check STRUCTURAL properties of the
// derived Session_id / Thread_id / prompt_cache_key (cross-auth distinct,
// within-auth stable, valid v7 UUID with recent timestamp, Session_id !=
// prompt_cache_key) rather than hardcoding a specific SHA1-derived value.
//
// Tests exercise applyCodexFingerprintHardeningHTTP — the single hook that
// runs after upstream's cacheHelper + applyCodexHeaders have built httpReq.
// Each test mints a synthetic post-cacheHelper httpReq (body + Session_id
// header pre-populated to mimic what upstream's cacheHelper would have done
// for the corresponding `from` path) and asserts what hardening overrides.

// newPostCacheHelperRequest builds the httpReq state we'd see right after
// upstream's cacheHelper returns, ready to be passed to the hardening hook.
//
// upstreamCacheID mirrors what upstream's cacheHelper put into the body's
// prompt_cache_key and the Session_id header for non-codex paths. For the
// codex direct path pass "" — the inbound session/thread are then taken from
// gin context only.
func newPostCacheHelperRequest(t *testing.T, ctx context.Context, url string, upstreamCacheID string) *http.Request {
	t.Helper()
	body := []byte(`{"model":"gpt-5.3-codex","stream":true}`)
	if upstreamCacheID != "" {
		// Mimic upstream's cacheHelper sjson.SetBytes(prompt_cache_key).
		body = []byte(`{"model":"gpt-5.3-codex","stream":true,"prompt_cache_key":"` + upstreamCacheID + `"}`)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build httpReq: %v", err)
	}
	if upstreamCacheID != "" {
		httpReq.Header.Set("Session_id", upstreamCacheID)
	}
	return httpReq
}

func TestCodexFingerprintHardeningHTTP_OpenAIChat_StableWithinAuth(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Set("userApiKey", "test-api-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	cacheID := "shared-cache-id-from-upstream-cacheHelper"
	url := "https://example.com/responses"

	r1 := newPostCacheHelperRequest(t, ctx, url, cacheID)
	if err := applyCodexFingerprintHardeningHTTP(ctx, r1, auth, url); err != nil {
		t.Fatalf("hardening error: %v", err)
	}
	body1, _ := io.ReadAll(r1.Body)
	sid1 := r1.Header.Get("Session_id")
	tid1 := r1.Header.Get("Thread_id")
	xrid1 := r1.Header.Get("X-Client-Request-Id")
	pck1 := gjson.GetBytes(body1, "prompt_cache_key").String()
	inst1 := gjson.GetBytes(body1, "client_metadata.x-codex-installation-id").String()

	for _, v := range []string{sid1, tid1, xrid1, pck1, inst1} {
		if v == "" {
			t.Fatalf("missing required value: sid=%q tid=%q xrid=%q pck=%q inst=%q", sid1, tid1, xrid1, pck1, inst1)
		}
	}
	if sid1 == pck1 {
		t.Fatalf("Session_id (%q) == prompt_cache_key — real Codex CLI never makes them equal", sid1)
	}
	if tid1 != pck1 {
		t.Fatalf("Thread_id (%q) must equal prompt_cache_key (%q)", tid1, pck1)
	}
	if xrid1 != tid1 {
		t.Fatalf("X-Client-Request-Id (%q) must equal Thread_id (%q)", xrid1, tid1)
	}
	assertLooksLikeRealCodexSessionID(t, sid1)
	assertLooksLikeRealCodexSessionID(t, tid1)

	// Second call with same auth + same cacheID must produce the same outputs.
	r2 := newPostCacheHelperRequest(t, ctx, url, cacheID)
	if err := applyCodexFingerprintHardeningHTTP(ctx, r2, auth, url); err != nil {
		t.Fatalf("hardening error (2nd): %v", err)
	}
	if sid2 := r2.Header.Get("Session_id"); sid1 != sid2 {
		t.Fatalf("Session_id must be stable across calls: %q vs %q", sid1, sid2)
	}
	if tid2 := r2.Header.Get("Thread_id"); tid1 != tid2 {
		t.Fatalf("Thread_id must be stable across calls: %q vs %q", tid1, tid2)
	}
}

func TestCodexFingerprintHardeningHTTP_PerAuthDiffersAcrossAuths(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Set("userApiKey", "test-api-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}
	ensureCodexInstallationID(authA)
	ensureCodexInstallationID(authB)

	url := "https://example.com/responses"
	cacheID := "shared-cache-id"

	rA := newPostCacheHelperRequest(t, ctx, url, cacheID)
	if err := applyCodexFingerprintHardeningHTTP(ctx, rA, authA, url); err != nil {
		t.Fatalf("hardening error (A): %v", err)
	}
	rB := newPostCacheHelperRequest(t, ctx, url, cacheID)
	if err := applyCodexFingerprintHardeningHTTP(ctx, rB, authB, url); err != nil {
		t.Fatalf("hardening error (B): %v", err)
	}

	bodyA, _ := io.ReadAll(rA.Body)
	bodyB, _ := io.ReadAll(rB.Body)
	sidA, sidB := rA.Header.Get("Session_id"), rB.Header.Get("Session_id")
	tidA, tidB := rA.Header.Get("Thread_id"), rB.Header.Get("Thread_id")
	pckA := gjson.GetBytes(bodyA, "prompt_cache_key").String()
	pckB := gjson.GetBytes(bodyB, "prompt_cache_key").String()
	instA := gjson.GetBytes(bodyA, "client_metadata.x-codex-installation-id").String()
	instB := gjson.GetBytes(bodyB, "client_metadata.x-codex-installation-id").String()

	for _, v := range []string{sidA, sidB, tidA, tidB, pckA, pckB, instA, instB} {
		if v == "" {
			t.Fatalf("missing required value")
		}
	}
	if sidA == sidB {
		t.Fatalf("Session_id leaked across auths: %q", sidA)
	}
	if tidA == tidB {
		t.Fatalf("Thread_id leaked across auths: %q", tidA)
	}
	if pckA == pckB {
		t.Fatalf("prompt_cache_key leaked across auths: %q", pckA)
	}
	if instA == instB {
		t.Fatalf("installation_id leaked across auths: %q", instA)
	}
	if sidA == tidA || sidB == tidB {
		t.Fatalf("Session_id == Thread_id (real Codex CLI never makes them equal)")
	}
	if pckA != tidA || pckB != tidB {
		t.Fatalf("prompt_cache_key must equal Thread_id")
	}
}

func TestCodexFingerprintHardeningHTTP_DirectCodex_MirrorsInboundV7Timestamp(t *testing.T) {
	// Real Codex CLI sends two distinct UUIDv7s as session_id and thread_id
	// headers. The hardening must extract each, derive a per-auth v7 that
	// preserves the corresponding inbound timestamp, and never let the raw
	// inbound value reach upstream.
	inboundSessionV7 := uuid.Must(uuid.NewV7()).String()
	inboundThreadV7 := uuid.Must(uuid.NewV7()).String()
	if inboundSessionV7 == inboundThreadV7 {
		t.Fatalf("setup: expected two different v7 inputs")
	}

	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Request.Header.Set("Session_id", inboundSessionV7)
	ginCtx.Request.Header.Set("Thread_id", inboundThreadV7)
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}
	ensureCodexInstallationID(authA)
	ensureCodexInstallationID(authB)

	url := "https://example.com/responses"
	rA := newPostCacheHelperRequest(t, ctx, url, "" /*codex direct: no upstream cache.ID*/)
	if err := applyCodexFingerprintHardeningHTTP(ctx, rA, authA, url); err != nil {
		t.Fatalf("hardening error (A): %v", err)
	}
	rB := newPostCacheHelperRequest(t, ctx, url, "")
	if err := applyCodexFingerprintHardeningHTTP(ctx, rB, authB, url); err != nil {
		t.Fatalf("hardening error (B): %v", err)
	}

	sidA, sidB := rA.Header.Get("Session_id"), rB.Header.Get("Session_id")
	tidA, tidB := rA.Header.Get("Thread_id"), rB.Header.Get("Thread_id")

	for _, raw := range []string{inboundSessionV7, inboundThreadV7} {
		if sidA == raw || sidB == raw || tidA == raw || tidB == raw {
			t.Fatalf("hardening forwarded raw inbound v7 (%q)", raw)
		}
	}
	if sidA == sidB || tidA == tidB {
		t.Fatalf("cross-auth leaked")
	}
	if sidA == tidA || sidB == tidB {
		t.Fatalf("Session_id == Thread_id within an auth")
	}

	for _, v := range []string{sidA, sidB, tidA, tidB} {
		assertLooksLikeRealCodexSessionID(t, v)
	}

	wantSessionTS := extractV7TimestampMs(uuid.MustParse(inboundSessionV7))
	wantThreadTS := extractV7TimestampMs(uuid.MustParse(inboundThreadV7))
	for _, sid := range []string{sidA, sidB} {
		if got := extractV7TimestampMs(uuid.MustParse(sid)); got != wantSessionTS {
			t.Errorf("session stream timestamp %d != inbound session %d", got, wantSessionTS)
		}
	}
	for _, tid := range []string{tidA, tidB} {
		if got := extractV7TimestampMs(uuid.MustParse(tid)); got != wantThreadTS {
			t.Errorf("thread stream timestamp %d != inbound thread %d", got, wantThreadTS)
		}
	}
}

func TestCodexFingerprintHardeningHTTP_CompactPath_AddsInstallationIDHeader(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Set("userApiKey", "test-api-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)
	wantInst, _ := auth.Metadata["installation_id"].(string)

	for _, tc := range []struct {
		name   string
		url    string
		expect bool
	}{
		{"compact path", "https://example.com/responses/compact", true},
		{"standard path", "https://example.com/responses", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPostCacheHelperRequest(t, ctx, tc.url, "cache-1")
			if err := applyCodexFingerprintHardeningHTTP(ctx, r, auth, tc.url); err != nil {
				t.Fatalf("hardening error: %v", err)
			}
			got := r.Header.Get("X-Codex-Installation-Id")
			if tc.expect {
				if got != wantInst {
					t.Fatalf("compact path: X-Codex-Installation-Id = %q, want %q", got, wantInst)
				}
			} else {
				if got != "" {
					t.Fatalf("standard path: X-Codex-Installation-Id should be empty, got %q", got)
				}
			}
		})
	}
}

func TestCodexFingerprintHardeningHTTP_BodyResetIsRetrySafe(t *testing.T) {
	// httpReq.GetBody must produce a fresh reader so the Go transport can
	// retry idempotent requests after early connection close.
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Set("userApiKey", "test-api-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	url := "https://example.com/responses"
	r := newPostCacheHelperRequest(t, ctx, url, "cache-1")
	if err := applyCodexFingerprintHardeningHTTP(ctx, r, auth, url); err != nil {
		t.Fatalf("hardening error: %v", err)
	}
	if r.GetBody == nil {
		t.Fatal("GetBody should be set after hardening")
	}
	first, err := r.GetBody()
	if err != nil {
		t.Fatalf("GetBody (1st): %v", err)
	}
	firstBytes, _ := io.ReadAll(first)
	second, err := r.GetBody()
	if err != nil {
		t.Fatalf("GetBody (2nd): %v", err)
	}
	secondBytes, _ := io.ReadAll(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("GetBody returned different bytes across calls: %q vs %q", firstBytes, secondBytes)
	}
	if int64(len(firstBytes)) != r.ContentLength {
		t.Fatalf("ContentLength %d != actual body length %d", r.ContentLength, len(firstBytes))
	}
	// Sanity: derived values are present.
	if pck := gjson.GetBytes(firstBytes, "prompt_cache_key").String(); pck == "" {
		t.Fatal("prompt_cache_key not set on retry-safe body")
	}
	_ = time.Now // silence unused import if we trim other deps later
}

// TestCodexFingerprintHardeningHTTP_ConditionalHeaders_ForwardedFromInbound
// verifies H: when the inbound codex direct request carries the conditional
// codex CLI headers, the hardening hook forwards subagent verbatim and
// derives parent_thread_id per-auth. Attestation is intentionally stripped
// (see hardening hook audit note): a forwarded attestation token would be
// cross-auth identical across pool dispatches of the same inbound, a clean
// correlation signal; and it would fail upstream binding-validation anyway.
func TestCodexFingerprintHardeningHTTP_ConditionalHeaders_ForwardedFromInbound(t *testing.T) {
	inboundParent := uuid.Must(uuid.NewV7()).String()
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Request.Header.Set("X-Openai-Subagent", "code-reviewer")
	ginCtx.Request.Header.Set("X-Codex-Parent-Thread-Id", inboundParent)
	ginCtx.Request.Header.Set("X-Oai-Attestation", "attestation-token-xyz")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	url := "https://example.com/responses"
	r := newPostCacheHelperRequest(t, ctx, url, "" /*codex direct path*/)
	if err := applyCodexFingerprintHardeningHTTP(ctx, r, auth, url); err != nil {
		t.Fatalf("hardening: %v", err)
	}

	if got := r.Header.Get("X-Openai-Subagent"); got != "code-reviewer" {
		t.Fatalf("X-Openai-Subagent = %q, want verbatim passthrough %q", got, "code-reviewer")
	}
	if got := r.Header.Get("X-Oai-Attestation"); got != "" {
		t.Fatalf("X-Oai-Attestation should be stripped (cross-auth correlation risk + invalid binding); got %q", got)
	}
	parentOut := r.Header.Get("X-Codex-Parent-Thread-Id")
	if parentOut == "" {
		t.Fatal("X-Codex-Parent-Thread-Id should be forwarded when inbound has it")
	}
	if parentOut == inboundParent {
		t.Fatalf("X-Codex-Parent-Thread-Id forwarded verbatim (%q); must be per-auth derived to avoid cross-auth leak", parentOut)
	}
	assertLooksLikeRealCodexSessionID(t, parentOut)

	// The hardening derive maps (parent, auth) deterministically into the
	// thread namespace, so this should equal derivedThreadID(parent, auth).
	want := derivedThreadID(inboundParent, auth)
	if parentOut != want {
		t.Fatalf("X-Codex-Parent-Thread-Id = %q, want derivedThreadID(parent, auth) = %q", parentOut, want)
	}
}

// TestCodexFingerprintHardeningHTTP_ConditionalHeaders_AbsentWhenInboundAbsent
// verifies that on non-codex / non-subagent paths, the hardening hook does
// NOT synthesize the conditional headers. Real Codex CLI omits them outside
// subagent flow; if we always emitted them, the constant-value pattern would
// itself be a fingerprint. Attestation is always absent regardless (stripped).
func TestCodexFingerprintHardeningHTTP_ConditionalHeaders_AbsentWhenInboundAbsent(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Set("userApiKey", "test-api-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	url := "https://example.com/responses"
	r := newPostCacheHelperRequest(t, ctx, url, "cache-1" /*non-codex synthesis*/)
	if err := applyCodexFingerprintHardeningHTTP(ctx, r, auth, url); err != nil {
		t.Fatalf("hardening: %v", err)
	}

	for _, h := range []string{"X-Openai-Subagent", "X-Codex-Parent-Thread-Id", "X-Oai-Attestation"} {
		if got := r.Header.Get(h); got != "" {
			t.Errorf("%s should be absent on non-codex/non-subagent path; got %q", h, got)
		}
	}
}

// TestCodexFingerprintHardeningHTTP_Attestation_StrippedEvenWhenInboundPresent
// guards the attestation-strip invariant: even if inbound carries the header,
// the hardening hook MUST drop it. See computeCodexFingerprintValues for
// reasoning.
func TestCodexFingerprintHardeningHTTP_Attestation_StrippedEvenWhenInboundPresent(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Request.Header.Set("X-Oai-Attestation", "attestation-token-xyz")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	url := "https://example.com/responses"
	r := newPostCacheHelperRequest(t, ctx, url, "")
	// Pre-populate the outbound header to verify hardening strips even what
	// upstream might have copied through. Use multiple case variants — Go's
	// http.Header canonicalises on Set, but lowercase + mixed forms may
	// survive in test scaffolding.
	r.Header.Set("X-Oai-Attestation", "attestation-token-xyz")
	if err := applyCodexFingerprintHardeningHTTP(ctx, r, auth, url); err != nil {
		t.Fatalf("hardening: %v", err)
	}
	if got := r.Header.Get("X-Oai-Attestation"); got != "" {
		t.Fatalf("X-Oai-Attestation must be stripped, got %q", got)
	}
	for k := range r.Header {
		if strings.EqualFold(k, "x-oai-attestation") {
			t.Errorf("found attestation-like header %q in output; must be stripped", k)
		}
	}
}

// TestCodexFingerprintHardeningHTTP_ParentThreadID_DerivedPerAuth verifies the
// L1 invariant extends to parent_thread_id: two different auths sharing the
// same inbound parent must end up with different derived values upstream.
// Otherwise pooled accounts in a subagent flow could be correlated.
func TestCodexFingerprintHardeningHTTP_ParentThreadID_DerivedPerAuth(t *testing.T) {
	inboundParent := uuid.Must(uuid.NewV7()).String()

	doOnce := func(authID string) string {
		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = httptest.NewRequest("POST", "/", nil)
		ginCtx.Request.Header.Set("X-Codex-Parent-Thread-Id", inboundParent)
		ctx := context.WithValue(context.Background(), "gin", ginCtx)
		auth := &cliproxyauth.Auth{ID: authID}
		ensureCodexInstallationID(auth)
		url := "https://example.com/responses"
		r := newPostCacheHelperRequest(t, ctx, url, "")
		if err := applyCodexFingerprintHardeningHTTP(ctx, r, auth, url); err != nil {
			t.Fatalf("hardening (%s): %v", authID, err)
		}
		return r.Header.Get("X-Codex-Parent-Thread-Id")
	}

	a := doOnce("auth-A")
	b := doOnce("auth-B")
	if a == "" || b == "" {
		t.Fatalf("parent_thread_id missing: a=%q b=%q", a, b)
	}
	if a == b {
		t.Fatalf("LEAK: X-Codex-Parent-Thread-Id identical across auth-A and auth-B (%q)", a)
	}
	if a == inboundParent || b == inboundParent {
		t.Fatalf("parent_thread_id forwarded verbatim — must be per-auth derived")
	}
}
