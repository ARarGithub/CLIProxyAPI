package executor

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// All assertions in this file deliberately check STRUCTURAL properties of the
// derived Session_id (cross-auth distinct, within-auth stable, body matches
// header, valid v7 UUID with recent timestamp) rather than hardcoding a
// specific SHA1-derived value. The derive algorithm is allowed to change as
// long as these properties hold.

func TestCodexExecutorCacheHelper_OpenAIChat_StableWithinAuth(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Set("userApiKey", "test-api-key")

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex","stream":true}`)
	req := cliproxyexecutor.Request{
		Model:   "gpt-5.3-codex",
		Payload: []byte(`{"model":"gpt-5.3-codex"}`),
	}
	url := "https://example.com/responses"
	auth := &cliproxyauth.Auth{ID: "auth-A"}

	httpReq1, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, auth)
	if err != nil {
		t.Fatalf("cacheHelper error: %v", err)
	}
	body1, _ := io.ReadAll(httpReq1.Body)
	sid1 := httpReq1.Header.Get("Session_id")
	pck1 := gjson.GetBytes(body1, "prompt_cache_key").String()

	if sid1 == "" {
		t.Fatal("Session_id missing")
	}
	if sid1 != pck1 {
		t.Fatalf("body prompt_cache_key (%q) must match header Session_id (%q)", pck1, sid1)
	}
	assertLooksLikeRealCodexSessionID(t, sid1)

	httpReq2, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, auth)
	if err != nil {
		t.Fatalf("cacheHelper error (second call): %v", err)
	}
	sid2 := httpReq2.Header.Get("Session_id")
	if sid1 != sid2 {
		t.Fatalf("Session_id must be stable across calls with same auth: %q vs %q", sid1, sid2)
	}
}

func TestCodexExecutorCacheHelper_PerAuthSessionIDDiffersAcrossAuths(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Set("userApiKey", "test-api-key")

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex","stream":true}`)
	req := cliproxyexecutor.Request{
		Model:   "gpt-5.3-codex",
		Payload: []byte(`{"model":"gpt-5.3-codex"}`),
	}
	url := "https://example.com/responses"

	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}

	reqA, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, authA)
	if err != nil {
		t.Fatalf("cacheHelper(authA) error: %v", err)
	}
	reqB, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, authB)
	if err != nil {
		t.Fatalf("cacheHelper(authB) error: %v", err)
	}

	sidA := reqA.Header.Get("Session_id")
	sidB := reqB.Header.Get("Session_id")
	if sidA == "" || sidB == "" {
		t.Fatalf("Session_id missing: A=%q B=%q", sidA, sidB)
	}
	if sidA == sidB {
		t.Fatalf("Session_id leaked across auths: A=B=%q (must differ)", sidA)
	}
	assertLooksLikeRealCodexSessionID(t, sidA)
	assertLooksLikeRealCodexSessionID(t, sidB)

	bodyA, _ := io.ReadAll(reqA.Body)
	bodyB, _ := io.ReadAll(reqB.Body)
	pckA := gjson.GetBytes(bodyA, "prompt_cache_key").String()
	pckB := gjson.GetBytes(bodyB, "prompt_cache_key").String()
	if pckA == pckB {
		t.Fatalf("prompt_cache_key leaked across auths: A=B=%q (must differ)", pckA)
	}
	if pckA != sidA || pckB != sidB {
		t.Fatalf("body prompt_cache_key must match header Session_id (A: %q vs %q; B: %q vs %q)", pckA, sidA, pckB, sidB)
	}
}

func TestCodexExecutorCacheHelper_DirectCodex_MirrorsInboundV7Timestamp(t *testing.T) {
	// Codex CLI sends a fresh UUIDv7 per session. The proxy should produce a
	// derived UUID that (a) carries the SAME timestamp as the inbound (so it
	// looks like the same session that started at the same wall-clock time),
	// (b) differs across auths in the random portion, (c) does NOT pass the
	// raw inbound through.
	inboundV7 := uuid.Must(uuid.NewV7()).String()

	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Request.Header.Set("Session_id", inboundV7)

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex"}`)
	req := cliproxyexecutor.Request{Model: "gpt-5.3-codex", Payload: []byte(`{}`)}
	url := "https://example.com/responses"

	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}

	reqA, err := executor.cacheHelper(ctx, sdktranslator.FromString("codex"), url, req, rawJSON, authA)
	if err != nil {
		t.Fatalf("cacheHelper(authA) error: %v", err)
	}
	reqB, err := executor.cacheHelper(ctx, sdktranslator.FromString("codex"), url, req, rawJSON, authB)
	if err != nil {
		t.Fatalf("cacheHelper(authB) error: %v", err)
	}

	sidA := reqA.Header.Get("Session_id")
	sidB := reqB.Header.Get("Session_id")
	if sidA == "" || sidB == "" {
		t.Fatalf("direct path did not set Session_id: A=%q B=%q", sidA, sidB)
	}
	if sidA == inboundV7 || sidB == inboundV7 {
		t.Fatalf("direct path forwarded raw client v7 without derivation: A=%q B=%q inbound=%q", sidA, sidB, inboundV7)
	}
	if sidA == sidB {
		t.Fatalf("direct path leaked session_id across auths: %q", sidA)
	}

	// Both derived UUIDs should look like real v7 sessions...
	assertLooksLikeRealCodexSessionID(t, sidA)
	assertLooksLikeRealCodexSessionID(t, sidB)

	// ...and specifically should have the SAME timestamp as the inbound.
	inU := uuid.MustParse(inboundV7)
	wantTS := extractV7TimestampMs(inU)
	for _, sid := range []string{sidA, sidB} {
		gotU := uuid.MustParse(sid)
		if gotTS := extractV7TimestampMs(gotU); gotTS != wantTS {
			t.Fatalf("derived v7 timestamp %d does not match inbound %d (sid=%s)", gotTS, wantTS, sid)
		}
	}
}

// assertLooksLikeRealCodexSessionID verifies the derived session_id passes the
// trivial structural checks that the upstream Codex API could perform: parses
// as a UUID, has the expected version (defaulting to 7), and (for v7) carries
// a timestamp within a plausible recent window.
func assertLooksLikeRealCodexSessionID(t *testing.T, sid string) {
	t.Helper()
	u, err := uuid.Parse(sid)
	if err != nil {
		t.Fatalf("derived session_id %q is not a valid UUID: %v", sid, err)
	}
	if v := u.Version(); byte(v) != 7 {
		t.Fatalf("derived session_id %q has version %d, want 7 (real Codex CLI uses Uuid::now_v7)", sid, v)
	}
	// Variant must be RFC4122 (high 2 bits of byte 8 = 10).
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
