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
// derived Session_id / Thread_id / prompt_cache_key (cross-auth distinct,
// within-auth stable, valid v7 UUID with recent timestamp, Session_id !=
// prompt_cache_key) rather than hardcoding a specific SHA1-derived value.
// The derive algorithm is allowed to change as long as these properties hold.

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
	tid1 := httpReq1.Header.Get("Thread_id")
	xrid1 := httpReq1.Header.Get("X-Client-Request-Id")
	pck1 := gjson.GetBytes(body1, "prompt_cache_key").String()

	for _, v := range []string{sid1, tid1, xrid1, pck1} {
		if v == "" {
			t.Fatalf("missing required value: sid=%q tid=%q xrid=%q pck=%q", sid1, tid1, xrid1, pck1)
		}
	}
	if sid1 == pck1 {
		t.Fatalf("Session_id (%q) == prompt_cache_key — real Codex CLI never makes them equal", sid1)
	}
	if tid1 != pck1 {
		t.Fatalf("Thread_id (%q) must equal prompt_cache_key (%q) — real Codex CLI uses thread_id as prompt_cache_key", tid1, pck1)
	}
	if xrid1 != tid1 {
		t.Fatalf("X-Client-Request-Id (%q) must equal Thread_id (%q) — real Codex CLI uses thread_id as x-client-request-id", xrid1, tid1)
	}
	assertLooksLikeRealCodexSessionID(t, sid1)
	assertLooksLikeRealCodexSessionID(t, tid1)

	httpReq2, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON, auth)
	if err != nil {
		t.Fatalf("cacheHelper error (second call): %v", err)
	}
	if sid2 := httpReq2.Header.Get("Session_id"); sid1 != sid2 {
		t.Fatalf("Session_id must be stable across calls with same auth: %q vs %q", sid1, sid2)
	}
	if tid2 := httpReq2.Header.Get("Thread_id"); tid1 != tid2 {
		t.Fatalf("Thread_id must be stable across calls with same auth: %q vs %q", tid1, tid2)
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

	bodyA, _ := io.ReadAll(reqA.Body)
	bodyB, _ := io.ReadAll(reqB.Body)
	sidA, sidB := reqA.Header.Get("Session_id"), reqB.Header.Get("Session_id")
	tidA, tidB := reqA.Header.Get("Thread_id"), reqB.Header.Get("Thread_id")
	pckA := gjson.GetBytes(bodyA, "prompt_cache_key").String()
	pckB := gjson.GetBytes(bodyB, "prompt_cache_key").String()

	for _, v := range []string{sidA, sidB, tidA, tidB, pckA, pckB} {
		if v == "" {
			t.Fatalf("missing required value: sidA=%q sidB=%q tidA=%q tidB=%q pckA=%q pckB=%q", sidA, sidB, tidA, tidB, pckA, pckB)
		}
	}
	if sidA == sidB {
		t.Fatalf("Session_id leaked across auths: A=B=%q", sidA)
	}
	if tidA == tidB {
		t.Fatalf("Thread_id leaked across auths: A=B=%q", tidA)
	}
	if pckA == pckB {
		t.Fatalf("prompt_cache_key leaked across auths: A=B=%q", pckA)
	}
	if sidA == tidA || sidB == tidB {
		t.Fatalf("Session_id == Thread_id (A: %q vs %q; B: %q vs %q) — real Codex CLI never makes them equal", sidA, tidA, sidB, tidB)
	}
	if pckA != tidA || pckB != tidB {
		t.Fatalf("prompt_cache_key must equal Thread_id (A: %q vs %q; B: %q vs %q)", pckA, tidA, pckB, tidB)
	}
	assertLooksLikeRealCodexSessionID(t, sidA)
	assertLooksLikeRealCodexSessionID(t, sidB)
	assertLooksLikeRealCodexSessionID(t, tidA)
	assertLooksLikeRealCodexSessionID(t, tidB)
}

func TestCodexExecutorCacheHelper_DirectCodex_MirrorsInboundV7Timestamp(t *testing.T) {
	// Codex CLI sends a fresh UUIDv7 per session_id AND another fresh UUIDv7
	// per thread_id (two independent client-side now_v7() calls). The proxy
	// must produce derived UUIDs that:
	//   (a) borrow each inbound v7's timestamp into the corresponding stream
	//       (Session_id derived borrows from inbound Session_id, Thread_id
	//       derived borrows from inbound Thread_id);
	//   (b) differ across auths in the random portion;
	//   (c) NEVER pass the raw inbound through;
	//   (d) keep Session_id != Thread_id (they're different streams).
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

	sidA, sidB := reqA.Header.Get("Session_id"), reqB.Header.Get("Session_id")
	tidA, tidB := reqA.Header.Get("Thread_id"), reqB.Header.Get("Thread_id")

	for _, v := range []string{sidA, sidB, tidA, tidB} {
		if v == "" {
			t.Fatalf("missing required value: sidA=%q sidB=%q tidA=%q tidB=%q", sidA, sidB, tidA, tidB)
		}
	}
	for _, raw := range []string{inboundSessionV7, inboundThreadV7} {
		if sidA == raw || sidB == raw || tidA == raw || tidB == raw {
			t.Fatalf("direct path forwarded raw client v7 without derivation (raw=%q)", raw)
		}
	}
	if sidA == sidB {
		t.Fatalf("session stream leaked across auths: %q", sidA)
	}
	if tidA == tidB {
		t.Fatalf("thread stream leaked across auths: %q", tidA)
	}
	if sidA == tidA || sidB == tidB {
		t.Fatalf("Session_id == Thread_id within one auth (A: %q vs %q; B: %q vs %q)", sidA, tidA, sidB, tidB)
	}

	for _, v := range []string{sidA, sidB, tidA, tidB} {
		assertLooksLikeRealCodexSessionID(t, v)
	}

	// Cross-stream timestamp mirroring: each derived stream's timestamp must
	// match the corresponding inbound stream's timestamp.
	wantSessionTS := extractV7TimestampMs(uuid.MustParse(inboundSessionV7))
	wantThreadTS := extractV7TimestampMs(uuid.MustParse(inboundThreadV7))
	for _, sid := range []string{sidA, sidB} {
		if gotTS := extractV7TimestampMs(uuid.MustParse(sid)); gotTS != wantSessionTS {
			t.Errorf("session stream timestamp %d does not match inbound session %d (sid=%s)", gotTS, wantSessionTS, sid)
		}
	}
	for _, tid := range []string{tidA, tidB} {
		if gotTS := extractV7TimestampMs(uuid.MustParse(tid)); gotTS != wantThreadTS {
			t.Errorf("thread stream timestamp %d does not match inbound thread %d (tid=%s)", gotTS, wantThreadTS, tid)
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
