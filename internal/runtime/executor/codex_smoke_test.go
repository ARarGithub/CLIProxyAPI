package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// Smoke tests for the Codex executor's full request pipeline.
//
// Distinct from codex_fingerprint_regression_test.go (which tests one auth
// per scenario in isolation) and from the unit tests in codex_session_id_test.go
// (which test the derive function directly). These tests drive the real
// CodexExecutor across a sequence of requests with auth switching, verifying:
//
//   - Cross-auth distinctness: A != B for all per-auth-derived values
//     (already covered by regression test for first-request semantics).
//   - Auth round-trip stability: A -> B -> A means the third request reaches
//     upstream with the SAME values as the first (the in-process cache must
//     pin per-auth values across intervening requests by other auths).
//     This is the prompt-cache-continuity invariant — if auth A's derived
//     prompt_cache_key shifted when a request to auth B ran between, the
//     OpenAI prompt cache for auth A would miss on resumption.
//
// The pipeline exercised: cliproxyexecutor.Request -> CodexExecutor.Execute
// -> cacheHelper -> applyCodexHeaders -> applyCodexFingerprintHardeningHTTP
// -> http.Client.Do -> recorded by fake upstream. Same code path as
// production except the gin handler layer is skipped (that layer's job is to
// build the cliproxyexecutor.Request from inbound HTTP and route to the
// right executor; both verified separately by handler-level tests).

func newSmokeUpstream(t *testing.T, recorded *[]recordedUpstreamRequest, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*recorded = append(*recorded, recordedUpstreamRequest{Headers: r.Header.Clone(), Body: body})
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":0,\"status\":\"completed\",\"background\":false,\"error\":null}}\n\n"))
	}))
}

// smokeRunOnce dispatches one request through CodexExecutor.Execute as the
// production handlers do (ctx carries the gin context that supplies inbound
// headers; auth carries the per-account state). Returns the request that
// the fake upstream observed.
func smokeRunOnce(
	t *testing.T,
	upstream *httptest.Server,
	recorded *[]recordedUpstreamRequest,
	mu *sync.Mutex,
	installationIDByAuthID map[string]string,
	authID, token string,
	sc fingerprintScenario,
) recordedUpstreamRequest {
	t.Helper()
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	if sc.inboundAPIKey != "" {
		ginCtx.Set("userApiKey", sc.inboundAPIKey)
	}
	for k, v := range sc.ginHeaders {
		ginCtx.Request.Header.Set(k, v)
	}
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{
		ID:         authID,
		Attributes: map[string]string{"base_url": upstream.URL, "api_key": token},
		Metadata:   map[string]any{},
	}
	if existing := installationIDByAuthID[authID]; existing != "" {
		auth.Metadata["installation_id"] = existing
	}
	ensureCodexInstallationID(auth)
	installationIDByAuthID[authID] = codexInstallationIDForAuth(auth)

	executor := NewCodexExecutor(&config.Config{})
	_, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(sc.clientPayload),
	}, cliproxyexecutor.Options{
		SourceFormat: sc.from,
		Stream:       false,
	})
	if err != nil {
		t.Fatalf("Execute(%s): %v", authID, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*recorded) == 0 {
		t.Fatalf("no upstream request recorded for %s", authID)
	}
	return (*recorded)[len(*recorded)-1]
}

// TestCodexSmoke_AuthRoundTrip_PreservesValues exercises the
// A -> B -> A request sequence and verifies that each crossAuthLeakField:
//   - differs across auths (A vs B)
//   - is identical across two A requests separated by a B request
//
// The first invariant is the pool-fingerprint protection; the second is the
// prompt-cache-continuity invariant (an auth resuming a conversation after
// a different auth ran in between must see the same upstream-bound values
// so OpenAI's prompt cache stays warm).
func TestCodexSmoke_AuthRoundTrip_PreservesValues(t *testing.T) {
	scenarios := []fingerprintScenario{
		{
			name:          "codex_direct",
			from:          sdktranslator.FromString("codex"),
			clientPayload: `{"model":"gpt-5-codex","input":"hello"}`,
			ginHeaders:    map[string]string{"Session_id": "client-session-XYZ", "Thread_id": uuid.Must(uuid.NewV7()).String()},
		},
		{
			name:          "codex_direct_subagent",
			from:          sdktranslator.FromString("codex"),
			clientPayload: `{"model":"gpt-5-codex","input":"hello"}`,
			ginHeaders: map[string]string{
				"Session_id":               "client-session-XYZ",
				"Thread_id":                uuid.Must(uuid.NewV7()).String(),
				"X-Openai-Subagent":        "code-reviewer",
				"X-Codex-Parent-Thread-Id": uuid.Must(uuid.NewV7()).String(),
			},
		},
		{
			name:          "openai_response",
			from:          sdktranslator.FromString("openai-response"),
			clientPayload: `{"model":"gpt-5-codex","input":"hello","prompt_cache_key":"caller-supplied-cache"}`,
		},
		{
			name:          "openai_chat",
			from:          sdktranslator.FromString("openai"),
			clientPayload: `{"model":"gpt-5-codex","messages":[{"role":"user","content":"hello"}]}`,
			inboundAPIKey: "user-api-key",
		},
		{
			name:          "claude",
			from:          sdktranslator.FromString("claude"),
			clientPayload: `{"model":"gpt-5-codex","messages":[{"role":"user","content":"hello"}],"metadata":{"user_id":"user_abc__session_xyz"}}`,
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			var (
				mu       sync.Mutex
				recorded []recordedUpstreamRequest
			)
			upstream := newSmokeUpstream(t, &recorded, &mu)
			defer upstream.Close()
			installationIDByAuthID := map[string]string{}

			recA1 := smokeRunOnce(t, upstream, &recorded, &mu, installationIDByAuthID, "auth-A", "token-A", sc)
			recB := smokeRunOnce(t, upstream, &recorded, &mu, installationIDByAuthID, "auth-B", "token-B", sc)
			recA2 := smokeRunOnce(t, upstream, &recorded, &mu, installationIDByAuthID, "auth-A", "token-A", sc)

			for _, f := range crossAuthLeakFields {
				a1 := readFingerprintField(recA1, f)
				b := readFingerprintField(recB, f)
				a2 := readFingerprintField(recA2, f)
				if a1 == "" && b == "" && a2 == "" {
					continue
				}

				// Round-trip: after a B request between, A's second request
				// must reach upstream with the same value as A's first.
				// Otherwise the per-auth cache lost its pin, and the OpenAI
				// prompt cache on this account would miss whenever the pool
				// dispatched a different auth in between.
				if a1 != a2 {
					t.Errorf("ROUND-TRIP LOST: %s %s changed across A1 -> B -> A2 (%q vs %q) — %s",
						f.location, f.name, a1, a2, f.why)
				}

				// Cross-auth: B's value must differ from A's. (Pool
				// fingerprint protection; same shape as regression test.)
				if a1 == b {
					t.Errorf("CROSS-AUTH LEAK: %s %s = %q identical across auth-A and auth-B — %s",
						f.location, f.name, a1, f.why)
				}
			}

			// Spot-check the wire shape on each captured upstream request.
			// If hardening was somehow bypassed, these would be missing or
			// the wrong shape.
			for i, rec := range []recordedUpstreamRequest{recA1, recB, recA2} {
				if got := rec.Headers.Get("Session_id"); got == "" {
					t.Errorf("request[%d]: Session_id missing", i)
				} else {
					assertCodexV7Mimic(t, "request["+sc.name+"] Session_id", got)
				}
				if got := rec.Headers.Get("Thread_id"); got == "" {
					t.Errorf("request[%d]: Thread_id missing", i)
				} else {
					assertCodexV7Mimic(t, "request["+sc.name+"] Thread_id", got)
				}
				if got := gjson.GetBytes(rec.Body, "client_metadata.x-codex-installation-id").String(); got == "" {
					t.Errorf("request[%d]: installation_id missing from body", i)
				}
				if got := rec.Headers.Get("X-Codex-Window-Id"); got == "" {
					t.Errorf("request[%d]: X-Codex-Window-Id missing", i)
				}
				if got := rec.Headers.Get("X-Oai-Attestation"); got != "" {
					t.Errorf("request[%d]: X-Oai-Attestation must be stripped, got %q", i, got)
				}
			}
		})
	}
}

// TestCodexSmoke_PipelineWiring is a single-request smoke that just confirms
// the executor + hardening hook chain actually runs end-to-end against a
// fresh fake upstream. Catches the "hardening got disconnected" failure
// mode that more focused tests might miss (e.g., a refactor that removes
// the callsite would still let TestCodexFingerprintHardeningHTTP_* pass
// because they invoke hardening directly).
func TestCodexSmoke_PipelineWiring(t *testing.T) {
	var (
		mu       sync.Mutex
		recorded []recordedUpstreamRequest
	)
	upstream := newSmokeUpstream(t, &recorded, &mu)
	defer upstream.Close()

	sc := fingerprintScenario{
		from:          sdktranslator.FromString("openai-response"),
		clientPayload: `{"model":"gpt-5-codex","input":"hi","prompt_cache_key":"caller-supplied"}`,
	}
	rec := smokeRunOnce(t, upstream, &recorded, &mu, map[string]string{}, "auth-A", "token-A", sc)

	// If the pipeline ran end-to-end, the upstream captured request must
	// reflect every fingerprint surface the hardening hook owns.
	for _, check := range []struct {
		name string
		ok   bool
	}{
		{"Session_id header set", rec.Headers.Get("Session_id") != ""},
		{"Thread_id header set", rec.Headers.Get("Thread_id") != ""},
		{"X-Client-Request-Id header set", rec.Headers.Get("X-Client-Request-Id") != ""},
		{"X-Codex-Window-Id header set", rec.Headers.Get("X-Codex-Window-Id") != ""},
		{"prompt_cache_key body set", gjson.GetBytes(rec.Body, "prompt_cache_key").String() != ""},
		{"client_metadata.x-codex-installation-id body set", gjson.GetBytes(rec.Body, "client_metadata.x-codex-installation-id").String() != ""},
		{"Conversation_id stripped (no key present)", rec.Headers.Get("Conversation_id") == ""},
		{"X-Oai-Attestation stripped", rec.Headers.Get("X-Oai-Attestation") == ""},
		{"Authorization header set (per-auth)", rec.Headers.Get("Authorization") == "Bearer token-A"},
	} {
		if !check.ok {
			t.Errorf("pipeline wiring: %s", check.name)
		}
	}

	// The derived session/thread/prompt_cache_key should be Codex-CLI-shaped
	// UUIDv7 — proves hardening actually ran end-to-end (vs. cacheHelper's
	// raw UUIDv5/v4).
	assertCodexV7Mimic(t, "Session_id", rec.Headers.Get("Session_id"))
	assertCodexV7Mimic(t, "Thread_id", rec.Headers.Get("Thread_id"))
	assertCodexV7Mimic(t, "prompt_cache_key", gjson.GetBytes(rec.Body, "prompt_cache_key").String())
}
