package executor

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestBuildCodexWebsocketRequestBodyPreservesPreviousResponseID(t *testing.T) {
	body := []byte(`{"model":"gpt-5-codex","previous_response_id":"resp-1","input":[{"type":"message","id":"msg-1"}]}`)

	wsReqBody := buildCodexWebsocketRequestBody(body)

	if got := gjson.GetBytes(wsReqBody, "type").String(); got != "response.create" {
		t.Fatalf("type = %s, want response.create", got)
	}
	if got := gjson.GetBytes(wsReqBody, "previous_response_id").String(); got != "resp-1" {
		t.Fatalf("previous_response_id = %s, want resp-1", got)
	}
	if gjson.GetBytes(wsReqBody, "input.0.id").String() != "msg-1" {
		t.Fatalf("input item id mismatch")
	}
	if got := gjson.GetBytes(wsReqBody, "type").String(); got == "response.append" {
		t.Fatalf("unexpected websocket request type: %s", got)
	}
}

func TestCodexWebsocketsExecutePreservesPreviousResponseIDUpstream(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	capturedPayload := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Fatalf("request path = %s, want /responses", r.URL.Path)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade websocket: %v", err)
		}
		defer func() { _ = conn.Close() }()

		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read upstream websocket message: %v", err)
		}
		if msgType != websocket.TextMessage {
			t.Fatalf("message type = %d, want text", msgType)
		}
		capturedPayload <- bytes.Clone(payload)

		completed := []byte(`{"type":"response.completed","response":{"id":"resp-2","output":[],"usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}}`)
		if errWrite := conn.WriteMessage(websocket.TextMessage, completed); errWrite != nil {
			t.Fatalf("write completed websocket message: %v", errWrite)
		}
	}))
	defer server.Close()

	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-test", "base_url": server.URL}}
	req := cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","previous_response_id":"resp-1","input":[{"type":"message","id":"msg-1"}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("codex")}

	if _, err := exec.Execute(context.Background(), auth, req, opts); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	select {
	case payload := <-capturedPayload:
		if got := gjson.GetBytes(payload, "type").String(); got != "response.create" {
			t.Fatalf("upstream type = %s, want response.create; payload=%s", got, payload)
		}
		if got := gjson.GetBytes(payload, "previous_response_id").String(); got != "resp-1" {
			t.Fatalf("upstream previous_response_id = %s, want resp-1; payload=%s", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream websocket payload")
	}
}

func TestCodexWebsocketsUpstreamDisconnectChanSignalsOnInvalidate(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	exec := NewCodexWebsocketsExecutor(&config.Config{})
	sessionID := "sess-1"
	disconnectCh := exec.UpstreamDisconnectChan(sessionID)
	if disconnectCh == nil {
		t.Fatal("expected disconnect channel")
	}

	sess := exec.getOrCreateSession(sessionID)
	if sess == nil {
		t.Fatal("expected session")
	}
	sess.connMu.Lock()
	sess.conn = conn
	sess.authID = "auth-1"
	sess.wsURL = "ws://example.test/responses"
	sess.readerConn = conn
	sess.connMu.Unlock()

	upstreamErr := errors.New("upstream gone")
	exec.invalidateUpstreamConn(sess, conn, "test_invalidate", upstreamErr)

	select {
	case errRead, ok := <-disconnectCh:
		if !ok {
			t.Fatal("expected disconnect channel to deliver error before closing")
		}
		if errRead == nil || errRead.Error() != upstreamErr.Error() {
			t.Fatalf("disconnect error = %v, want %v", errRead, upstreamErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for disconnect signal")
	}
}

func TestApplyCodexWebsocketHeadersDefaultsToCurrentResponsesBeta(t *testing.T) {
	headers := applyCodexWebsocketHeaders(context.Background(), http.Header{}, nil, "", nil)

	if got := headers.Get("OpenAI-Beta"); got != codexResponsesWebsocketBetaHeaderValue {
		t.Fatalf("OpenAI-Beta = %s, want %s", got, codexResponsesWebsocketBetaHeaderValue)
	}
	if got := headers.Get("User-Agent"); got != codexUserAgent {
		t.Fatalf("User-Agent = %s, want %s", got, codexUserAgent)
	}
	if !strings.HasPrefix(codexUserAgent, codexOriginator+"/") {
		t.Fatalf("default Codex User-Agent = %s, want prefix %s/", codexUserAgent, codexOriginator)
	}
	if strings.HasPrefix(codexUserAgent, "codex-tui/") {
		t.Fatalf("default Codex User-Agent = %s, must not use stale codex-tui prefix", codexUserAgent)
	}
	if strings.Contains(codexUserAgent, "(codex-tui;") {
		t.Fatalf("default Codex User-Agent = %s, must not include stale codex-tui suffix", codexUserAgent)
	}
	if got := headers.Get("Originator"); got != codexOriginator {
		t.Fatalf("Originator = %s, want %s", got, codexOriginator)
	}
	if got := headers.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
	if got := headers.Get("x-codex-beta-features"); got != "" {
		t.Fatalf("x-codex-beta-features = %q, want empty", got)
	}
	if got := headers.Get("X-Codex-Turn-Metadata"); got != "" {
		t.Fatalf("X-Codex-Turn-Metadata = %q, want empty", got)
	}
	if got := headers.Get("X-Client-Request-Id"); got != "" {
		t.Fatalf("X-Client-Request-Id = %q, want empty", got)
	}
}

func TestApplyCodexWebsocketHeadersPassesThroughClientIdentityHeaders(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"email": "user@example.com"},
	}
	ctx := contextWithGinHeaders(map[string]string{
		"Originator":            "Codex Desktop",
		"User-Agent":            "codex_cli_rs/0.1.0",
		"Version":               "0.115.0-alpha.27",
		"X-Codex-Turn-Metadata": `{"turn_id":"turn-1"}`,
		"X-Client-Request-Id":   "019d2233-e240-7162-992d-38df0a2a0e0d",
		"session_id":            "sess-client",
	})

	headers := applyCodexWebsocketHeaders(ctx, http.Header{}, auth, "", nil)

	if got := headers.Get("Originator"); got != "Codex Desktop" {
		t.Fatalf("Originator = %s, want %s", got, "Codex Desktop")
	}
	if got := headers.Get("User-Agent"); got != "codex_cli_rs/0.1.0" {
		t.Fatalf("User-Agent = %s, want %s", got, "codex_cli_rs/0.1.0")
	}
	if got := headers.Get("Version"); got != "0.115.0-alpha.27" {
		t.Fatalf("Version = %s, want %s", got, "0.115.0-alpha.27")
	}
	if got := headers.Get("X-Codex-Turn-Metadata"); got != `{"turn_id":"turn-1"}` {
		t.Fatalf("X-Codex-Turn-Metadata = %s, want %s", got, `{"turn_id":"turn-1"}`)
	}
	if got := headers.Get("X-Client-Request-Id"); got != "019d2233-e240-7162-992d-38df0a2a0e0d" {
		t.Fatalf("X-Client-Request-Id = %s, want %s", got, "019d2233-e240-7162-992d-38df0a2a0e0d")
	}
	if got := headerValueCaseInsensitive(headers, "session_id"); got != "sess-client" {
		t.Fatalf("session_id = %s, want sess-client", got)
	}
	if _, ok := headers["session_id"]; !ok {
		t.Fatalf("expected lowercase session_id header key, got %#v", headers)
	}
}

func TestApplyCodexWebsocketHeadersUsesConfigDefaultsForOAuth(t *testing.T) {
	cfg := &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent:    "my-codex-client/1.0",
			BetaFeatures: "feature-a,feature-b",
		},
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"email": "user@example.com"},
	}

	headers := applyCodexWebsocketHeaders(context.Background(), http.Header{}, auth, "", cfg)

	if got := headers.Get("User-Agent"); got != "my-codex-client/1.0" {
		t.Fatalf("User-Agent = %s, want %s", got, "my-codex-client/1.0")
	}
	if got := headers.Get("x-codex-beta-features"); got != "feature-a,feature-b" {
		t.Fatalf("x-codex-beta-features = %s, want %s", got, "feature-a,feature-b")
	}
	if got := headers.Get("OpenAI-Beta"); got != codexResponsesWebsocketBetaHeaderValue {
		t.Fatalf("OpenAI-Beta = %s, want %s", got, codexResponsesWebsocketBetaHeaderValue)
	}
}

func TestApplyCodexWebsocketHeadersPrefersExistingHeadersOverClientAndConfig(t *testing.T) {
	cfg := &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent:    "config-ua",
			BetaFeatures: "config-beta",
		},
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"email": "user@example.com"},
	}
	ctx := contextWithGinHeaders(map[string]string{
		"User-Agent":            "client-ua",
		"X-Codex-Beta-Features": "client-beta",
	})
	headers := http.Header{}
	headers.Set("User-Agent", "existing-ua")
	headers.Set("X-Codex-Beta-Features", "existing-beta")

	got := applyCodexWebsocketHeaders(ctx, headers, auth, "", cfg)

	if gotVal := got.Get("User-Agent"); gotVal != "existing-ua" {
		t.Fatalf("User-Agent = %s, want %s", gotVal, "existing-ua")
	}
	if gotVal := got.Get("x-codex-beta-features"); gotVal != "existing-beta" {
		t.Fatalf("x-codex-beta-features = %s, want %s", gotVal, "existing-beta")
	}
}

func TestApplyCodexWebsocketHeadersConfigUserAgentOverridesClientHeader(t *testing.T) {
	cfg := &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent:    "config-ua",
			BetaFeatures: "config-beta",
		},
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"email": "user@example.com"},
	}
	ctx := contextWithGinHeaders(map[string]string{
		"User-Agent":            "client-ua",
		"X-Codex-Beta-Features": "client-beta",
	})

	headers := applyCodexWebsocketHeaders(ctx, http.Header{}, auth, "", cfg)

	if got := headers.Get("User-Agent"); got != "config-ua" {
		t.Fatalf("User-Agent = %s, want %s", got, "config-ua")
	}
	if got := headers.Get("x-codex-beta-features"); got != "client-beta" {
		t.Fatalf("x-codex-beta-features = %s, want %s", got, "client-beta")
	}
}

func TestApplyCodexWebsocketHeadersIgnoresConfigForAPIKeyAuth(t *testing.T) {
	cfg := &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent:    "config-ua",
			BetaFeatures: "config-beta",
		},
	}
	auth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"api_key": "sk-test"},
	}

	headers := applyCodexWebsocketHeaders(context.Background(), http.Header{}, auth, "sk-test", cfg)

	if got := headers.Get("User-Agent"); got != "" {
		t.Fatalf("User-Agent = %s, want empty", got)
	}
	if got := headers.Get("x-codex-beta-features"); got != "" {
		t.Fatalf("x-codex-beta-features = %q, want empty", got)
	}
	if got := headers.Get("Originator"); got != "" {
		t.Fatalf("Originator = %s, want empty", got)
	}
}

func TestApplyCodexWebsocketHeadersPreservesExplicitAPIKeyUserAgent(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "sk-test"}}
	ctx := contextWithGinHeaders(map[string]string{"User-Agent": "api-key-client/1.0", "Originator": "explicit-origin"})

	headers := applyCodexWebsocketHeaders(ctx, http.Header{}, auth, "sk-test", nil)

	if got := headers.Get("User-Agent"); got != "api-key-client/1.0" {
		t.Fatalf("User-Agent = %s, want api-key-client/1.0", got)
	}
	if got := headers.Get("Originator"); got != "explicit-origin" {
		t.Fatalf("Originator = %s, want explicit-origin", got)
	}
}

// hardenWS is a tiny test helper that wires applyCodexPromptCacheHeaders +
// applyCodexFingerprintHardeningWS the same way the executor does, so the
// pre/post invariants below correspond to what real upstream sees.
func hardenWS(t *testing.T, from sdktranslator.Format, payload []byte, body []byte, auth *cliproxyauth.Auth) ([]byte, http.Header) {
	t.Helper()
	return hardenWSWithCtx(t, context.Background(), from, payload, body, auth)
}

// hardenWSWithCtx is the gin-aware variant, used by tests that want to assert
// behavior of inbound headers / body fields the codex direct path would
// supply via the gin request.
func hardenWSWithCtx(t *testing.T, ctx context.Context, from sdktranslator.Format, payload []byte, body []byte, auth *cliproxyauth.Auth) ([]byte, http.Header) {
	t.Helper()
	req := cliproxyexecutor.Request{Model: "gpt-5-codex", Payload: payload}
	body, headers := applyCodexPromptCacheHeaders(from, req, body)
	body, headers = applyCodexFingerprintHardeningWS(ctx, body, headers, auth)
	return body, headers
}

func TestCodexFingerprintHardeningWS_NoConversationId_OnlySessionAndThread(t *testing.T) {
	// Upstream's applyCodexPromptCacheHeaders sets a Conversation_id header;
	// the hardening hook must strip it (real Codex CLI never sends it). Both
	// session_id and thread_id (lowercase) must be present.
	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	_, headers := hardenWS(t, "openai-response",
		[]byte(`{"prompt_cache_key":"cache-1"}`),
		[]byte(`{"model":"gpt-5-codex"}`), auth)

	if sid := headerValueCaseInsensitive(headers, "session_id"); sid == "" {
		t.Fatalf("session_id header should be set, got empty (headers=%#v)", headers)
	}
	if _, ok := headers["session_id"]; !ok {
		t.Fatalf("expected lowercase session_id key, got %#v", headers)
	}
	if tid := headerValueCaseInsensitive(headers, "thread_id"); tid == "" {
		t.Fatalf("thread_id header should be set, got empty (headers=%#v)", headers)
	}
	if _, ok := headers["thread_id"]; !ok {
		t.Fatalf("expected lowercase thread_id key, got %#v", headers)
	}
	if got := headers.Get("Conversation_id"); got != "" {
		t.Fatalf("Conversation_id must NOT be present (real Codex CLI doesn't send it); got %q", got)
	}
	for k := range headers {
		if strings.EqualFold(k, "conversation_id") || strings.EqualFold(k, "conversation-id") {
			t.Fatalf("found conversation-id-like header %q in output; must be stripped", k)
		}
	}
}

func TestCodexFingerprintHardeningWS_DerivesSessionAndThreadPerAuth(t *testing.T) {
	authA := &cliproxyauth.Auth{ID: "auth-A"}
	authB := &cliproxyauth.Auth{ID: "auth-B"}
	ensureCodexInstallationID(authA)
	ensureCodexInstallationID(authB)

	bodyA, hA := hardenWS(t, "openai-response",
		[]byte(`{"prompt_cache_key":"cache-1"}`),
		[]byte(`{"model":"gpt-5-codex"}`), authA)
	bodyB, hB := hardenWS(t, "openai-response",
		[]byte(`{"prompt_cache_key":"cache-1"}`),
		[]byte(`{"model":"gpt-5-codex"}`), authB)

	sidA := headerValueCaseInsensitive(hA, "session_id")
	sidB := headerValueCaseInsensitive(hB, "session_id")
	tidA := headerValueCaseInsensitive(hA, "thread_id")
	tidB := headerValueCaseInsensitive(hB, "thread_id")
	xrA := headerValueCaseInsensitive(hA, "x-client-request-id")
	xrB := headerValueCaseInsensitive(hB, "x-client-request-id")
	widA := headerValueCaseInsensitive(hA, "x-codex-window-id")
	widB := headerValueCaseInsensitive(hB, "x-codex-window-id")
	pckA := gjson.GetBytes(bodyA, "prompt_cache_key").String()
	pckB := gjson.GetBytes(bodyB, "prompt_cache_key").String()
	instA := gjson.GetBytes(bodyA, "client_metadata.x-codex-installation-id").String()
	instB := gjson.GetBytes(bodyB, "client_metadata.x-codex-installation-id").String()
	wsWidA := gjson.GetBytes(bodyA, "client_metadata.x-codex-window-id").String()

	for _, v := range []string{sidA, sidB, tidA, tidB, xrA, xrB, widA, widB, pckA, pckB, instA, instB, wsWidA} {
		if v == "" {
			t.Fatalf("missing required value")
		}
	}
	if sidA == "cache-1" || sidB == "cache-1" || tidA == "cache-1" || tidB == "cache-1" {
		t.Fatalf("raw client cache key forwarded without derivation")
	}
	if sidA == sidB || tidA == tidB || xrA == xrB || pckA == pckB || widA == widB || instA == instB {
		t.Fatalf("cross-auth leak across one of the per-auth derived values")
	}
	if tidA != xrA || tidA != pckA {
		t.Fatalf("auth-A: thread_id (%q), x-client-request-id (%q), prompt_cache_key (%q) must be equal", tidA, xrA, pckA)
	}
	if tidB != xrB || tidB != pckB {
		t.Fatalf("auth-B: thread_id (%q), x-client-request-id (%q), prompt_cache_key (%q) must be equal", tidB, xrB, pckB)
	}
	if sidA == tidA || sidB == tidB {
		t.Fatalf("session_id == thread_id within an auth — real Codex CLI never makes them equal")
	}
	// WS body's client_metadata also carries window_id (mirror real client).
	if wsWidA != widA {
		t.Fatalf("WS body client_metadata.x-codex-window-id (%q) must equal header X-Codex-Window-Id (%q)", wsWidA, widA)
	}
}

// TestCodexFingerprintHardeningWS_ConditionalHeaders_ForwardedFromInbound (H)
// verifies the WS path forwards subagent / parent_thread_id / attestation
// from inbound gin headers, using the lowercase header names real Codex CLI
// emits over the websocket upgrade. parent_thread_id is per-auth derived to
// avoid cross-auth leak; the other two are verbatim passthroughs.
func TestCodexFingerprintHardeningWS_ConditionalHeaders_ForwardedFromInbound(t *testing.T) {
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

	_, headers := hardenWSWithCtx(t, ctx, "codex",
		[]byte(`{"model":"gpt-5-codex","input":"hi"}`),
		[]byte(`{"model":"gpt-5-codex"}`), auth)

	if got := headerValueCaseInsensitive(headers, "x-openai-subagent"); got != "code-reviewer" {
		t.Fatalf("x-openai-subagent = %q, want verbatim passthrough", got)
	}
	if got := headerValueCaseInsensitive(headers, "x-oai-attestation"); got != "attestation-token-xyz" {
		t.Fatalf("x-oai-attestation = %q, want verbatim passthrough", got)
	}
	parentOut := headerValueCaseInsensitive(headers, "x-codex-parent-thread-id")
	if parentOut == "" {
		t.Fatal("x-codex-parent-thread-id should be forwarded when inbound has it")
	}
	if parentOut == inboundParent {
		t.Fatalf("x-codex-parent-thread-id forwarded verbatim (%q); must be per-auth derived", parentOut)
	}
	// All three should land under their case-preserved lowercase keys (so
	// hyper-style WS upgrades see them in canonical Codex form).
	for _, lower := range []string{"x-openai-subagent", "x-codex-parent-thread-id", "x-oai-attestation"} {
		if _, ok := headers[lower]; !ok {
			t.Fatalf("expected case-preserved lowercase header %q in %#v", lower, headers)
		}
	}
}

// TestCodexFingerprintHardeningWS_ConditionalHeaders_AbsentWhenInboundAbsent
// verifies the non-subagent / non-codex case: no inbound conditional headers
// → no outbound conditional headers (otherwise their constant emission would
// be a fingerprint).
func TestCodexFingerprintHardeningWS_ConditionalHeaders_AbsentWhenInboundAbsent(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	_, headers := hardenWS(t, "openai-response",
		[]byte(`{"prompt_cache_key":"cache-1"}`),
		[]byte(`{"model":"gpt-5-codex"}`), auth)

	for _, h := range []string{"x-openai-subagent", "x-codex-parent-thread-id", "x-oai-attestation"} {
		if got := headerValueCaseInsensitive(headers, h); got != "" {
			t.Errorf("%s should be absent on non-subagent path; got %q", h, got)
		}
		if _, ok := headers[h]; ok {
			t.Errorf("%s should be absent from header keys on non-subagent path", h)
		}
	}
}

// TestCodexFingerprintHardeningWS_ClientMetadata_ParentThreadIDDerived (I)
// verifies the WS body's client_metadata.x-codex-parent-thread-id is also
// per-auth derived. Real Codex CLI puts this in BOTH the header and the WS
// body's client_metadata when in subagent flow — the fork must derive both
// consistently (= same derived value).
func TestCodexFingerprintHardeningWS_ClientMetadata_ParentThreadIDDerived(t *testing.T) {
	inboundParent := uuid.Must(uuid.NewV7()).String()
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest("POST", "/", nil)
	ginCtx.Request.Header.Set("X-Codex-Parent-Thread-Id", inboundParent)
	ctx := context.WithValue(context.Background(), "gin", ginCtx)

	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	body, headers := hardenWSWithCtx(t, ctx, "codex",
		[]byte(`{"model":"gpt-5-codex","input":"hi"}`),
		[]byte(`{"model":"gpt-5-codex"}`), auth)

	bodyParent := gjson.GetBytes(body, "client_metadata.x-codex-parent-thread-id").String()
	headerParent := headerValueCaseInsensitive(headers, "x-codex-parent-thread-id")
	if bodyParent == "" {
		t.Fatal("WS body client_metadata.x-codex-parent-thread-id should be set when inbound has parent_thread_id")
	}
	if bodyParent == inboundParent {
		t.Fatalf("client_metadata.x-codex-parent-thread-id forwarded verbatim (%q); must be derived", bodyParent)
	}
	if bodyParent != headerParent {
		t.Fatalf("WS body parent (%q) != header parent (%q); real Codex CLI sets both to the same value", bodyParent, headerParent)
	}
}

// TestCodexFingerprintHardeningWS_ClientMetadata_PassthroughFields (I)
// verifies the WS body's conditional client_metadata fields (subagent label,
// turn metadata) are preserved verbatim through the hardening hook. Real
// Codex CLI emits these in subagent / per-turn flows; the fork must not
// rewrite them. installation_id, window_id, parent_thread_id are handled
// elsewhere — this test guards the "everything else just rides through" path.
func TestCodexFingerprintHardeningWS_ClientMetadata_PassthroughFields(t *testing.T) {
	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	inputBody := []byte(`{` +
		`"model":"gpt-5-codex",` +
		`"prompt_cache_key":"cache-1",` +
		`"client_metadata":{` +
		`"x-openai-subagent":"code-reviewer",` +
		`"x-codex-turn-metadata":"{\"turn_id\":\"turn-1\"}"` +
		`}}`)

	body, _ := hardenWS(t, "openai-response",
		[]byte(`{"model":"gpt-5-codex","input":"hi","prompt_cache_key":"cache-1"}`),
		inputBody, auth)

	if got := gjson.GetBytes(body, "client_metadata.x-openai-subagent").String(); got != "code-reviewer" {
		t.Fatalf("client_metadata.x-openai-subagent = %q, want %q (passthrough)", got, "code-reviewer")
	}
	if got := gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").String(); got != `{"turn_id":"turn-1"}` {
		t.Fatalf("client_metadata.x-codex-turn-metadata = %q, want passthrough", got)
	}
	// The mandatory fields hardening adds must still be present alongside the
	// preserved passthroughs.
	if got := gjson.GetBytes(body, "client_metadata.x-codex-installation-id").String(); got == "" {
		t.Fatal("client_metadata.x-codex-installation-id must remain set")
	}
	if got := gjson.GetBytes(body, "client_metadata.x-codex-window-id").String(); got == "" {
		t.Fatal("client_metadata.x-codex-window-id must remain set")
	}
}

// TestCodexFingerprintHardeningWS_ClientMetadata_ParentThreadIDFromBody (I)
// verifies the body-only path: if inbound carries parent_thread_id in the WS
// client_metadata but not in the gin headers, the hardening hook still picks
// it up, derives, and writes it back.
func TestCodexFingerprintHardeningWS_ClientMetadata_ParentThreadIDFromBody(t *testing.T) {
	inboundParent := uuid.Must(uuid.NewV7()).String()
	auth := &cliproxyauth.Auth{ID: "auth-A"}
	ensureCodexInstallationID(auth)

	// Construct a WS body that already carries parent_thread_id in its
	// client_metadata (no gin header). The hardening should pick it up from
	// the body.
	inputBody := []byte(`{"model":"gpt-5-codex","client_metadata":{"x-codex-parent-thread-id":"` + inboundParent + `"}}`)
	body, headers := hardenWS(t, "codex",
		[]byte(`{"model":"gpt-5-codex","input":"hi"}`),
		inputBody, auth)

	bodyParent := gjson.GetBytes(body, "client_metadata.x-codex-parent-thread-id").String()
	if bodyParent == "" {
		t.Fatal("expected derived parent_thread_id in body when inbound body had it")
	}
	if bodyParent == inboundParent {
		t.Fatalf("forwarded verbatim from body; must be derived")
	}
	if got := headerValueCaseInsensitive(headers, "x-codex-parent-thread-id"); got != bodyParent {
		t.Fatalf("body-sourced parent should also propagate to header (%q vs body %q)", got, bodyParent)
	}
}

func TestApplyCodexWebsocketHeadersUsesCanonicalAccountHeader(t *testing.T) {
	auth := &cliproxyauth.Auth{Provider: "codex", Metadata: map[string]any{"account_id": "acct-1"}}

	headers := applyCodexWebsocketHeaders(context.Background(), http.Header{}, auth, "", nil)

	if got := headerValueCaseInsensitive(headers, "ChatGPT-Account-ID"); got != "acct-1" {
		t.Fatalf("ChatGPT-Account-ID = %s, want acct-1", got)
	}
	values, ok := headers["ChatGPT-Account-ID"]
	if !ok {
		t.Fatalf("expected exact ChatGPT-Account-ID key, got %#v", headers)
	}
	if len(values) != 1 || values[0] != "acct-1" {
		t.Fatalf("ChatGPT-Account-ID values = %#v, want [acct-1]", values)
	}
}

func TestBuildCodexResponsesWebsocketURLRequiresHTTPURL(t *testing.T) {
	if got, err := buildCodexResponsesWebsocketURL("https://example.com/backend/responses"); err != nil || got != "wss://example.com/backend/responses" {
		t.Fatalf("https URL = %q, %v; want wss URL", got, err)
	}
	if _, err := buildCodexResponsesWebsocketURL("ftp://example.com/responses"); err == nil {
		t.Fatalf("expected unsupported scheme error")
	}
	if _, err := buildCodexResponsesWebsocketURL("https:///responses"); err == nil {
		t.Fatalf("expected empty host error")
	}
}

func TestParseCodexWebsocketErrorMarksConnectionLimitRetryable(t *testing.T) {
	err, ok := parseCodexWebsocketError([]byte(`{"type":"error","status":429,"error":{"code":"websocket_connection_limit_reached","message":"too many websockets"},"headers":{"retry-after":"1"}}`))
	if !ok {
		t.Fatalf("expected websocket error")
	}
	status, ok := err.(interface{ StatusCode() int })
	if !ok || status.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %#v, want 429", err)
	}
	retryable, ok := err.(interface{ RetryAfter() *time.Duration })
	if !ok || retryable.RetryAfter() == nil {
		t.Fatalf("expected retryable websocket connection limit error")
	}
	if got := *retryable.RetryAfter(); got != 0 {
		t.Fatalf("retryAfter = %v, want connection-limit fallback 0", got)
	}
	withHeaders, ok := err.(interface{ Headers() http.Header })
	if !ok || withHeaders.Headers().Get("retry-after") != "1" {
		t.Fatalf("headers = %#v, want retry-after", err)
	}
}

func TestParseCodexWebsocketErrorUsesUsageLimitRetryMetadata(t *testing.T) {
	err, ok := parseCodexWebsocketError([]byte(`{"type":"error","status":429,"body":{"error":{"type":"usage_limit_reached","message":"usage limit reached","resets_in_seconds":7}}}`))
	if !ok {
		t.Fatalf("expected websocket error")
	}

	retryable, ok := err.(interface{ RetryAfter() *time.Duration })
	if !ok || retryable.RetryAfter() == nil {
		t.Fatalf("expected retryable usage limit websocket error")
	}
	if got := *retryable.RetryAfter(); got != 7*time.Second {
		t.Fatalf("retryAfter = %v, want 7s", got)
	}
}

func TestParseCodexWebsocketErrorPreservesWrappedBodyAndHeaders(t *testing.T) {
	err, ok := parseCodexWebsocketError([]byte(`{"type":"error","status":429,"body":{"error":{"code":"websocket_connection_limit_reached","type":"server_error","message":"too many websocket connections"}},"headers":{"x-request-id":"req-1"}}`))
	if !ok {
		t.Fatalf("expected websocket error")
	}

	parsed := gjson.Parse(err.Error())
	if got := parsed.Get("status").Int(); got != http.StatusTooManyRequests {
		t.Fatalf("wrapped status = %d, want 429; payload=%s", got, err.Error())
	}
	if got := parsed.Get("body.error.code").String(); got != "websocket_connection_limit_reached" {
		t.Fatalf("wrapped body error code = %s, want websocket_connection_limit_reached; payload=%s", got, err.Error())
	}
	if got := parsed.Get("error.code").String(); got != "websocket_connection_limit_reached" {
		t.Fatalf("surface error code = %s, want websocket_connection_limit_reached; payload=%s", got, err.Error())
	}
	retryable, ok := err.(interface{ RetryAfter() *time.Duration })
	if !ok || retryable.RetryAfter() == nil {
		t.Fatalf("expected body.error.code websocket connection limit to be retryable")
	}
	withHeaders, ok := err.(interface{ Headers() http.Header })
	if !ok || withHeaders.Headers().Get("x-request-id") != "req-1" {
		t.Fatalf("headers = %#v, want x-request-id", err)
	}
}

func TestApplyCodexHeadersUsesConfigUserAgentForOAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	cfg := &config.Config{
		CodexHeaderDefaults: config.CodexHeaderDefaults{
			UserAgent:    "config-ua",
			BetaFeatures: "config-beta",
		},
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"email": "user@example.com"},
	}
	req = req.WithContext(contextWithGinHeaders(map[string]string{
		"User-Agent": "client-ua",
	}))

	applyCodexHeaders(req, auth, "oauth-token", true, cfg)

	if got := req.Header.Get("User-Agent"); got != "config-ua" {
		t.Fatalf("User-Agent = %s, want %s", got, "config-ua")
	}
	if got := req.Header.Get("x-codex-beta-features"); got != "" {
		t.Fatalf("x-codex-beta-features = %q, want empty", got)
	}
}

func TestApplyCodexHeadersPassesThroughClientIdentityHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{"email": "user@example.com"},
	}
	req = req.WithContext(contextWithGinHeaders(map[string]string{
		"Originator":            "Codex Desktop",
		"Version":               "0.115.0-alpha.27",
		"X-Codex-Turn-Metadata": `{"turn_id":"turn-1"}`,
		"X-Client-Request-Id":   "019d2233-e240-7162-992d-38df0a2a0e0d",
	}))

	applyCodexHeaders(req, auth, "oauth-token", true, nil)

	if got := req.Header.Get("Originator"); got != "Codex Desktop" {
		t.Fatalf("Originator = %s, want %s", got, "Codex Desktop")
	}
	if got := req.Header.Get("Version"); got != "0.115.0-alpha.27" {
		t.Fatalf("Version = %s, want %s", got, "0.115.0-alpha.27")
	}
	if got := req.Header.Get("X-Codex-Turn-Metadata"); got != `{"turn_id":"turn-1"}` {
		t.Fatalf("X-Codex-Turn-Metadata = %s, want %s", got, `{"turn_id":"turn-1"}`)
	}
	if got := req.Header.Get("X-Client-Request-Id"); got != "019d2233-e240-7162-992d-38df0a2a0e0d" {
		t.Fatalf("X-Client-Request-Id = %s, want %s", got, "019d2233-e240-7162-992d-38df0a2a0e0d")
	}
}

func TestApplyCodexHeadersDoesNotInjectClientOnlyHeadersByDefault(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	applyCodexHeaders(req, nil, "oauth-token", true, nil)

	if got := req.Header.Get("Version"); got != "" {
		t.Fatalf("Version = %q, want empty", got)
	}
	if got := req.Header.Get("X-Codex-Turn-Metadata"); got != "" {
		t.Fatalf("X-Codex-Turn-Metadata = %q, want empty", got)
	}
	if got := req.Header.Get("X-Client-Request-Id"); got != "" {
		t.Fatalf("X-Client-Request-Id = %q, want empty", got)
	}
}

func contextWithGinHeaders(headers map[string]string) context.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	ginCtx.Request.Header = make(http.Header, len(headers))
	for key, value := range headers {
		ginCtx.Request.Header.Set(key, value)
	}
	return context.WithValue(context.Background(), "gin", ginCtx)
}

func TestNewProxyAwareWebsocketDialerDirectDisablesProxy(t *testing.T) {
	t.Parallel()

	dialer := newProxyAwareWebsocketDialer(
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		&cliproxyauth.Auth{ProxyURL: "direct"},
	)

	if dialer.Proxy != nil {
		t.Fatal("expected websocket proxy function to be nil for direct mode")
	}
}
