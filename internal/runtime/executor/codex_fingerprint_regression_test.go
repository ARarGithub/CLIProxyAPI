package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// This file is a fingerprint regression test for the Codex upstream path.
//
// Purpose: every time someone modifies request-building, header logic, or
// adds a new feature touching Codex, run this test. It will fail if the
// upstream Codex API can correlate two requests served by two different
// OAuth accounts as the same session — i.e. if a pool fingerprint leaks.
//
// Failures:
//   - "LEAK" -> a known leak channel (Session_id / prompt_cache_key / etc.)
//     is identical across auths. Hard fail.
//   - "STABILITY" -> the same channel changed between two requests with
//     the same auth, breaking within-account prompt cache. Hard fail.
//   - "potential new leak" -> some other field happens to be identical
//     across auths. Soft log. Add it to crossAuthLeakFields if it's a
//     real leak vector, or to genericNoiseFieldsAllowedIdentical if it's
//     known-harmless.
//
// Coverage today: HTTP /responses path for Codex backend, four inbound
// client formats (codex direct, openai-response, openai chat, claude).
// Websocket /responses path is covered by unit tests in
// codex_websockets_executor_test.go.
//
// See LEAK_RISKS.md L1 for the original threat model.

type recordedUpstreamRequest struct {
	Headers http.Header
	Body    []byte
}

type fingerprintFieldLocation int

const (
	inHeader fingerprintFieldLocation = iota
	inBody
)

func (l fingerprintFieldLocation) String() string {
	if l == inHeader {
		return "header"
	}
	return "body"
}

type fingerprintField struct {
	location fingerprintFieldLocation
	name     string
	why      string
}

// crossAuthLeakFields are fields whose value being identical across two
// different OAuth accounts is a decisive pool-detection signal upstream.
// Add a new entry whenever code introduces another conversation / session /
// cache identifier that reaches the upstream.
var crossAuthLeakFields = []fingerprintField{
	{inHeader, "Session_id", "Codex session identifier"},
	{inHeader, "session_id", "Codex session identifier (lowercase variant)"},
	{inHeader, "Conversation_id", "Codex websocket conversation identifier"},
	{inBody, "prompt_cache_key", "Codex prompt cache key"},
	{inBody, "previous_response_id", "Trivially correlates conversation turns across accounts"},
}

// crossAuthMustDifferFields are fields the test EXPECTS to differ across
// auths. If they are identical, the test setup never actually rotated auths
// (test bug, not a real result).
var crossAuthMustDifferFields = []fingerprintField{
	{inHeader, "Authorization", "Bearer token of the OAuth account"},
}

// genericNoiseFieldsAllowedIdentical lists header / body keys whose values
// being identical across two auths is normal and uninteresting (transport
// defaults, single-process proxy constants, etc.). Used to filter the
// "potential new leak" report so devs can see only the surprising matches.
//
// Header keys MUST use Go's http.CanonicalHeaderKey form.
var genericNoiseFieldsAllowedIdentical = map[string]bool{
	// transport / encoding
	"Content-Type":    true,
	"Content-Length":  true,
	"Accept":          true,
	"Accept-Encoding": true,
	"Connection":      true,
	// proxy-controlled, intentionally same across auths
	"User-Agent":                            true,
	"Originator":                            true,
	"Version":                               true,
	"X-Codex-Beta-Features":                 true,
	"X-Codex-Turn-Metadata":                 true,
	"X-Codex-Turn-State":                    true,
	"X-Client-Request-Id":                   true,
	"X-Responsesapi-Include-Timing-Metrics": true,
	"Openai-Beta":                           true,
}

// bodyContentFieldsAllowedIdentical lists Codex /responses body keys that
// carry user-controlled content (prompt text, model name, sampling params).
// They are expected to be identical when two auths run the same prompt and
// must not pollute the "potential new leak" report.
var bodyContentFieldsAllowedIdentical = map[string]bool{
	"model":               true,
	"stream":              true,
	"input":               true,
	"instructions":        true,
	"messages":            true,
	"tools":               true,
	"tool_choice":         true,
	"temperature":         true,
	"top_p":               true,
	"max_tokens":          true,
	"max_output_tokens":   true,
	"parallel_tool_calls": true,
	"store":               true,
	"include":             true,
	"reasoning":           true,
	"metadata":            true,
	"user":                true,
	"response_format":     true,
	"service_tier":        true,
	"text":                true,
	"truncation":          true,
	"modalities":          true,
}

type fingerprintScenario struct {
	name          string
	from          sdktranslator.Format
	clientPayload string
	ginHeaders    map[string]string
	inboundAPIKey string
}

func TestCodexUpstreamFingerprintRegression_NoCrossAuthCorrelation(t *testing.T) {
	var (
		mu       sync.Mutex
		recorded []recordedUpstreamRequest
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		recorded = append(recorded, recordedUpstreamRequest{Headers: r.Header.Clone(), Body: body})
		mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":0,\"status\":\"completed\",\"background\":false,\"error\":null}}\n\n"))
	}))
	defer server.Close()

	runOnce := func(t *testing.T, authID, token string, sc fingerprintScenario) recordedUpstreamRequest {
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
			Attributes: map[string]string{"base_url": server.URL, "api_key": token},
		}
		executor := NewCodexExecutor(&config.Config{})
		_, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
			Model:   "gpt-5-codex",
			Payload: []byte(sc.clientPayload),
		}, cliproxyexecutor.Options{
			SourceFormat: sc.from,
			Stream:       false,
		})
		if err != nil {
			t.Fatalf("Execute(%s) error: %v", authID, err)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(recorded) == 0 {
			t.Fatalf("no upstream request recorded for %s", authID)
		}
		return recorded[len(recorded)-1]
	}

	resetRecorded := func() {
		mu.Lock()
		recorded = nil
		mu.Unlock()
	}

	scenarios := []fingerprintScenario{
		{
			name:          "codex_direct_with_session_header",
			from:          sdktranslator.FromString("codex"),
			clientPayload: `{"model":"gpt-5-codex","input":"hello"}`,
			ginHeaders:    map[string]string{"Session_id": "client-session-XYZ"},
		},
		{
			name:          "openai_response_with_prompt_cache_key",
			from:          sdktranslator.FromString("openai-response"),
			clientPayload: `{"model":"gpt-5-codex","input":"hello","prompt_cache_key":"caller-supplied-cache"}`,
		},
		{
			name:          "openai_chat_uses_inbound_apikey_for_cache",
			from:          sdktranslator.FromString("openai"),
			clientPayload: `{"model":"gpt-5-codex","messages":[{"role":"user","content":"hello"}]}`,
			inboundAPIKey: "user-api-key",
		},
		{
			name:          "claude_uses_metadata_user_id_for_cache",
			from:          sdktranslator.FromString("claude"),
			clientPayload: `{"model":"gpt-5-codex","messages":[{"role":"user","content":"hello"}],"metadata":{"user_id":"user_abc__session_xyz"}}`,
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			resetRecorded()

			recordA := runOnce(t, "auth-A", "token-A", sc)
			recordB := runOnce(t, "auth-B", "token-B", sc)

			for _, f := range crossAuthMustDifferFields {
				a, b := readFingerprintField(recordA, f), readFingerprintField(recordB, f)
				if a == "" && b == "" {
					continue
				}
				if a == b {
					t.Fatalf("setup error: %s %s identical across auths (%q) — auths did not actually rotate",
						f.location, f.name, a)
				}
			}

			for _, f := range crossAuthLeakFields {
				a, b := readFingerprintField(recordA, f), readFingerprintField(recordB, f)
				if a == "" && b == "" {
					continue
				}
				if a == b {
					t.Errorf("LEAK: %s %s = %q across auth-A and auth-B — %s",
						f.location, f.name, a, f.why)
				}
			}

			resetRecorded()
			recordA1 := runOnce(t, "auth-A", "token-A", sc)
			recordA2 := runOnce(t, "auth-A", "token-A", sc)
			for _, f := range crossAuthLeakFields {
				a1, a2 := readFingerprintField(recordA1, f), readFingerprintField(recordA2, f)
				if a1 == "" && a2 == "" {
					continue
				}
				if a1 != a2 {
					t.Errorf("STABILITY: %s %s differs across two requests with the same auth (%q vs %q) — within-account prompt cache will miss",
						f.location, f.name, a1, a2)
				}
			}

			reportPotentialNewLeaks(t, recordA, recordB)
		})
	}
}

func readFingerprintField(r recordedUpstreamRequest, f fingerprintField) string {
	switch f.location {
	case inHeader:
		return r.Headers.Get(f.name)
	case inBody:
		return gjson.GetBytes(r.Body, f.name).String()
	}
	return ""
}

// reportPotentialNewLeaks scans all headers and top-level body keys, and
// logs (informationally — not a hard fail) any field whose value is
// identical across two different auths and isn't already accounted for as a
// known leak vector or known-harmless constant. Devs reviewing test output
// after a code change can use these logs to spot new leak channels they
// introduced unintentionally.
func reportPotentialNewLeaks(t *testing.T, a, b recordedUpstreamRequest) {
	t.Helper()

	known := map[string]bool{}
	for _, f := range crossAuthLeakFields {
		known[f.location.String()+":"+strings.ToLower(f.name)] = true
	}
	for _, f := range crossAuthMustDifferFields {
		known[f.location.String()+":"+strings.ToLower(f.name)] = true
	}

	headerKeys := map[string]struct{}{}
	for k := range a.Headers {
		headerKeys[k] = struct{}{}
	}
	for k := range b.Headers {
		headerKeys[k] = struct{}{}
	}
	headerList := make([]string, 0, len(headerKeys))
	for k := range headerKeys {
		headerList = append(headerList, k)
	}
	sort.Strings(headerList)
	for _, k := range headerList {
		if genericNoiseFieldsAllowedIdentical[k] {
			continue
		}
		if known["header:"+strings.ToLower(k)] {
			continue
		}
		va := a.Headers.Get(k)
		vb := b.Headers.Get(k)
		if va == "" || vb == "" {
			continue
		}
		if va == vb {
			t.Logf("potential new leak: header %s = %q is identical across auth-A and auth-B; review whether this correlates conversations", k, va)
		}
	}

	bodyKeys := map[string]struct{}{}
	collectTopLevelKeys(a.Body, bodyKeys)
	collectTopLevelKeys(b.Body, bodyKeys)
	bodyList := make([]string, 0, len(bodyKeys))
	for k := range bodyKeys {
		bodyList = append(bodyList, k)
	}
	sort.Strings(bodyList)
	for _, k := range bodyList {
		if known["body:"+strings.ToLower(k)] {
			continue
		}
		if bodyContentFieldsAllowedIdentical[k] {
			continue
		}
		va := gjson.GetBytes(a.Body, k).Raw
		vb := gjson.GetBytes(b.Body, k).Raw
		if va == "" || vb == "" {
			continue
		}
		if va == vb {
			t.Logf("potential new leak: body.%s = %s is identical across auth-A and auth-B; review whether this correlates conversations", k, truncateForLog(va, 80))
		}
	}
}

func collectTopLevelKeys(body []byte, into map[string]struct{}) {
	gjson.ParseBytes(body).ForEach(func(key, _ gjson.Result) bool {
		into[key.String()] = struct{}{}
		return true
	})
}

func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("...(%d bytes)", len(s))
}
