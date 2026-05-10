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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

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
	{inHeader, "Session_id", "Codex session identifier (HTTP)"},
	{inHeader, "session_id", "Codex session identifier (lowercase, WS)"},
	{inHeader, "Thread_id", "Codex thread identifier (HTTP)"},
	{inHeader, "thread_id", "Codex thread identifier (lowercase, WS)"},
	{inHeader, "X-Client-Request-Id", "Codex per-thread request id (= thread_id in real Codex CLI)"},
	{inHeader, "X-Codex-Window-Id", "Codex window id (= thread_id : generation; thread part must differ across auths)"},
	{inHeader, "X-Codex-Parent-Thread-Id", "Codex parent thread identifier (subagent flow); must be per-auth derived to prevent cross-pool correlation"},
	{inBody, "prompt_cache_key", "Codex prompt cache key (= thread_id in real Codex CLI)"},
	{inBody, "previous_response_id", "Trivially correlates conversation turns across accounts"},
	{inBody, "client_metadata.x-codex-installation-id", "Per-install UUIDv4; sharing across accounts identifies single-machine pool"},
	{inBody, "client_metadata.x-codex-parent-thread-id", "Codex parent thread identifier in WS client_metadata (subagent flow)"},
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
	// X-Openai-Subagent is a small fixed enum (e.g. "review", "compact")
	// indicating the subagent role for the request. Two pool dispatches of
	// the same client's subagent flow naturally see the same label — not a
	// per-account correlation signal.
	"X-Openai-Subagent": true,
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

// codexV7Fixture is a freshly-minted UUIDv7 used as inbound parent_thread_id
// in subagent-flow scenarios. Generated at package init so the v7 timestamp
// is "now" and the v7 mimic check (≤ 30 days old) always passes.
var codexV7Fixture = uuid.Must(uuid.NewV7()).String()

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

	// In production, the same Auth object lives in the manager's pool across
	// requests, so its persisted installation_id stays put. The test creates
	// fresh Auth objects per runOnce call, so without a fixture the stability
	// check below would always fail. installationIDByAuthID gives the test a
	// per-(test-run, authID) memory.
	installationIDByAuthID := map[string]string{}

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
			// In production, installation_id is seeded at OAuth login
			// (sdk/auth/codex_device.go) and ensured on Refresh
			// (codex_executor.go). Reuse the per-(test-run, authID) value if
			// the harness has seen this auth before, otherwise let
			// ensureCodexInstallationID generate one and remember it.
			Metadata: map[string]any{},
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
			name:          "codex_direct_with_subagent_flow",
			from:          sdktranslator.FromString("codex"),
			clientPayload: `{"model":"gpt-5-codex","input":"hello"}`,
			ginHeaders: map[string]string{
				"Session_id":               "client-session-XYZ",
				"X-Openai-Subagent":        "code-reviewer",
				"X-Codex-Parent-Thread-Id": codexV7Fixture,
				"X-Oai-Attestation":        "attestation-token-xyz",
			},
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

			// Structural v7 mimic check: every upstream-bound Session_id and
			// Thread_id (and the matching body prompt_cache_key) must look
			// like a real Codex CLI v7 UUID. A v5 / v4 / random-timestamp-v7
			// leaks the proxy by trivial inspection. See LEAK_RISKS.md L1.
			for _, rec := range []recordedUpstreamRequest{recordA, recordB} {
				if sid := rec.Headers.Get("Session_id"); sid != "" {
					assertCodexV7Mimic(t, "header Session_id", sid)
				}
				if tid := rec.Headers.Get("Thread_id"); tid != "" {
					assertCodexV7Mimic(t, "header Thread_id", tid)
				}
				if pck := gjson.GetBytes(rec.Body, "prompt_cache_key").String(); pck != "" {
					assertCodexV7Mimic(t, "body prompt_cache_key", pck)
				}

				// Cross-stream: Session_id and prompt_cache_key (= thread_id)
				// must NEVER be equal. Real Codex CLI's session_id and
				// thread_id are independent v7 UUIDs; equality would itself
				// be a fingerprint. See LEAK_RISKS.md L1, CODEX_CLI_REFERENCE.md.
				sid := rec.Headers.Get("Session_id")
				pck := gjson.GetBytes(rec.Body, "prompt_cache_key").String()
				if sid != "" && pck != "" && sid == pck {
					t.Errorf("LEAK: Session_id (%q) == prompt_cache_key (%q) — real Codex CLI never makes them equal", sid, pck)
				}
				tid := rec.Headers.Get("Thread_id")
				if sid != "" && tid != "" && sid == tid {
					t.Errorf("LEAK: Session_id (%q) == Thread_id (%q) — real Codex CLI never makes them equal", sid, tid)
				}
				// thread_id family invariant: thread_id == prompt_cache_key
				// == x-client-request-id (real Codex CLI ties all three to
				// state.thread_id).
				if tid != "" && pck != "" && tid != pck {
					t.Errorf("INCONSISTENT: Thread_id (%q) != prompt_cache_key (%q) — must be the same string", tid, pck)
				}
				if xrid := rec.Headers.Get("X-Client-Request-Id"); xrid != "" && tid != "" && xrid != tid {
					t.Errorf("INCONSISTENT: X-Client-Request-Id (%q) != Thread_id (%q) — real Codex CLI sets x-client-request-id = thread_id", xrid, tid)
				}

				// Negative assertion: Conversation_id must NOT be sent. Real
				// Codex CLI never emits this header (verified against
				// codex-rs/core/src/client.rs:build_websocket_headers, see
				// CODEX_CLI_REFERENCE.md §A). The original CLIProxyAPI
				// fabricated it; we must not.
				if cid := rec.Headers.Get("Conversation_id"); cid != "" {
					t.Errorf("LEAK: Conversation_id = %q present — real Codex CLI never sends this header", cid)
				}

				// installation_id: body's client_metadata.x-codex-installation-id
				// must be present (real Codex CLI always sends it) and must be a
				// valid UUIDv4 (real Codex CLI uses Uuid::new_v4()). See
				// LEAK_RISKS.md F, CODEX_CLI_REFERENCE.md §6.F.
				inst := gjson.GetBytes(rec.Body, "client_metadata.x-codex-installation-id").String()
				if inst == "" {
					t.Errorf("MISSING: body.client_metadata.x-codex-installation-id is empty — real Codex CLI always sends it")
				} else if u, err := uuid.Parse(inst); err != nil {
					t.Errorf("MALFORMED: client_metadata.x-codex-installation-id = %q is not a UUID: %v", inst, err)
				} else if v := byte(u.Version()); v != 4 {
					t.Errorf("MALFORMED: client_metadata.x-codex-installation-id = %q has version %d, want 4 (real Codex CLI uses Uuid::new_v4)", inst, v)
				}

				// x-codex-window-id: must be present and shaped as
				// "{uuid}:{integer}". The uuid prefix must equal the derived
				// Thread_id (so a future fingerprint check that decodes the
				// thread part still ties to a coherent thread). See
				// LEAK_RISKS.md G, CODEX_CLI_REFERENCE.md §6.G.
				wid := rec.Headers.Get("X-Codex-Window-Id")
				if wid == "" {
					t.Errorf("MISSING: X-Codex-Window-Id is empty — real Codex CLI always sends it")
				} else {
					colon := strings.LastIndex(wid, ":")
					if colon <= 0 || colon == len(wid)-1 {
						t.Errorf("MALFORMED: X-Codex-Window-Id = %q must be of form \"{uuid}:{integer}\"", wid)
					} else {
						widThread := wid[:colon]
						widGen := wid[colon+1:]
						if tid != "" && widThread != tid {
							t.Errorf("INCONSISTENT: X-Codex-Window-Id thread prefix (%q) != Thread_id (%q)", widThread, tid)
						}
						if _, err := uuid.Parse(widThread); err != nil {
							t.Errorf("MALFORMED: X-Codex-Window-Id thread prefix %q is not a UUID: %v", widThread, err)
						}
						if widGen == "" {
							t.Errorf("MALFORMED: X-Codex-Window-Id = %q has empty generation suffix", wid)
						}
					}
				}

				// Conditional codex CLI headers (H/J): subagent / parent_thread_id
				// must be present iff inbound carried them, and must NEVER be
				// emitted on non-subagent / non-codex paths (constant emission
				// would itself be a fingerprint). Attestation is ALWAYS stripped
				// regardless of inbound (cross-auth correlation risk + invalid
				// binding when pool dispatches to a different OAuth). For the
				// subagent scenario specifically, also verify parent_thread_id
				// is per-auth derived (not the raw inbound value) and v7-shaped.
				if got := rec.Headers.Get("X-Oai-Attestation"); got != "" {
					t.Errorf("LEAK: X-Oai-Attestation = %q present — must always be stripped (cross-auth correlation risk)", got)
				}
				for _, c := range []struct {
					name    string
					inbound string
					out     string
					derive  bool
				}{
					{"X-Openai-Subagent", sc.ginHeaders["X-Openai-Subagent"], rec.Headers.Get("X-Openai-Subagent"), false},
					{"X-Codex-Parent-Thread-Id", sc.ginHeaders["X-Codex-Parent-Thread-Id"], rec.Headers.Get("X-Codex-Parent-Thread-Id"), true},
				} {
					if c.inbound == "" {
						if c.out != "" {
							t.Errorf("LEAK: %s = %q emitted with no inbound (would be a constant fingerprint)", c.name, c.out)
						}
						continue
					}
					if c.out == "" {
						t.Errorf("MISSING: inbound %s = %q present but outbound is empty", c.name, c.inbound)
						continue
					}
					if c.derive {
						if c.out == c.inbound {
							t.Errorf("LEAK: %s forwarded verbatim (%q); must be per-auth derived", c.name, c.out)
						}
						assertCodexV7Mimic(t, "header "+c.name, c.out)
					} else if c.out != c.inbound {
						t.Errorf("INCONSISTENT: %s = %q, want verbatim passthrough of inbound %q", c.name, c.out, c.inbound)
					}
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

// assertCodexV7Mimic asserts that a session-correlating value sent to upstream
// looks like a real Codex CLI session id: parses as a UUID, has version 7, has
// RFC4122 variant bits, and carries a recent timestamp in the leading 48 bits.
//
// Real Codex CLI uses Uuid::now_v7() (codex-rs/protocol/src/session_id.rs).
// Anything else (v5, v4, or v7-with-implausible-timestamp) is a trivial check
// the upstream can perform to flag the proxy.
func assertCodexV7Mimic(t *testing.T, label, value string) {
	t.Helper()
	u, err := uuid.Parse(value)
	if err != nil {
		t.Errorf("LEAK: %s = %q is not a valid UUID — does not look like real Codex CLI session_id", label, value)
		return
	}
	if v := byte(u.Version()); v != 7 {
		t.Errorf("LEAK: %s = %q has UUID version %d (real Codex CLI uses v7)", label, value, v)
		return
	}
	if u[8]&0xc0 != 0x80 {
		t.Errorf("LEAK: %s = %q has non-RFC4122 variant bits 0x%02x", label, value, u[8])
		return
	}
	tsMs := extractV7TimestampMs(u)
	now := time.Now().UnixMilli()
	const recentWindow = int64(30 * 24 * time.Hour / time.Millisecond)
	if tsMs > now+60_000 {
		t.Errorf("LEAK: %s = %q has v7 timestamp %d in the future (now=%d)", label, value, tsMs, now)
	}
	if tsMs < now-recentWindow {
		t.Errorf("LEAK: %s = %q has v7 timestamp %d older than 30 days (now=%d) — looks SHA1-derived",
			label, value, tsMs, now)
	}
}
